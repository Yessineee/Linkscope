export const RISK_LEVELS = {
  SAFE:       { label: 'SAFE',       min: 0,  max: 20  },
  LOW:        { label: 'LOW',        min: 21, max: 40  },
  SUSPICIOUS: { label: 'SUSPICIOUS', min: 41, max: 70  },
  DANGEROUS:  { label: 'DANGEROUS',  min: 71, max: 100 },
}

export const DEFAULT_THRESHOLDS = { low: 20, suspicious: 40, dangerous: 70 }

function getRiskLevel(score, thresholds = DEFAULT_THRESHOLDS) {
  if (score <= thresholds.low) return RISK_LEVELS.SAFE
  if (score <= thresholds.suspicious) return RISK_LEVELS.LOW
  if (score <= thresholds.dangerous) return RISK_LEVELS.SUSPICIOUS
  return RISK_LEVELS.DANGEROUS
}

const ageText = e => (e.domainAge ? ` · domain age: ${e.domainAge}` : '')

function lookalikeText(e) {
  switch (e.kind) {
    case 'wrong-domain':
      return `"${e.brand}" appears in this address, but the site is not ${e.brand}'s real website (possible impersonation)`
    case 'brand-in-subdomain':
      return `"${e.brand}" is used as a subdomain of an unrelated site (possible impersonation)`
    case 'combosquat':
      return `Domain combines "${e.brand}" with a login-style word (possible impersonation)`
    default:
      return `Domain looks like ${e.brand} (possible typosquatting)`
  }
}

const DESCRIBE = {
  gsb_match: e => `Google Safe Browsing flagged this site as ${e.threatType || 'a threat'}`,
  ipqs_phishing: e => `IPQualityScore flagged this as a phishing site (risk score: ${e.fraudScore}/100${ageText(e)})`,
  ipqs_malware: () => 'IPQualityScore identified this as a malware site',
  ipqs_high_risk: e => `IPQualityScore risk score: ${e.fraudScore}/100${ageText(e)}`,
  vt_detections: e => `VirusTotal: ${e.detectionCount} of ${e.engineCount} engines flagged this URL`,
  domain_lookalike: lookalikeText,
  domain_mixed_script: () => 'Domain mixes letters from different alphabets (possible homograph attack)',
  suspicious_form: () => 'Page contains a form that submits credentials to a suspicious endpoint',
  redirect_chain: () => 'Page uses a suspicious redirect chain',
  no_https: () => 'Site does not use HTTPS',
  missing_headers: e =>
    `Missing ${e.count} security header${e.count > 1 ? 's' : ''} (CSP/HSTS), common on quickly built or poorly maintained sites`,
  urgency_language: () => 'Page contains urgency language commonly used in phishing attacks',
  incomplete: e => `Could not check ${e.failedSources.join(', ')}, so this result may be incomplete`,
}

export function describeSignal(signal) {
  const describe = DESCRIBE[signal.id]
  return describe ? describe(signal.evidence ?? {}) : signal.id
}

export function calculateRiskScore(
  domainResult, gsbResult, ipqsResult, vtResult, contentResult = {}, thresholds = DEFAULT_THRESHOLDS
) {
  const signals = []
  const add = (id, points, evidence = {}) => signals.push({ id, points, evidence })

  if (gsbResult?.isThreat) {
    add('gsb_match', 80, { threatType: gsbResult.threatType })
  }

  const ipqsEvidence = { fraudScore: ipqsResult?.fraudScore, domainAge: ipqsResult?.domainAge }
  if (ipqsResult?.isPhishing) add('ipqs_phishing', 60, ipqsEvidence)
  else if (ipqsResult?.isMalware) add('ipqs_malware', 60)
  else if (ipqsResult?.fraudScore > 75) add('ipqs_high_risk', 60, ipqsEvidence)

  if (vtResult?.isThreat) {
    add('vt_detections', 50, { detectionCount: vtResult.detectionCount, engineCount: vtResult.engineCount })
  }

  if (domainResult?.isLookalike && domainResult?.matchedBrand) {
    add('domain_lookalike', 40, { brand: domainResult.matchedBrand, kind: domainResult.kind ?? 'typosquat' })
  }
  if (domainResult?.hasMixedScript) add('domain_mixed_script', 40)

  if (contentResult?.hasSuspiciousForm) add('suspicious_form', 30)
  if (contentResult?.hasRedirectChain) add('redirect_chain', 25)
  if (contentResult?.isHTTPS === false) add('no_https', 20)

  const missingHeaders =
    (contentResult?.hasCSP === false ? 1 : 0) + (contentResult?.hasHSTS === false ? 1 : 0)
  if (missingHeaders > 0) add('missing_headers', Math.min(missingHeaders * 5, 10), { count: missingHeaders })

  if (contentResult?.hasUrgencyLanguage) add('urgency_language', 15)

  const score = Math.min(signals.reduce((sum, s) => sum + s.points, 0), 100)

  return {
    score,
    riskLevel: getRiskLevel(score, thresholds),
    reasons: signals.map(describeSignal),
    signals,
  }
}