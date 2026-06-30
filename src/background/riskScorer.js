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

export function calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult = {}, thresholds = DEFAULT_THRESHOLDS) {

  let score = 0
  const reasons = []

  if (gsbResult?.isThreat) {
    score += 80
    reasons.push(`Google Safe Browsing flagged this site as ${gsbResult.threatType || 'a threat'}`)
  }

  if (ipqsResult?.isPhishing) {
    score += 60
    const ageText = ipqsResult.domainAge ? ` · domain age: ${ipqsResult.domainAge}` : ''
    reasons.push(`IPQualityScore flagged this as a phishing site (risk score: ${ipqsResult.fraudScore}/100${ageText})`)

  } else if (ipqsResult?.isMalware) {
    score += 60
    reasons.push('IPQualityScore identified this as a malware site')
  } else if (ipqsResult?.fraudScore > 75) {
    score += 60
    const ageText = ipqsResult.domainAge ? ` · domain age: ${ipqsResult.domainAge}` : ''
    reasons.push(`IPQualityScore risk score: ${ipqsResult.fraudScore}/100${ageText}`)
  }

  if (vtResult?.isThreat) {
    score += 50
    reasons.push(`VirusTotal: ${vtResult.detectionCount} of ${vtResult.engineCount} engines flagged this URL`)
  }

  if (domainResult?.isLookalike && domainResult?.matchedBrand) {
    score += 40
    reasons.push(`Domain looks like ${domainResult.matchedBrand} (possible typosquatting)`)
  }

  if (domainResult?.hasMixedScript) {
    score += 40
    reasons.push('Domain contains internationalized characters (possible homograph attack)')
  }

  if (contentResult?.hasSuspiciousForm) {
    score += 30
    reasons.push('Page contains a form that submits credentials to a suspicious endpoint')
  }

  if (contentResult?.hasRedirectChain) {
    score += 25
    reasons.push('Page uses a suspicious redirect chain')
  }

  if (contentResult?.isHTTPS === false) {
    score += 20
    reasons.push('Site does not use HTTPS')
  }

  let missingHeaders = 0
  if (contentResult?.hasCSP === false) missingHeaders++
  if (contentResult?.hasHSTS === false) missingHeaders++

  if (missingHeaders > 0) {
    score += Math.min(missingHeaders * 5, 10)
    reasons.push(`Missing ${missingHeaders} security header${missingHeaders > 1 ? 's' : ''} (CSP/HSTS), common on quickly built or poorly maintained sites`)
  }

  if (contentResult?.hasUrgencyLanguage) {
    score += 15
    reasons.push('Page contains urgency language commonly used in phishing attacks')
  }

  score = Math.min(score, 100)

  const riskLevel = getRiskLevel(score, thresholds)

  return {
    score,
    riskLevel,
    reasons,
  }
}