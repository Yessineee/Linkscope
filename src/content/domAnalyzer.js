const URGENCY_PATTERNS = [
  'your account has been suspended',
  'your account will be closed',
  'your account has been compromised',
  'unusual activity detected',
  'unauthorized access',
  'verify your account',
  'confirm your identity',
  'update your information',
  'act immediately',
  'immediate action required',
  'within 24 hours',
  'within 48 hours',
  'expires soon',
  'limited time',
  'or lose access',
  'to avoid suspension',
  'to avoid termination',
  'failure to verify',
  'your information is at risk',
  'click here immediately',
  'respond immediately',
  'urgent notice',
  'important notice',
  'security alert',
  'warning:',
  'verify now to avoid',
  'your payment could not be processed',
  'update your payment information',
  'unusual sign-in activity',
  'we detected a login from',
  'your subscription will be cancelled',
  'confirm your password',
  'click the link below to verify',
  'your account is locked',
]

function getPageText() {
  const body = document.body
  if (!body) return ''
  return body.innerText.toLowerCase()
}


const URGENCY_MATCH_THRESHOLD = 2

function detectUrgencyLanguage(pageText) {
  const matchedPatterns = URGENCY_PATTERNS.filter(pattern =>
    pageText.includes(pattern)
  )
  return {
    hasUrgencyLanguage: matchedPatterns.length >= URGENCY_MATCH_THRESHOLD,
    matchedPatterns,
  }
}

function checkHTTPS() {
  return window.location.protocol === 'https:'
}

export function analyzePage() {
  const pageText = getPageText()
  const { hasUrgencyLanguage, matchedPatterns } = detectUrgencyLanguage(pageText)
  const isHTTPS = checkHTTPS()

  return {
    hasUrgencyLanguage,
    matchedPatterns,
    isHTTPS,
  }
}