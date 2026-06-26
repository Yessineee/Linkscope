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
]

function getPageText() {
  const body = document.body
  if (!body) return ''
  return body.innerText.toLowerCase()
}

function detectUrgencyLanguage(pageText) {
  const matchedPatterns = URGENCY_PATTERNS.filter(pattern =>
    pageText.includes(pattern)
  )
  return {
    hasUrgencyLanguage: matchedPatterns.length > 0,
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