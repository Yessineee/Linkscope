const SENSITIVE_INPUT_TYPES = ['password', 'email', 'tel', 'number']

const SENSITIVE_INPUT_NAMES = [
  'password', 'pass', 'pwd',
  'email', 'mail',
  'card', 'cardnumber', 'ccnumber',
  'cvv', 'cvc',
  'ssn', 'social',
  'account', 'login', 'username', 'user',
]

function isSensitiveInput(input) {
  const type = input.type?.toLowerCase() ?? ''
  const name = input.name?.toLowerCase() ?? ''
  const id = input.id?.toLowerCase() ?? ''
  return (
    SENSITIVE_INPUT_TYPES.includes(type) ||
    SENSITIVE_INPUT_NAMES.some(s => name.includes(s)) ||
    SENSITIVE_INPUT_NAMES.some(s => id.includes(s))
  )
}

function getFormSubmissionDomain(form, currentDomain) {
  const action = form.action?.trim()
  if (!action || action === '' || action === '#') {
    return currentDomain
  }
  try {
    const actionURL = new URL(action)
    return actionURL.hostname
  } catch {
    return currentDomain
  }
}

function isExternalDomain(submissionDomain, currentDomain) {
  if (!submissionDomain || !currentDomain) return false
  const getBase = domain => domain.split('.').slice(-2).join('.')
  return getBase(submissionDomain) !== getBase(currentDomain)
}

export function detectSuspiciousForms() {
  const currentDomain = window.location.hostname
  const forms = document.querySelectorAll('form')
  let hasSuspiciousForm = false
  const suspiciousForms = []

  for (const form of forms) {
    const inputs = form.querySelectorAll('input')
    const hasSensitiveInput = Array.from(inputs).some(isSensitiveInput)
    if (!hasSensitiveInput) continue

    const submissionDomain = getFormSubmissionDomain(form, currentDomain)
    const isExternal = isExternalDomain(submissionDomain, currentDomain)

    if (isExternal) {
      hasSuspiciousForm = true
      suspiciousForms.push({
        action: form.action,
        submissionDomain,
        currentDomain,
      })
    }
  }

  return {
    hasSuspiciousForm,
    suspiciousForms,
  }
}