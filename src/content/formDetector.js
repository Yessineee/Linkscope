import { extractDomainFromHostname } from '../utils/domainUtils.js'

const SENSITIVE_INPUT_TYPES = ['password', 'email', 'tel']

const SENSITIVE_INPUT_NAMES = [
  'password', 'pass', 'pwd',
  'email', 'mail',
  'card', 'cardnumber', 'ccnumber',
  'cvv', 'cvc',
  'ssn', 'social',
  'account', 'login', 'username', 'user',
]

// Page markup can shadow properties like form.action with named elements, so the native methods are called directly instead of through the form.
const getAttr = (el, name) => Element.prototype.getAttribute.call(el, name)
const queryAll = (root, selector) => Element.prototype.querySelectorAll.call(root, selector)

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
  const action = (getAttr(form, 'action') ?? '').trim()
  if (action === '' || action === '#') return currentDomain
  try {
    // Resolving against the page URL also handles relative and protocol-relative ("//host/path") actions.
    return new URL(action, window.location.href).hostname
  } catch {
    return currentDomain
  }
}

function isExternalDomain(submissionDomain, currentDomain) {
  if (!submissionDomain || !currentDomain) return false
  return extractDomainFromHostname(submissionDomain) !== extractDomainFromHostname(currentDomain)
}

export function detectSuspiciousForms() {
  const currentDomain = window.location.hostname
  const forms = Document.prototype.querySelectorAll.call(document, 'form')
  let hasSuspiciousForm = false
  const suspiciousForms = []

  for (const form of forms) {
    const inputs = queryAll(form, 'input')
    if (!Array.from(inputs).some(isSensitiveInput)) continue

    const submissionDomain = getFormSubmissionDomain(form, currentDomain)
    if (isExternalDomain(submissionDomain, currentDomain)) {
      hasSuspiciousForm = true
      suspiciousForms.push({
        action: getAttr(form, 'action') ?? '',
        submissionDomain,
        currentDomain,
      })
    }
  }

  return { hasSuspiciousForm, suspiciousForms }
}