/*global chrome*/

import { detectSuspiciousForms } from './formDetector.js'
import { analyzePage } from './domAnalyzer.js'
import { showWarning, removeWarning } from './warningBanner.js'



function sameDocument(a, b) {
  try {
    const x = new URL(a), y = new URL(b)
    return x.origin === y.origin && x.pathname === y.pathname
  } catch {
    return false
  }
}

let rescanTimer = null

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  
  if (message.type === 'ANALYSIS_RESULT') {
    if (message.url && !sameDocument(message.url, window.location.href)) {
      sendResponse({ received: false })
      return true
    }
    const { result } = message

    if (result.riskLevel?.label && result.riskLevel.label !== 'SAFE') {
      showWarning(result.riskLevel.label, result.reasons)
    } else {
      removeWarning()
    }

    sendResponse({ received: true })
  }

  if (message.type === 'REMOVE_WARNING') {
    removeWarning()
    sendResponse({ received: true })
  }

  if (message.type === 'PAGE_CHANGED') {
    // A single-page app changed its address without reloading: report the new view once it has rendered.
    clearTimeout(rescanTimer)
    rescanTimer = setTimeout(sendContentResults, 800)
    sendResponse({ received: true })
  }

  return true
})

function safely(fn, fallback) {
  try {
    return fn()
  } catch (err) {
    console.warn('Linkscope detector failed:', err)
    return fallback
  }
}

function runContentAnalysis() {
  const formResult = safely(detectSuspiciousForms, { hasSuspiciousForm: false })
  const pageResult = safely(analyzePage, { hasUrgencyLanguage: false })
  return {
    hasSuspiciousForm: formResult.hasSuspiciousForm === true,
    hasUrgencyLanguage: pageResult.hasUrgencyLanguage === true,
  }
}

function sendContentResults() {
  chrome.runtime
    .sendMessage({ type: 'CONTENT_ANALYSIS', contentResult: runContentAnalysis() })
    .catch(() => {})
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', sendContentResults)
} else {
  sendContentResults()
}