/*global chrome*/

import { detectSuspiciousForms } from './formDetector.js'
import { analyzePage } from './domAnalyzer.js'
import { showWarning, removeWarning } from './warningBanner.js'

function runContentAnalysis() {
  const formResult = detectSuspiciousForms()
  const pageResult = analyzePage()

  return {
    hasSuspiciousForm: formResult.hasSuspiciousForm,
    suspiciousForms: formResult.suspiciousForms,
    hasUrgencyLanguage: pageResult.hasUrgencyLanguage,
    matchedPatterns: pageResult.matchedPatterns,
    isHTTPS: pageResult.isHTTPS,
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  
  if (message.type === 'ANALYSIS_RESULT') {
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

  return true
})

function sendContentResults() {
  const contentResult = runContentAnalysis()

  chrome.runtime.sendMessage({
    type: 'CONTENT_ANALYSIS',
    contentResult,
  }).catch(() => {})
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', sendContentResults)
} else {
  sendContentResults()
}