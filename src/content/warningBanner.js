const ICONS = {
  alertTriangle: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
    <path d="M12 9v4"/><path d="M12 17h.01"/>
  </svg>`,
  shieldAlert: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <path d="M12 8v4"/><path d="M12 16h.01"/>
  </svg>`,
  x: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
  </svg>`,
  arrowLeft: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>
  </svg>`,
}

const STYLES = `
  .pd-reset * {
    box-sizing: border-box;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    line-height: 1.5;
  }

  .pd-banner-low {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    background: #854d0e;
    color: #fef9c3;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 14px;
  }

  .pd-banner-low-text { flex: 1; }

  .pd-banner-low-close {
    background: none;
    border: none;
    color: #fef9c3;
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    border-radius: 4px;
  }
  
  .pd-banner-low-label {
  background: rgba(0,0,0,0.25);
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 700;
  margin-right: 6px;
}

  .pd-banner-low-close:hover { background: rgba(255,255,255,0.15); }

  .pd-overlay-suspicious {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    z-index: 2147483647;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .pd-card-suspicious {
    background: #1c1917;
    border: 1px solid #ea580c;
    border-radius: 12px;
    padding: 32px;
    max-width: 480px;
    width: 90%;
    color: #fafaf9;
  }

  .pd-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    color: #ea580c;
  }

  .pd-card-title {
    font-size: 18px;
    font-weight: 600;
    margin: 0;
  }

  .pd-reasons-list {
    list-style: none;
    padding: 0;
    margin: 0 0 24px 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .pd-reason-item {
    font-size: 13px;
    color: #a8a29e;
    padding-left: 12px;
    border-left: 2px solid #ea580c;
  }

  .pd-button-group {
    display: flex;
    gap: 12px;
  }

  .pd-btn-leave {
    flex: 1;
    padding: 10px;
    background: #ea580c;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
  }

  .pd-btn-leave:hover { background: #c2410c; }

  .pd-btn-continue {
    flex: 1;
    padding: 10px;
    background: none;
    color: #a8a29e;
    border: 1px solid #44403c;
    border-radius: 8px;
    font-size: 14px;
    cursor: pointer;
  }

  .pd-btn-continue:hover { background: #292524; }

  .pd-overlay-dangerous {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    z-index: 2147483647;
    background: #0c0a09;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .pd-card-dangerous {
    background: #1c0a09;
    border: 1px solid #dc2626;
    border-radius: 12px;
    padding: 40px;
    max-width: 520px;
    width: 90%;
    color: #fafaf9;
    text-align: center;
  }

  .pd-card-dangerous .pd-card-header {
    flex-direction: column;
    color: #dc2626;
    margin-bottom: 12px;
  }

  .pd-card-dangerous .pd-card-title { font-size: 22px; }

  .pd-card-dangerous .pd-card-header svg {
    width: 48px;
    height: 48px;
  }

  .pd-subtitle {
    font-size: 14px;
    color: #a8a29e;
    margin: 0 0 24px 0;
  }

  .pd-card-dangerous .pd-reasons-list { text-align: left; margin-bottom: 32px; }
  .pd-card-dangerous .pd-reason-item { border-left-color: #dc2626; }

  .pd-btn-back {
    width: 100%;
    padding: 12px;
    background: #dc2626;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 12px;
  }

  .pd-btn-back:hover { background: #b91c1c; }

  .pd-btn-proceed {
    width: 100%;
    padding: 10px;
    background: none;
    color: #57534e;
    border: 1px solid #292524;
    border-radius: 8px;
    font-size: 13px;
    cursor: pointer;
  }

  .pd-btn-proceed:hover { color: #a8a29e; border-color: #44403c; }
`

function injectStyles() {
  if (document.getElementById('pd-styles')) return
  const style = document.createElement('style')
  style.id = 'pd-styles'
  style.textContent = STYLES
  document.head.appendChild(style)
}

function removeExistingWarnings() {
  const existing = document.getElementById('pd-warning-container')
  if (existing) existing.remove()
}

function leaveSafely() {
  if (window.history.length > 1) {
    window.history.back()
  } else {
    window.location.href = 'https://www.google.com'
  }
}

function escapeHtml(str) {
  const div = document.createElement('div')
  div.textContent = String(str ?? '')
  return div.innerHTML
}

function buildReasonsList(reasons) {
  if (!reasons || reasons.length === 0) {
    return '<p style="font-size:13px;color:#a8a29e;margin:0 0 24px 0">No specific indicators identified.</p>'
  }
  return `
    <ul class="pd-reasons-list">
      ${reasons.map(r => `<li class="pd-reason-item">${escapeHtml(r)}</li>`).join('')}
    </ul>
  `
}

function showLowRiskBanner(reasons) {
  injectStyles()
  removeExistingWarnings()

  const container = document.createElement('div')
  container.id = 'pd-warning-container'
  container.className = 'pd-reset'

  const reasonText = escapeHtml(reasons && reasons.length > 0 ? reasons[0] : 'Minor risk indicators detected on this site.')

  container.innerHTML = `
    <div class="pd-banner-low">
      ${ICONS.alertTriangle}
      <span class="pd-banner-low-text">
        <span class="pd-banner-low-label">Low Risk</span> ${reasonText}
      </span>
      <button class="pd-banner-low-close" id="pd-close-btn">
        ${ICONS.x}
      </button>
    </div>
  `

  document.body.appendChild(container)
  document.getElementById('pd-close-btn').addEventListener('click', () => {
    container.remove()
  })
}

function showSuspiciousOverlay(reasons) {
  injectStyles()
  removeExistingWarnings()

  const container = document.createElement('div')
  container.id = 'pd-warning-container'
  container.className = 'pd-reset'

  container.innerHTML = `
    <div class="pd-overlay-suspicious">
      <div class="pd-card-suspicious">
        <div class="pd-card-header">
          ${ICONS.alertTriangle}
          <h2 class="pd-card-title">Suspicious Site Detected</h2>
        </div>
        ${buildReasonsList(reasons)}
        <div class="pd-button-group">
          <button class="pd-btn-leave" id="pd-leave-btn">
            Leave this page
          </button>
          <button class="pd-btn-continue" id="pd-continue-btn">
            Continue anyway
          </button>
        </div>
      </div>
    </div>
  `

  document.body.appendChild(container)
  document.getElementById('pd-leave-btn').addEventListener('click', () => {
    leaveSafely()
  })
  document.getElementById('pd-continue-btn').addEventListener('click', () => {
    container.remove()
  })
}

function showDangerousOverlay(reasons) {
  injectStyles()
  removeExistingWarnings()

  const container = document.createElement('div')
  container.id = 'pd-warning-container'
  container.className = 'pd-reset'

  container.innerHTML = `
    <div class="pd-overlay-dangerous">
      <div class="pd-card-dangerous">
        <div class="pd-card-header">
          ${ICONS.shieldAlert}
          <h2 class="pd-card-title">Dangerous Site Detected</h2>
        </div>
        <p class="pd-subtitle">
          This site has been identified as dangerous. Do not enter any personal information.
        </p>
        ${buildReasonsList(reasons)}
        <button class="pd-btn-back" id="pd-back-btn">
          ${ICONS.arrowLeft}
          Go back to safety
        </button>
        <button class="pd-btn-proceed" id="pd-proceed-btn">
          Proceed anyway (not recommended)
        </button>
      </div>
    </div>
  `

  document.body.appendChild(container)
  document.getElementById('pd-back-btn').addEventListener('click', () => {
    leaveSafely()
  })
  document.getElementById('pd-proceed-btn').addEventListener('click', () => {
    container.remove()
  })
}

export function showWarning(riskLevel, reasons) {
  if (riskLevel === 'DANGEROUS') {
    showDangerousOverlay(reasons)
  } else if (riskLevel === 'SUSPICIOUS') {
    showSuspiciousOverlay(reasons)
  } else if (riskLevel === 'LOW') {
    showLowRiskBanner(reasons)
  }
}

export function removeWarning() {
  removeExistingWarnings()
}