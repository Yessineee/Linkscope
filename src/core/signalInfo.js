export const SIGNAL_INFO = {
  gsb_match: {
    icon: 'shield', color: '#4285f4',
    why: "Google maintains a list of sites known to host malware or steal credentials. A match here means this exact URL was already reported by users or automated scanners.",
  },
  ipqs_phishing: {
    icon: 'alertTriangle', color: '#f59e0b',
    why: "This service analyzes domain age, hosting patterns, and known fraud signals. New or disposable domains are commonly used because attackers abandon them quickly once blocked.",
  },
  ipqs_malware: {
    icon: 'alertTriangle', color: '#f59e0b',
    why: "This service analyzes domain age, hosting patterns, and known fraud signals. New or disposable domains are commonly used because attackers abandon them quickly once blocked.",
  },
  ipqs_high_risk: {
    icon: 'alertTriangle', color: '#f59e0b',
    why: "This service analyzes domain age, hosting patterns, and known fraud signals. New or disposable domains are commonly used because attackers abandon them quickly once blocked.",
  },
  vt_detections: {
    icon: 'shieldAlert', color: '#ef4444',
    why: "Dozens of independent antivirus engines scanned this URL. A high number of detections means multiple security vendors, not just one, agree this is dangerous.",
  },
  domain_lookalike: {
    icon: 'shieldX', color: '#f97316',
    why: "Attackers register addresses that imitate trusted brands by swapping characters ('paypa1.com'), adding words ('paypal-verify.com'), or using the brand name on a site that isn't theirs ('paypal.github.io'), hoping you won't notice.",
  },
  domain_mixed_script: {
    icon: 'shieldX', color: '#f97316',
    why: "Some letters from other alphabets look identical to Latin letters but are different characters. Mixing alphabets inside one name is a classic way to fake a trusted domain.",
  },
  suspicious_form: {
    icon: 'alertTriangle', color: '#f59e0b',
    why: "A login form sending your data to a different domain than the one you're visiting is a classic sign of credential theft.",
  },
  redirect_chain: {
    icon: 'alertTriangle', color: '#f97316',
    why: "Legitimate sites rarely bounce through several unrelated domains. Long redirect chains are often used to hide the final phishing destination from filters.",
  },
  no_https: {
    icon: 'alertTriangle', color: '#ef4444',
    why: "Without HTTPS, any data you submit, including passwords, travels unencrypted and can be intercepted by anyone on the network.",
  },
  missing_headers: {
    icon: 'alertTriangle', color: '#94a3b8',
    why: "Security headers like CSP and HSTS aren't phishing-specific, but their absence often correlates with quickly built or poorly maintained sites, including phishing pages that skip standard hardening.",
  },
  urgency_language: {
    icon: 'alertTriangle', color: '#f59e0b',
    why: "Phishing pages often create false urgency, telling you to act now or lose access, to make you act before thinking carefully.",
  },
  incomplete: {
    icon: 'alertTriangle', color: '#f97316',
    why: "Linkscope couldn't reach one of its data sources, so this is a partial result, not a clean bill of health. Rescan in a few minutes to try again.",
  },
}