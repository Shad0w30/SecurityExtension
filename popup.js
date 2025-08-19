
// DOM Elements
const runAuditBtn = document.getElementById('runAuditBtn');
const clearResultsBtn = document.getElementById('clearResultsBtn');
const headersList = document.getElementById('headersList');
const cookiesList = document.getElementById('cookiesList');
const storageList = document.getElementById('storageList');
const criticalCount = document.getElementById('criticalCount');
const highCount = document.getElementById('highCount');
const mediumCount = document.getElementById('mediumCount');
const lowCount = document.getElementById('lowCount');

// Counters
let issueCounts = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0
};

// Security configuration
const config = {
  sensitivePatterns: [
    /password/i, /passwd/i, /pwd/i, /secret/i, 
    /token/i, /auth/i, /credential/i, /session/i,
    /key/i, /api[-_]?key/i, /bearer/i, /jwt/i,
    /ssn/i, /social.?security/i, /credit.?card/i, 
    /cvv/i, /cvc/i, /expiration/i, /phone/i, 
    /email/i, /address/i, /dob/i, /birth/i
  ],
  headerRules: {
    'content-security-policy': { severity: 'high', required: true },
    'x-frame-options': { severity: 'high', required: true, values: ['DENY', 'SAMEORIGIN'] },
    'x-content-type-options': { severity: 'medium', required: true, values: ['nosniff'] },
    'strict-transport-security': { severity: 'high', required: location.protocol === 'https:' },
    'referrer-policy': { severity: 'low', required: true },
    'permissions-policy': { severity: 'medium', required: false },
    'x-xss-protection': { severity: 'low', required: false }
  }
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    if (tabs[0]) {
      runSecurityAudit();
    }
  });
});

// Event Listeners
runAuditBtn.addEventListener('click', runSecurityAudit);
clearResultsBtn.addEventListener('click', clearResults);

// Main function to run security audit
function runSecurityAudit() {
  // Clear previous results
  clearResults();
  
  // Show loading state
  runAuditBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i> Scanning...';
  runAuditBtn.disabled = true;
  
  // Get current tab information
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    if (!tabs[0]) return;
    
    const tabId = tabs[0].id;
    const url = tabs[0].url;
    
    // Get security information
    chrome.cookies.getAll({url}, (cookies) => {
      checkCookies(cookies, url);
    });
    
    // Get storage data
    chrome.storage.local.get(null, (localStorage) => {
      chrome.storage.session.get(null, (sessionStorage) => {
        checkStorage(localStorage, sessionStorage);
      });
    });
    
    // Get headers
    chrome.runtime.sendMessage({
      action: 'getHeaders',
      tabId: tabId
    }, (response) => {
      if (response && response.headers) {
        checkSecurityHeaders(response.headers);
      }
    });
    
    // Update stats after a delay to allow all checks to complete
    setTimeout(() => {
      updateCounters();
      runAuditBtn.innerHTML = '<i class="fas fa-play"></i> Run Security Audit';
      runAuditBtn.disabled = false;
    }, 1000);
  });
}

// Header security checks
function checkSecurityHeaders(headers) {
  Object.entries(config.headerRules).forEach(([header, rule]) => {
    const value = headers[header] || headers[header.toLowerCase()];
    if (!value && rule.required) {
      addIssue('headers', `Missing ${header} header`, rule.severity, 
               `${header} header is required for security`);
    } else if (value && rule.values && !rule.values.includes(value)) {
      addIssue('headers', `Misconfigured ${header} header`, rule.severity, 
               `Invalid value: ${value}. Allowed: ${rule.values.join(', ')}`);
    }
  });
}

// Cookie attribute checks
function checkCookies(cookies, url) {
  cookies.forEach(cookie => {
    // Check for sensitive data in cookie names/values
    config.sensitivePatterns.forEach(pattern => {
      if (pattern.test(cookie.name) || pattern.test(cookie.value)) {
        addIssue('cookies', 'Sensitive data in cookie', 'critical', 
                 `Potential sensitive data in cookie: ${cookie.name}`);
      }
    });

    // Check for missing Secure flag on HTTPS sites
    if (url.startsWith('https://') && !cookie.secure) {
      addIssue('cookies', 'Missing Secure flag', 'high', 
               `Cookie "${cookie.name}" missing Secure flag on HTTPS site`);
    }

    // Check for missing HttpOnly flag
    if (!cookie.httpOnly) {
      addIssue('cookies', 'Missing HttpOnly flag', 'medium', 
               `Cookie "${cookie.name}" is accessible to JavaScript`);
    }

    // Check SameSite attribute
    if (!cookie.sameSite) {
      addIssue('cookies', 'Missing SameSite attribute', 'medium', 
               `Cookie "${cookie.name}" missing SameSite attribute`);
    } else if (cookie.sameSite === 'no_restriction' && !cookie.secure) {
      addIssue('cookies', 'Insecure SameSite=None without Secure', 'high', 
               `Cookie "${cookie.name}" has SameSite=None but no Secure flag`);
    }
  });
}

// Storage checks
function checkStorage(localStorage, sessionStorage) {
  const checkStorageObject = (storage, name) => {
    Object.entries(storage).forEach(([key, value]) => {
      config.sensitivePatterns.forEach(pattern => {
        if (pattern.test(key) || pattern.test(value)) {
          addIssue('storage', 'Sensitive data in storage', 'critical', 
                   `Found in ${name} key: "${key}"`);
        }
      });
    });
  };

  checkStorageObject(localStorage, 'localStorage');
  checkStorageObject(sessionStorage, 'sessionStorage');
}

// Add issue to UI
function addIssue(category, issue, severity, description) {
  // Get the target list
  const list = category === 'headers' ? headersList : 
               category === 'cookies' ? cookiesList : storageList;
  
  // Create issue element
  const issueEl = document.createElement('li');
  issueEl.className = `issue ${severity}`;
  issueEl.innerHTML = `
    <div class="issue-icon">
      <i class="fas fa-exclamation-triangle"></i>
    </div>
    <div class="issue-content">
      <h3>${issue}</h3>
      <p>${description}</p>
    </div>
  `;
  
  // Add to list
  list.appendChild(issueEl);
  
  // Update counters
  issueCounts[severity]++;
}

// Update counters
function updateCounters() {
  criticalCount.textContent = issueCounts.critical;
  highCount.textContent = issueCounts.high;
  mediumCount.textContent = issueCounts.medium;
  lowCount.textContent = issueCounts.low;
}

// Clear results
function clearResults() {
  headersList.innerHTML = '';
  cookiesList.innerHTML = '';
  storageList.innerHTML = '';
  
  // Reset counters
  issueCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  updateCounters();
}
