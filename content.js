// Intercept console methods to detect sensitive data leaks
const originalConsole = {
  log: console.log,
  warn: console.warn,
  error: console.error,
  info: console.info
};

const sensitivePatterns = [
  /password/i, /passwd/i, /pwd/i, /secret/i, 
  /token/i, /auth/i, /credential/i, /session/i,
  /key/i, /api[-_]?key/i, /bearer/i, /jwt/i,
  /ssn/i, /social.?security/i, /credit.?card/i, 
  /cvv/i, /cvc/i, /expiration/i, /phone/i, 
  /email/i, /address/i, /dob/i, /birth/i
];

// Override console methods
['log', 'warn', 'error', 'info'].forEach(method => {
  console[method] = function() {
    // Check for sensitive data
    Array.from(arguments).forEach(arg => {
      const str = String(arg);
      sensitivePatterns.forEach(pattern => {
        if (pattern.test(str)) {
          // Send message to background script
          chrome.runtime.sendMessage({
            action: 'consoleSensitiveData',
            data: str.substring(0, 200),
            type: method
          });
        }
      });
    });
    
    // Call original console method
    originalConsole[method].apply(console, arguments);
  };
});
