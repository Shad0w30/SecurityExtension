// Store headers for each request
const headersCache = {};

// Listen for web requests
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === 'main_frame') {
      const headers = {};
      details.responseHeaders.forEach(header => {
        headers[header.name.toLowerCase()] = header.value;
      });
      
      // Store headers for this tab
      headersCache[details.tabId] = headers;
    }
  },
  {urls: ['<all_urls>']},
  ['responseHeaders']
);

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getHeaders') {
    const headers = headersCache[request.tabId] || {};
    sendResponse({headers});
  }
});

// Clear cache when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete headersCache[tabId];
});
