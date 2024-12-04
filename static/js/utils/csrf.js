// Shared CSRF and API utilities
class CSRFProtection {
  static token = null;
  static tokenExpiry = null;
  static TOKEN_CACHE_KEY = 'csrf_token_cache';
  static TOKEN_EXPIRY_MINUTES = 30;
  static MAX_RETRIES = 3;
  
  static initialize() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      return this.initializeExtension();
    } else {
      return this.initializeWeb();
    }
  }

  static initializeExtension() {
    // Extension initialization logic
    return this.getCachedToken()
      .then(cachedToken => {
        if (cachedToken) {
          this.token = cachedToken;
          return this.token;
        }
        return this.fetchNewToken();
      })
      .catch(error => {
        console.error('Failed to initialize CSRF protection:', error);
        throw error;
      });
  }

  static initializeWeb() {
    // Web initialization logic
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (!metaTag) {
      throw new Error('CSRF token meta tag not found');
    }
    this.token = metaTag.content;
    return this.token;
  }

  static getCachedToken() {
    return new Promise((resolve) => {
      if (!chrome.storage) {
        return resolve(null);
      }
      chrome.storage.local.get([this.TOKEN_CACHE_KEY])
        .then(result => {
          const tokenData = result[this.TOKEN_CACHE_KEY];
          
          if (!tokenData) {
            return resolve(null);
          }

          // Check if token is expired
          if (Date.now() > tokenData.expiry) {
            // Token expired, remove it
            return chrome.storage.local.remove([this.TOKEN_CACHE_KEY])
              .then(() => resolve(null));
          }

          // Valid token found
          this.token = tokenData.token;
          this.tokenExpiry = tokenData.expiry;
          resolve(this.token);
        });
    });
  }

  static fetchNewToken() {
    return fetch('https://cvify.xyz/csrf-token', {
      method: 'GET',
      credentials: 'include'
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Failed to fetch CSRF token');
      }
      return response.json();
    })
    .then(data => {
      this.token = data.token;
      this.tokenExpiry = Date.now() + (this.TOKEN_EXPIRY_MINUTES * 60 * 1000);
      return this.cacheToken();
    })
    .then(() => {
      return this.token;
    });
  }

  static cacheToken() {
    if (!chrome.storage) {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      chrome.storage.local.set({
        [this.TOKEN_CACHE_KEY]: {
          token: this.token,
          expiry: this.tokenExpiry
        }
      }, resolve);
    });
  }
  
  static getToken() {
    return this.token;
  }

  static refreshToken() {
    return this.fetchNewToken();
  }

  static isTokenExpired() {
    return !this.token || !this.tokenExpiry || Date.now() > this.tokenExpiry;
  }

  static ensureValidToken() {
    if (this.isTokenExpired()) {
      return this.refreshToken();
    }
    return this.token;
  }
}

class CSRFError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CSRFError';
  }
}

function handleCSRFError(error, retryCount = 0) {
  if (retryCount >= CSRFProtection.MAX_RETRIES) return Promise.reject(error);
  
  if (error.message.includes('CSRF token mismatch') || 
      error.message.includes('Invalid CSRF token')) {
    return CSRFProtection.initialize()
      .then(() => true);
  }
  return Promise.resolve(false);
}

function fetchWithCSRF(url, options = {}, retryCount = 0) {
  if (retryCount >= CSRFProtection.MAX_RETRIES) return Promise.reject(error);
  return Promise.resolve()
    .then(() => {
      return CSRFProtection.ensureValidToken();
    })
    .then(() => {
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'X-CSRF-Token': CSRFProtection.getToken(),
          'Content-Type': 'application/json',
        },
        credentials: 'include'
      });
    })
    .then(response => {
      // Handle 403 errors specifically for CSRF issues
      if (response.status === 403) {
        return CSRFProtection.refreshToken()
          .then(() => fetchWithCSRF(url, options, retryCount + 1))
          .catch(error => {
            throw new Error('Failed to refresh CSRF token');
          });
      }

      if (!response.ok) {
        return response.json()
          .then(error => {
            throw new Error(error.message || `Request failed with status ${response.status}`);
          });
      }
      return response;
    })
    .catch(error => {
      return handleCSRFError(error, retryCount)
        .then(shouldRetry => {
          if (shouldRetry) {
            return fetchWithCSRF(url, options, retryCount + 1);
          }
          throw error;
        });
    });
}

// Add a cleanup utility
function cleanupExpiredTokens() {
  chrome.storage.local.get([CSRFProtection.TOKEN_CACHE_KEY], (result) => {
    const tokenData = result[CSRFProtection.TOKEN_CACHE_KEY];
    if (tokenData && Date.now() > tokenData.expiry) {
      chrome.storage.local.remove([CSRFProtection.TOKEN_CACHE_KEY]);
    }
  });
}

class APIError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'APIError';
    this.status = status;
  }
}

function handleAPIError(error) {
  if (error.message.includes('CSRF')) {
    // Handle CSRF specific errors
    console.error('CSRF validation failed:', error);
    // Maybe show a notification to the user
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icon48.png',
      title: 'Security Error',
      message: 'Please refresh the page and try again.'
    });
  } else {
    // Handle other API errors
    console.error('API error:', error);
  }
}

window.CSRFProtection = CSRFProtection;
window.fetchWithCSRF = fetchWithCSRF;
window.cleanupExpiredTokens = cleanupExpiredTokens;
window.APIError = APIError;
window.handleAPIError = handleAPIError;