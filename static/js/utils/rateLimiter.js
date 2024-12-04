class RateLimiter {
    static limits = {
        'default': { maxRequests: 60, timeWindow: 60000 }, // 60 requests per minute
        '/process': { maxRequests: 10, timeWindow: 60000 }, // 10 extractions per minute
        '/login': { maxRequests: 5, timeWindow: 300000 },   // 5 attempts per 5 minutes
        '/register': { maxRequests: 3, timeWindow: 300000 }, // 3 attempts per 5 minutes
        '/verify-email': { maxRequests: 5, timeWindow: 300000 }, // 5 attempts per 5 minutes
        '/resend-verification': { maxRequests: 2, timeWindow: 300000 }, // 2 attempts per 5 minutes
        '/generate-payment-token': { maxRequests: 5, timeWindow: 300000 }, // 5 attempts per 5 minutes
        '/create-cv': { maxRequests: 1, timeWindow: 5000 }, // 1 attempt per 5 seconds
        '/rename': { maxRequests: 1, timeWindow: 5000 }, // 1 attempt per 5 seconds
        '/duplicate': { maxRequests: 1, timeWindow: 5000 }, // 1 attempt per 5 seconds
        '/delete': { maxRequests: 1, timeWindow: 5000 }, // 1 attempt per 5 seconds
        '/update': { maxRequests: 1, timeWindow: 5000 }, // 1 attempt per 5 seconds
        '/request-password-reset': { maxRequests: 3, timeWindow: 300000 }, // 3 attempts per 5 minutes
        '/reset-password': { maxRequests: 1, timeWindow: 5000 }, // 1 attempt per 5 seconds
    };

    static requests = new Map();

    static async checkLimit(endpoint) {
        const now = Date.now();
        const limit = this.limits[endpoint] || this.limits.default;
        const key = endpoint;

        // Get or initialize request history
        if (!this.requests.has(key)) {
            this.requests.set(key, []);
        }

        // Clean up old requests
        const requests = this.requests.get(key);
        const validRequests = requests.filter(timestamp => 
            now - timestamp < limit.timeWindow
        );
        this.requests.set(key, validRequests);

        // Check if limit is exceeded
        if (validRequests.length >= limit.maxRequests) {
            const oldestRequest = validRequests[0];
            const timeToWait = limit.timeWindow - (now - oldestRequest);
            throw new Error(chrome.i18n.getMessage('rateLimitExceeded',
                [Math.ceil(timeToWait / 1000)]));
        }

        // Add new request
        validRequests.push(now);
        this.requests.set(key, validRequests);
    }

    static async clearHistory() {
        this.requests.clear();
    }
}

// Enhanced fetchWithCSRF that includes rate limiting
function fetchWithRateLimit(fetchFunction, url, options = {}) {
    const endpoint = url.startsWith('http') ? new URL(url).pathname : url;
    
    return RateLimiter.checkLimit(endpoint)
        .then(() => {
            return fetchFunction(url, options);
        })
        .catch(error => {
            if (error.message.includes('Rate limit exceeded')) {
                // Handle rate limit error
                console.error('Rate limit error:', error);
                throw new Error(chrome.i18n.getMessage('rateLimitExceeded',
                    [error.message.match(/\d+/)[0]]));
            }
            throw error;
        });
}

function debounce(func, delay = 300) {
    let debounceTimer;
    return function() {
      const context = this;
      const args = arguments;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => func.apply(context, args), delay);
    }
}

window.fetchWithRateLimit = fetchWithRateLimit;
window.debounce = debounce;
