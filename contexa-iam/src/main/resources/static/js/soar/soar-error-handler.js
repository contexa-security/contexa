/**
 * SOAR Error Handling System
 * 
 * Comprehensive error handling with Circuit Breaker pattern,
 * exponential backoff retry logic, and user-friendly error messages
 */
class SoarErrorHandler {
    constructor() {
        // Circuit Breaker configuration
        this.circuitBreakers = new Map();
        this.defaultCircuitBreakerConfig = {
            failureThreshold: 5,
            successThreshold: 2,
            timeout: 60000, // 1 minute
            halfOpenRequests: 3
        };
        
        // Retry configuration
        this.retryConfig = {
            maxRetries: 3,
            initialDelay: 1000,
            maxDelay: 30000,
            backoffMultiplier: 2
        };
        
        // Error classification
        this.errorTypes = {
            NETWORK: 'network',
            AUTHENTICATION: 'auth',
            AUTHORIZATION: 'authz',
            VALIDATION: 'validation',
            SERVER: 'server',
            TIMEOUT: 'timeout',
            UNKNOWN: 'unknown'
        };
        
        // Error history for analysis
        this.errorHistory = [];
        this.maxHistorySize = 100;
        
        // Recovery strategies
        this.recoveryStrategies = new Map();
        this.initializeRecoveryStrategies();
        
        // Initialize CircuitBreaker class
        this.initCircuitBreaker();
        
        // Global error handler
        this.setupGlobalErrorHandler();
    }

    /**
     * Initialize CircuitBreaker class
     */
    initCircuitBreaker() {
        const self = this;
        
        this.CircuitBreaker = class {
            constructor(name, config) {
                this.name = name;
                this.config = config;
                this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
                this.failureCount = 0;
                this.successCount = 0;
                this.lastFailureTime = null;
                this.halfOpenRequests = 0;
            }

            async execute(fn, fallback) {
                // Check if circuit should transition from OPEN to HALF_OPEN
                if (this.state === 'OPEN') {
                    if (Date.now() - this.lastFailureTime > this.config.timeout) {
                        this.state = 'HALF_OPEN';
                        this.halfOpenRequests = 0;
                        console.log(`Circuit breaker ${this.name} transitioning to HALF_OPEN`);
                    } else {
                        console.log(`🚫 Circuit breaker ${this.name} is OPEN, using fallback`);
                        return fallback ? fallback() : Promise.reject(new Error('Circuit breaker is OPEN'));
                    }
                }

                // Check if HALF_OPEN limit reached
                if (this.state === 'HALF_OPEN' && this.halfOpenRequests >= this.config.halfOpenRequests) {
                    console.log(`Circuit breaker ${this.name} HALF_OPEN limit reached`);
                    return fallback ? fallback() : Promise.reject(new Error('Circuit breaker HALF_OPEN limit reached'));
                }

                try {
                    if (this.state === 'HALF_OPEN') {
                        this.halfOpenRequests++;
                    }

                    const result = await fn();
                    this.onSuccess();
                    return result;
                } catch (error) {
                    this.onFailure();
                    throw error;
                }
            }

            onSuccess() {
                this.failureCount = 0;
                
                if (this.state === 'HALF_OPEN') {
                    this.successCount++;
                    if (this.successCount >= this.config.successThreshold) {
                        this.state = 'CLOSED';
                        this.successCount = 0;
                        console.log(`Circuit breaker ${this.name} is now CLOSED`);
                    }
                }
            }

            onFailure() {
                this.failureCount++;
                this.lastFailureTime = Date.now();
                
                if (this.failureCount >= this.config.failureThreshold) {
                    this.state = 'OPEN';
                    this.successCount = 0;
                    console.log(`Circuit breaker ${this.name} is now OPEN`);
                }
            }

            getState() {
                return {
                    name: this.name,
                    state: this.state,
                    failureCount: this.failureCount,
                    successCount: this.successCount,
                    lastFailureTime: this.lastFailureTime
                };
            }

            reset() {
                this.state = 'CLOSED';
                this.failureCount = 0;
                this.successCount = 0;
                this.lastFailureTime = null;
                this.halfOpenRequests = 0;
            }
        };
    }

    /**
     * Get or create circuit breaker for a service
     */
    getCircuitBreaker(serviceName, config = {}) {
        if (!this.circuitBreakers.has(serviceName)) {
            const breakerConfig = { ...this.defaultCircuitBreakerConfig, ...config };
            const breaker = new this.CircuitBreaker(serviceName, breakerConfig);
            this.circuitBreakers.set(serviceName, breaker);
        }
        return this.circuitBreakers.get(serviceName);
    }

    /**
     * Execute function with circuit breaker
     */
    async executeWithCircuitBreaker(serviceName, fn, fallback) {
        const circuitBreaker = this.getCircuitBreaker(serviceName);
        return circuitBreaker.execute(fn, fallback);
    }

    /**
     * Retry with exponential backoff
     */
    async retryWithBackoff(fn, options = {}) {
        const config = { ...this.retryConfig, ...options };
        let lastError;
        let delay = config.initialDelay;

        for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
            try {
                console.log(`Attempt ${attempt + 1}/${config.maxRetries + 1}`);
                const result = await fn();
                console.log(`Success on attempt ${attempt + 1}`);
                return result;
            } catch (error) {
                lastError = error;
                console.error(`Attempt ${attempt + 1} failed:`, error.message);

                if (attempt < config.maxRetries) {
                    console.log(`⏳ Waiting ${delay}ms before retry...`);
                    await this.sleep(delay);
                    delay = Math.min(delay * config.backoffMultiplier, config.maxDelay);
                }
            }
        }

        throw lastError;
    }

    /**
     * Combined circuit breaker with retry
     */
    async executeWithResilience(serviceName, fn, options = {}) {
        const { fallback, ...retryOptions } = options;
        
        return this.executeWithCircuitBreaker(
            serviceName,
            () => this.retryWithBackoff(fn, retryOptions),
            fallback
        );
    }

    /**
     * Classify error type
     */
    classifyError(error) {
        if (!error) return this.errorTypes.UNKNOWN;

        const message = error.message || '';
        const code = error.code || error.status || 0;

        // Network errors
        if (error.name === 'NetworkError' || message.includes('fetch') || message.includes('network')) {
            return this.errorTypes.NETWORK;
        }

        // Authentication errors
        if (code === 401 || message.includes('unauthorized') || message.includes('authentication')) {
            return this.errorTypes.AUTHENTICATION;
        }

        // Authorization errors
        if (code === 403 || message.includes('forbidden') || message.includes('permission')) {
            return this.errorTypes.AUTHORIZATION;
        }

        // Validation errors
        if (code === 400 || message.includes('validation') || message.includes('invalid')) {
            return this.errorTypes.VALIDATION;
        }

        // Server errors
        if (code >= 500 || message.includes('server')) {
            return this.errorTypes.SERVER;
        }

        // Timeout errors
        if (message.includes('timeout') || error.name === 'TimeoutError') {
            return this.errorTypes.TIMEOUT;
        }

        return this.errorTypes.UNKNOWN;
    }

    /**
     * Get user-friendly error message
     */
    getUserFriendlyMessage(error) {
        const errorType = this.classifyError(error);
        
        const messages = {
            [this.errorTypes.NETWORK]: '네트워크 연결에 문제가 있습니다. 인터넷 연결을 확인해주세요.',
            [this.errorTypes.AUTHENTICATION]: '인증이 필요합니다. 다시 로그인해주세요.',
            [this.errorTypes.AUTHORIZATION]: '이 작업을 수행할 권한이 없습니다.',
            [this.errorTypes.VALIDATION]: '입력한 정보가 올바르지 않습니다. 다시 확인해주세요.',
            [this.errorTypes.SERVER]: '서버에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도해주세요.',
            [this.errorTypes.TIMEOUT]: '요청 시간이 초과되었습니다. 다시 시도해주세요.',
            [this.errorTypes.UNKNOWN]: '알 수 없는 오류가 발생했습니다. 관리자에게 문의해주세요.'
        };

        return messages[errorType] || messages[this.errorTypes.UNKNOWN];
    }

    /**
     * Initialize recovery strategies
     */
    initializeRecoveryStrategies() {
        // Network error recovery
        this.recoveryStrategies.set(this.errorTypes.NETWORK, {
            immediate: () => {
                console.log('🔧 Checking network connectivity...');
                return navigator.onLine;
            },
            delayed: async () => {
                console.log('🔧 Waiting for network recovery...');
                return new Promise((resolve) => {
                    const checkConnection = () => {
                        if (navigator.onLine) {
                            resolve(true);
                        } else {
                            setTimeout(checkConnection, 2000);
                        }
                    };
                    checkConnection();
                });
            }
        });

        // Authentication error recovery
        this.recoveryStrategies.set(this.errorTypes.AUTHENTICATION, {
            immediate: () => {
                console.log('🔧 Redirecting to login...');
                // Redirect to login or refresh token
                return false;
            },
            delayed: null
        });

        // Server error recovery
        this.recoveryStrategies.set(this.errorTypes.SERVER, {
            immediate: () => {
                console.log('🔧 Server error detected, will retry...');
                return false;
            },
            delayed: async () => {
                console.log('🔧 Waiting for server recovery...');
                await this.sleep(5000);
                return true;
            }
        });
    }

    /**
     * Handle error with recovery
     */
    async handleError(error, context = {}) {
        const errorType = this.classifyError(error);
        const timestamp = Date.now();
        
        // Log to history
        this.addToHistory({
            error: {
                message: error.message,
                stack: error.stack,
                code: error.code
            },
            type: errorType,
            context,
            timestamp
        });

        // Get recovery strategy
        const strategy = this.recoveryStrategies.get(errorType);
        let recovered = false;

        if (strategy) {
            // Try immediate recovery
            if (strategy.immediate) {
                recovered = await strategy.immediate();
            }

            // Try delayed recovery if immediate failed
            if (!recovered && strategy.delayed) {
                recovered = await strategy.delayed();
            }
        }

        // Return error handling result
        return {
            error,
            type: errorType,
            message: this.getUserFriendlyMessage(error),
            recovered,
            timestamp,
            context
        };
    }

    /**
     * Add error to history
     */
    addToHistory(errorEntry) {
        this.errorHistory.push(errorEntry);
        
        // Limit history size
        if (this.errorHistory.length > this.maxHistorySize) {
            this.errorHistory.shift();
        }
    }

    /**
     * Get error statistics
     */
    getErrorStatistics() {
        const stats = {
            total: this.errorHistory.length,
            byType: {},
            recentErrors: [],
            errorRate: 0
        };

        // Count by type
        this.errorHistory.forEach(entry => {
            stats.byType[entry.type] = (stats.byType[entry.type] || 0) + 1;
        });

        // Get recent errors (last 10)
        stats.recentErrors = this.errorHistory.slice(-10).reverse();

        // Calculate error rate (errors per minute for last 5 minutes)
        const fiveMinutesAgo = Date.now() - 300000;
        const recentErrorCount = this.errorHistory.filter(e => e.timestamp > fiveMinutesAgo).length;
        stats.errorRate = recentErrorCount / 5; // errors per minute

        return stats;
    }

    /**
     * Setup global error handler
     */
    setupGlobalErrorHandler() {
        // Handle unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled promise rejection:', event.reason);
            this.handleError(event.reason, { source: 'unhandledRejection' });
            event.preventDefault();
        });

        // Handle global errors
        window.addEventListener('error', (event) => {
            console.error('Global error:', event.error);
            this.handleError(event.error, { source: 'globalError' });
            event.preventDefault();
        });
    }

    /**
     * Create error boundary for async functions
     */
    createErrorBoundary(fn, errorHandler) {
        return async (...args) => {
            try {
                return await fn(...args);
            } catch (error) {
                const result = await this.handleError(error, { function: fn.name, args });
                
                if (errorHandler) {
                    return errorHandler(result);
                }
                
                throw error;
            }
        };
    }

    /**
     * Sleep utility
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Reset circuit breaker
     */
    resetCircuitBreaker(serviceName) {
        const breaker = this.circuitBreakers.get(serviceName);
        if (breaker) {
            breaker.reset();
            console.log(`Circuit breaker ${serviceName} has been reset`);
        }
    }

    /**
     * Get all circuit breakers status
     */
    getCircuitBreakersStatus() {
        const status = {};
        this.circuitBreakers.forEach((breaker, name) => {
            status[name] = breaker.getState();
        });
        return status;
    }

    /**
     * Clear error history
     */
    clearErrorHistory() {
        this.errorHistory = [];
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SoarErrorHandler;
}

// Make available globally for browser environment
if (typeof window !== 'undefined') {
    window.SoarErrorHandler = SoarErrorHandler;
}