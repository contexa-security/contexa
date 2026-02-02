/**
 * AIStudioCore - Main Controller for AI Studio
 *
 * Coordinates streaming operations using the shared ContexaStreaming library.
 * Provides a high-level API for AI query handling with modal feedback.
 *
 * @example Basic usage
 * const studio = new AIStudioCore();
 * await studio.initialize();
 * const result = await studio.handleAIQuery('What is machine learning?');
 *
 * @example With callbacks
 * const studio = new AIStudioCore({
 *     onQueryComplete: (response) => console.log('Done:', response),
 *     onQueryError: (error) => console.error('Error:', error)
 * });
 */
class AIStudioCore {
    /**
     * Creates a new AIStudioCore instance
     * @param {Object} [options] - Configuration options
     * @param {string} [options.graphContainerId] - Container ID for graph visualization
     * @param {Function} [options.onQueryStart] - Called when query starts
     * @param {Function} [options.onQueryComplete] - Called when query completes
     * @param {Function} [options.onQueryError] - Called on error
     * @param {Function} [options.onStreamChunk] - Called for each streaming chunk
     * @param {Function} [options.onFinalResponse] - Called when final response received
     */
    constructor(options = {}) {
        this.initializeComponents(options);

        this.eventListeners = [];
        this.timers = [];
        this.lastQueryTime = 0;
        this.isProcessing = false;

        this.callbacks = {
            onQueryStart: options.onQueryStart || null,
            onQueryComplete: options.onQueryComplete || null,
            onQueryError: options.onQueryError || null,
            onStreamChunk: options.onStreamChunk || null,
            onFinalResponse: options.onFinalResponse || null
        };
    }

    /**
     * Initializes components with fallback support
     * Uses shared ContexaStreaming library if available, otherwise uses local modules
     * @param {Object} options - Configuration options
     */
    initializeComponents(options) {
        if (typeof StreamingClient !== 'undefined') {
            this.streamingClient = new StreamingClient({
                markers: AIStudioConfig.markers,
                streaming: AIStudioConfig.streaming
            });
            this.useSharedLibrary = true;
        } else if (typeof StreamingHandler !== 'undefined') {
            this.streamingHandler = new StreamingHandler();
            this.useSharedLibrary = false;
        } else {
            throw new Error('StreamingClient or StreamingHandler is required');
        }

        this.modalManager = typeof ModalManager !== 'undefined' ? new ModalManager() : null;
        this.domRenderer = typeof DOMRenderer !== 'undefined' ? new DOMRenderer() : null;
        this.responseParser = typeof ResponseParser !== 'undefined' ? new ResponseParser() : null;
        this.graphManager = options.graphContainerId && typeof GraphManager !== 'undefined' ?
            new GraphManager(options.graphContainerId) : null;
    }

    /**
     * Initializes the AI Studio Core
     * @returns {Promise<void>}
     */
    async initialize() {
        if (this.graphManager) {
            try {
                await this.graphManager.initialize();
            } catch (error) {
                console.error('Graph initialization failed:', error);
            }
        }
    }

    /**
     * Handles an AI query with streaming
     * @param {string} query - The query text
     * @param {Object} [options] - Query options
     * @param {string} [options.url] - Override endpoint URL
     * @param {string} [options.userId] - User identifier
     * @param {string} [options.queryType] - Query type
     * @param {Object} [options.additionalParams] - Additional request parameters
     * @returns {Promise<Object>} The final response
     */
    async handleAIQuery(query, options = {}) {
        if (!this.canExecuteQuery()) {
            throw new Error('Query rate limit exceeded');
        }

        if (!this.validateQuery(query)) {
            throw new Error('Invalid query');
        }

        this.isProcessing = true;
        this.lastQueryTime = Date.now();

        const url = options.url || AIStudioConfig.api.STUDIO_QUERY_STREAM;
        const requestData = {
            query: query,
            userId: options.userId || 'anonymous',
            queryType: options.queryType || 'GENERAL',
            ...options.additionalParams
        };

        if (this.modalManager) {
            this.modalManager.show(query);
        }

        if (this.callbacks.onQueryStart) {
            this.callbacks.onQueryStart(query);
        }

        if (this.useSharedLibrary) {
            return this.executeWithStreamingClient(url, requestData);
        } else {
            return this.executeWithStreamingHandler(url, requestData);
        }
    }

    /**
     * Executes query using the shared StreamingClient library
     * @param {string} url - The endpoint URL
     * @param {Object} requestData - The request data
     * @returns {Promise<Object>} The final response
     */
    async executeWithStreamingClient(url, requestData) {
        try {
            const finalResponse = await this.streamingClient.stream(url, requestData, {
                onChunk: (chunk) => {
                    if (this.modalManager) {
                        this.modalManager.addStep(chunk);
                    }
                    if (this.callbacks.onStreamChunk) {
                        this.callbacks.onStreamChunk(chunk);
                    }
                },

                onFinalResponse: (response) => {
                    if (this.callbacks.onFinalResponse) {
                        this.callbacks.onFinalResponse(response);
                    }
                },

                onRetry: (attempt, maxAttempts) => {
                    if (this.modalManager) {
                        this.modalManager.showRetry(attempt, maxAttempts);
                    }
                },

                onAbort: () => {
                    this.isProcessing = false;
                    if (this.modalManager) {
                        this.modalManager.hide();
                    }
                }
            });

            this.isProcessing = false;
            if (this.modalManager) {
                this.modalManager.hide();
            }

            if (this.callbacks.onQueryComplete) {
                this.callbacks.onQueryComplete(finalResponse);
            }

            return finalResponse;

        } catch (error) {
            this.isProcessing = false;
            if (this.modalManager) {
                this.modalManager.showError(error.message || 'An error occurred');
                this.setTimeout(() => {
                    this.modalManager.hide();
                }, 3000);
            }

            if (this.callbacks.onQueryError) {
                this.callbacks.onQueryError(error);
            }

            throw error;
        }
    }

    /**
     * Executes query using the legacy StreamingHandler (fallback)
     * @param {string} url - The endpoint URL
     * @param {Object} requestData - The request data
     * @returns {Promise<Object>} The final response
     */
    executeWithStreamingHandler(url, requestData) {
        return new Promise((resolve, reject) => {
            let finalResponse = null;

            this.streamingHandler.startStreaming(url, requestData, {
                onChunk: (chunk) => {
                    if (this.modalManager) {
                        this.modalManager.addStep(chunk);
                    }
                    if (this.callbacks.onStreamChunk) {
                        this.callbacks.onStreamChunk(chunk);
                    }
                },

                onFinalResponse: (data) => {
                    finalResponse = this.parseFinalResponse(data);
                    if (this.callbacks.onFinalResponse) {
                        this.callbacks.onFinalResponse(finalResponse);
                    }
                },

                onDone: () => {
                    this.isProcessing = false;
                    if (this.modalManager) {
                        this.modalManager.hide();
                    }

                    if (this.callbacks.onQueryComplete) {
                        this.callbacks.onQueryComplete(finalResponse);
                    }

                    resolve(finalResponse);
                },

                onError: (error) => {
                    this.isProcessing = false;
                    if (this.modalManager) {
                        this.modalManager.showError(error.message || 'An error occurred');
                        this.setTimeout(() => {
                            this.modalManager.hide();
                        }, 3000);
                    }

                    if (this.callbacks.onQueryError) {
                        this.callbacks.onQueryError(error);
                    }

                    reject(error);
                },

                onRetry: (attempt, maxAttempts) => {
                    if (this.modalManager) {
                        this.modalManager.showRetry(attempt, maxAttempts);
                    }
                },

                onAbort: () => {
                    this.isProcessing = false;
                    if (this.modalManager) {
                        this.modalManager.hide();
                    }
                    resolve(null);
                },

                onStreamError: (errorMessage) => {
                    if (this.modalManager) {
                        this.modalManager.addStep(`Error: ${errorMessage}`);
                    }
                }
            });
        });
    }

    /**
     * Parses the final response from the stream
     * @param {string} data - The raw response data
     * @returns {Object} Parsed response
     */
    parseFinalResponse(data) {
        if (this.responseParser) {
            return this.responseParser.parseFinalResponse(data);
        }

        if (this.streamingClient) {
            return this.streamingClient.parseFinalResponse(data);
        }

        try {
            const markers = AIStudioConfig.markers;
            if (data.includes(markers.FINAL_RESPONSE)) {
                const markerIndex = data.indexOf(markers.FINAL_RESPONSE);
                const jsonString = data.substring(markerIndex + markers.FINAL_RESPONSE.length);
                return JSON.parse(jsonString.trim());
            }
            return JSON.parse(data.trim());
        } catch (error) {
            console.error('Failed to parse final response:', error);
            return { parseError: true, raw: data, errorMessage: error.message };
        }
    }

    /**
     * Validates a query
     * @param {string} query - The query to validate
     * @returns {boolean}
     */
    validateQuery(query) {
        if (!query || typeof query !== 'string') {
            return false;
        }

        const trimmed = query.trim();
        return trimmed.length >= AIStudioConfig.validation.MIN_QUERY_LENGTH &&
               trimmed.length <= AIStudioConfig.validation.MAX_QUERY_LENGTH;
    }

    /**
     * Checks if a query can be executed (rate limiting)
     * @returns {boolean}
     */
    canExecuteQuery() {
        if (this.isProcessing) {
            return false;
        }

        const elapsed = Date.now() - this.lastQueryTime;
        return elapsed >= AIStudioConfig.timing.MIN_QUERY_INTERVAL;
    }

    /**
     * Aborts the current query
     */
    abortQuery() {
        if (this.useSharedLibrary && this.streamingClient) {
            this.streamingClient.abort();
        } else if (this.streamingHandler) {
            this.streamingHandler.abort();
        }

        this.isProcessing = false;
        if (this.modalManager) {
            this.modalManager.hide();
        }
    }

    /**
     * Adds an event listener with tracking
     * @param {HTMLElement} element - The element
     * @param {string} event - The event name
     * @param {Function} handler - The event handler
     * @param {Object} [options] - Event listener options
     */
    addEventListener(element, event, handler, options) {
        element.addEventListener(event, handler, options);
        this.eventListeners.push({ element, event, handler, options });
    }

    /**
     * Sets a timeout with tracking
     * @param {Function} callback - The callback function
     * @param {number} delay - The delay in milliseconds
     * @returns {number} The timer ID
     */
    setTimeout(callback, delay) {
        const timerId = window.setTimeout(() => {
            this.timers = this.timers.filter(id => id !== timerId);
            callback();
        }, delay);
        this.timers.push(timerId);
        return timerId;
    }

    /**
     * Clears a timeout
     * @param {number} timerId - The timer ID
     */
    clearTimeout(timerId) {
        window.clearTimeout(timerId);
        this.timers = this.timers.filter(id => id !== timerId);
    }

    /**
     * Updates the graph with new data
     * @param {Object} data - The graph data
     */
    updateGraph(data) {
        if (this.graphManager && this.graphManager.isReady()) {
            this.graphManager.setData(data);
        }
    }

    /**
     * Gets the current processing state
     * @returns {boolean}
     */
    isQueryProcessing() {
        return this.isProcessing;
    }

    /**
     * Gets the underlying streaming client
     * @returns {StreamingClient|StreamingHandler}
     */
    getStreamingClient() {
        return this.useSharedLibrary ? this.streamingClient : this.streamingHandler;
    }

    /**
     * Checks if using shared streaming library
     * @returns {boolean}
     */
    isUsingSharedLibrary() {
        return this.useSharedLibrary;
    }

    /**
     * Destroys the AIStudioCore instance and cleans up resources
     */
    destroy() {
        this.eventListeners.forEach(({ element, event, handler, options }) => {
            element.removeEventListener(event, handler, options);
        });
        this.eventListeners = [];

        this.timers.forEach(timerId => window.clearTimeout(timerId));
        this.timers = [];

        if (this.useSharedLibrary && this.streamingClient) {
            this.streamingClient.abort();
        } else if (this.streamingHandler) {
            this.streamingHandler.abort();
        }

        if (this.modalManager) {
            this.modalManager.hide();
        }

        if (this.domRenderer) {
            this.domRenderer.destroy();
        }

        if (this.graphManager) {
            this.graphManager.destroy();
        }

        this.isProcessing = false;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = AIStudioCore;
}
