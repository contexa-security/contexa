/**
 * StreamingClient - Universal LLM Streaming Client
 *
 * A reusable streaming client for LLM responses that can be used
 * with any UI implementation through the UIAdapter pattern.
 *
 * @example Basic usage
 * const client = new StreamingClient();
 * const result = await client.stream('/api/llm/stream', { query: 'Hello' });
 *
 * @example With callbacks
 * const client = new StreamingClient();
 * await client.stream('/api/llm/stream', { query: 'Hello' }, {
 *     onChunk: (chunk) => console.log('Chunk:', chunk),
 *     onFinalResponse: (response) => console.log('Final:', response),
 *     onError: (error) => console.error('Error:', error)
 * });
 *
 * @example With custom configuration
 * const client = new StreamingClient({
 *     markers: { FINAL_RESPONSE: '###FINAL###' },
 *     streaming: { maxRetries: 5, retryDelay: 2000 }
 * });
 */
class StreamingClient {
    /**
     * Default configuration for the streaming client
     * @type {Object}
     */
    static DEFAULT_CONFIG = {
        markers: {
            FINAL_RESPONSE: '###FINAL_RESPONSE###',
            DONE: '[DONE]',
            ERROR_PREFIX: 'ERROR:',
            JSON_START: '===JSON_START===',
            JSON_END: '===JSON_END==='
        },
        streaming: {
            maxRetries: 3,
            retryDelay: 1000,
            retryMultiplier: 1.5
        }
    };

    /**
     * Creates a new StreamingClient instance
     * @param {Object} config - Configuration options
     * @param {Object} [config.markers] - Marker strings for parsing responses
     * @param {Object} [config.streaming] - Streaming configuration
     */
    constructor(config = {}) {
        this.config = this.mergeConfig(StreamingClient.DEFAULT_CONFIG, config);
        this.abortController = null;
        this.isAborted = false;
        this.retryCount = 0;
    }

    /**
     * Deep merges configuration objects
     * @param {Object} defaults - Default configuration
     * @param {Object} overrides - Override values
     * @returns {Object} Merged configuration
     */
    mergeConfig(defaults, overrides) {
        const result = { ...defaults };

        for (const key in overrides) {
            if (overrides[key] !== undefined && overrides[key] !== null) {
                if (typeof overrides[key] === 'object' && !Array.isArray(overrides[key])) {
                    result[key] = this.mergeConfig(defaults[key] || {}, overrides[key]);
                } else {
                    result[key] = overrides[key];
                }
            }
        }

        return result;
    }

    /**
     * Executes a streaming request
     * @param {string} url - The streaming endpoint URL
     * @param {Object} requestData - The request body data
     * @param {Object} [callbacks] - Callback functions for handling events
     * @param {Function} [callbacks.onChunk] - Called for each text chunk
     * @param {Function} [callbacks.onFinalResponse] - Called when final response is received
     * @param {Function} [callbacks.onComplete] - Called when streaming completes
     * @param {Function} [callbacks.onError] - Called on error
     * @param {Function} [callbacks.onRetry] - Called on retry (attempt, maxAttempts)
     * @param {Function} [callbacks.onAbort] - Called when streaming is aborted
     * @returns {Promise<Object|null>} The final parsed response or null
     */
    async stream(url, requestData, callbacks = {}) {
        return new Promise((resolve, reject) => {
            let finalResponse = null;

            this.startStreaming(url, requestData, {
                onChunk: (chunk) => {
                    if (callbacks.onChunk) {
                        callbacks.onChunk(chunk);
                    }
                },

                onFinalResponse: (data) => {
                    finalResponse = this.parseFinalResponse(data);
                    if (callbacks.onFinalResponse) {
                        callbacks.onFinalResponse(finalResponse);
                    }
                },

                onComplete: () => {
                    if (callbacks.onComplete) {
                        callbacks.onComplete();
                    }
                    resolve(finalResponse);
                },

                onError: (error) => {
                    if (callbacks.onError) {
                        callbacks.onError(error);
                    }
                    reject(error);
                },

                onRetry: (attempt, max) => {
                    if (callbacks.onRetry) {
                        callbacks.onRetry(attempt, max);
                    }
                },

                onAbort: () => {
                    if (callbacks.onAbort) {
                        callbacks.onAbort();
                    }
                    resolve(null);
                },

                onDone: callbacks.onDone,
                onEvent: callbacks.onEvent,
                onStreamError: callbacks.onStreamError
            });
        });
    }

    /**
     * Starts the streaming process
     * @param {string} url - The streaming endpoint URL
     * @param {Object} requestData - The request body data
     * @param {Object} callbacks - Callback functions
     */
    async startStreaming(url, requestData, callbacks) {
        this.isAborted = false;
        this.abortController = new AbortController();

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'text/event-stream',
                    ...this.getCsrfHeaders()
                },
                body: JSON.stringify(requestData),
                signal: this.abortController.signal
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            this.retryCount = 0;
            await this.processStream(response, callbacks);

        } catch (error) {
            if (error.name === 'AbortError' || this.isAborted) {
                if (callbacks.onAbort) {
                    callbacks.onAbort();
                }
                return;
            }

            const streamingConfig = this.config.streaming;
            if (this.retryCount < streamingConfig.maxRetries) {
                this.retryCount++;
                const delay = streamingConfig.retryDelay *
                    Math.pow(streamingConfig.retryMultiplier, this.retryCount - 1);

                if (callbacks.onRetry) {
                    callbacks.onRetry(this.retryCount, streamingConfig.maxRetries);
                }

                await this.sleep(delay);

                if (!this.isAborted) {
                    return this.startStreaming(url, requestData, callbacks);
                }
            }

            if (callbacks.onError) {
                callbacks.onError(error);
            }
        }
    }

    /**
     * Processes the streaming response
     * @param {Response} response - The fetch response
     * @param {Object} callbacks - Callback functions
     */
    async processStream(response, callbacks) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        try {
            while (true) {
                const { done, value } = await reader.read();

                if (done) {
                    if (buffer.trim()) {
                        this.processSSEData(buffer, callbacks);
                    }
                    break;
                }

                const text = decoder.decode(value, { stream: true });
                buffer += text;

                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    this.processSSELine(line, callbacks);
                }
            }

            if (callbacks.onComplete) {
                callbacks.onComplete();
            }

        } finally {
            reader.releaseLock();
        }
    }

    /**
     * Processes a single SSE line
     * @param {string} line - The SSE line to process
     * @param {Object} callbacks - Callback functions
     */
    processSSELine(line, callbacks) {
        const trimmedLine = line.trim();

        if (!trimmedLine || trimmedLine.startsWith(':')) {
            return;
        }

        if (trimmedLine.startsWith('data:')) {
            const data = trimmedLine.substring(5).trim();
            this.processSSEData(data, callbacks);
        } else if (trimmedLine.startsWith('event:')) {
            const event = trimmedLine.substring(6).trim();
            if (callbacks.onEvent) {
                callbacks.onEvent(event);
            }
        }
    }

    /**
     * Processes SSE data content
     * @param {string} data - The data content
     * @param {Object} callbacks - Callback functions
     */
    processSSEData(data, callbacks) {
        if (!data) {
            return;
        }

        const markers = this.config.markers;

        if (data === markers.DONE) {
            if (callbacks.onDone) {
                callbacks.onDone();
            }
            return;
        }

        if (data.startsWith(markers.ERROR_PREFIX)) {
            const errorMessage = data.substring(markers.ERROR_PREFIX.length).trim();
            if (callbacks.onStreamError) {
                callbacks.onStreamError(errorMessage);
            }
            return;
        }

        if (data.includes(markers.FINAL_RESPONSE)) {
            if (callbacks.onFinalResponse) {
                callbacks.onFinalResponse(data);
            }
            return;
        }

        if (callbacks.onChunk) {
            callbacks.onChunk(data);
        }
    }

    /**
     * Parses the final response from streaming data
     * @param {string} data - The raw response data
     * @returns {Object|null} Parsed response or null
     */
    parseFinalResponse(data) {
        if (!data) {
            return null;
        }

        try {
            const markers = this.config.markers;

            if (data.includes(markers.FINAL_RESPONSE)) {
                const markerIndex = data.indexOf(markers.FINAL_RESPONSE);
                const jsonString = data.substring(markerIndex + markers.FINAL_RESPONSE.length);
                return this.parseJson(jsonString);
            }

            return this.parseJson(data);
        } catch (error) {
            console.error('Failed to parse final response:', error);
            return {
                parseError: true,
                raw: data,
                errorMessage: error.message
            };
        }
    }

    /**
     * Parses JSON string with error handling
     * @param {string} jsonString - The JSON string to parse
     * @returns {Object} Parsed JSON object
     */
    parseJson(jsonString) {
        if (!jsonString || typeof jsonString !== 'string') {
            throw new Error('Invalid JSON input');
        }

        const trimmed = jsonString.trim();
        if (!trimmed) {
            throw new Error('Empty JSON input');
        }

        return JSON.parse(trimmed);
    }

    /**
     * Gets CSRF headers from meta tags
     * @returns {Object} CSRF headers
     */
    getCsrfHeaders() {
        if (typeof document === 'undefined') {
            return {};
        }

        const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;

        if (csrfToken && csrfHeader) {
            return { [csrfHeader]: csrfToken };
        }

        return {};
    }

    /**
     * Aborts the current streaming request
     */
    abort() {
        this.isAborted = true;
        if (this.abortController) {
            this.abortController.abort();
            this.abortController = null;
        }
    }

    /**
     * Resets the client state
     */
    reset() {
        this.abort();
        this.retryCount = 0;
        this.isAborted = false;
    }

    /**
     * Checks if the client is currently streaming
     * @returns {boolean}
     */
    isStreaming() {
        return this.abortController !== null && !this.isAborted;
    }

    /**
     * Sleep utility function
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Gets the current configuration
     * @returns {Object} Current configuration
     */
    getConfig() {
        return this.config;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = StreamingClient;
}
