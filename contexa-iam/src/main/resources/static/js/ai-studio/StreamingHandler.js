/**
 * StreamingHandler - SSE Streaming Handler with Retry Logic
 * Handles Server-Sent Events streaming with automatic reconnection
 */
class StreamingHandler {
    constructor(options = {}) {
        this.maxRetries = options.maxRetries || AIStudioConfig.streaming.MAX_RETRIES;
        this.retryDelay = options.retryDelay || AIStudioConfig.streaming.RETRY_DELAY;
        this.retryMultiplier = options.retryMultiplier || AIStudioConfig.streaming.RETRY_MULTIPLIER;
        this.retryCount = 0;
        this.abortController = null;
        this.isAborted = false;
    }

    /**
     * Starts streaming from the specified URL
     * @param {string} url - The streaming endpoint URL
     * @param {Object} requestData - The request body data
     * @param {Object} callbacks - Callback functions for handling events
     * @returns {Promise<void>}
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

            if (this.retryCount < this.maxRetries) {
                this.retryCount++;
                const delay = this.retryDelay * Math.pow(this.retryMultiplier, this.retryCount - 1);

                if (callbacks.onRetry) {
                    callbacks.onRetry(this.retryCount, this.maxRetries);
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

        if (data === AIStudioConfig.markers.DONE) {
            if (callbacks.onDone) {
                callbacks.onDone();
            }
            return;
        }

        if (data.startsWith(AIStudioConfig.markers.ERROR_PREFIX)) {
            const errorMessage = data.substring(AIStudioConfig.markers.ERROR_PREFIX.length).trim();
            if (callbacks.onStreamError) {
                callbacks.onStreamError(errorMessage);
            }
            return;
        }

        if (data.includes(AIStudioConfig.markers.FINAL_RESPONSE)) {
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
     * Gets CSRF headers from meta tags
     * @returns {Object} CSRF headers
     */
    getCsrfHeaders() {
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
     * Resets the handler state
     */
    reset() {
        this.abort();
        this.retryCount = 0;
        this.isAborted = false;
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
     * Checks if the handler is currently streaming
     * @returns {boolean}
     */
    isStreaming() {
        return this.abortController !== null && !this.isAborted;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = StreamingHandler;
}
