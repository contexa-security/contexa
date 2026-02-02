/**
 * StreamingClientBuilder - Builder Pattern for StreamingClient
 *
 * Provides a fluent API for configuring and building StreamingClient instances
 * with UI adapters and custom configurations.
 *
 * @example Basic usage with modal UI
 * const client = new StreamingClientBuilder()
 *     .withModalUI()
 *     .build();
 *
 * await client.streamWithAdapter('/api/llm/stream', { query: 'Hello' });
 *
 * @example With custom configuration
 * const client = new StreamingClientBuilder()
 *     .withMarkers({ FINAL_RESPONSE: '###FINAL###' })
 *     .withRetry({ maxRetries: 5, retryDelay: 2000 })
 *     .withSimpleProgress(document.getElementById('container'))
 *     .build();
 *
 * @example With custom adapter
 * const customAdapter = new MyCustomAdapter();
 * const client = new StreamingClientBuilder()
 *     .withAdapter(customAdapter)
 *     .build();
 */
class StreamingClientBuilder {
    /**
     * Creates a new StreamingClientBuilder instance
     */
    constructor() {
        this.config = {};
        this.adapter = null;
    }

    /**
     * Sets custom marker strings for response parsing
     * @param {Object} markers - Marker configuration
     * @param {string} [markers.FINAL_RESPONSE] - Final response marker
     * @param {string} [markers.DONE] - Done marker
     * @param {string} [markers.ERROR_PREFIX] - Error prefix marker
     * @returns {StreamingClientBuilder} this instance for chaining
     */
    withMarkers(markers) {
        this.config.markers = { ...this.config.markers, ...markers };
        return this;
    }

    /**
     * Sets retry configuration
     * @param {Object} options - Retry options
     * @param {number} [options.maxRetries] - Maximum retry attempts
     * @param {number} [options.retryDelay] - Initial retry delay in ms
     * @param {number} [options.retryMultiplier] - Retry delay multiplier
     * @returns {StreamingClientBuilder} this instance for chaining
     */
    withRetry(options) {
        this.config.streaming = { ...this.config.streaming, ...options };
        return this;
    }

    /**
     * Sets a custom UI adapter
     * @param {UIAdapter} adapter - The UI adapter instance
     * @returns {StreamingClientBuilder} this instance for chaining
     */
    withAdapter(adapter) {
        this.adapter = adapter;
        return this;
    }

    /**
     * Configures the builder to use a modal UI adapter
     * @param {Object} [options] - Modal adapter options
     * @returns {StreamingClientBuilder} this instance for chaining
     */
    withModalUI(options = {}) {
        this.adapter = new ModalUIAdapter(options);
        return this;
    }

    /**
     * Configures the builder to use a simple progress UI adapter
     * @param {HTMLElement} [container] - Container element for the progress UI
     * @param {Object} [options] - Additional options
     * @returns {StreamingClientBuilder} this instance for chaining
     */
    withSimpleProgress(container, options = {}) {
        this.adapter = new SimpleProgressAdapter({ container, ...options });
        return this;
    }

    /**
     * Configures the builder to use a console output adapter
     * @param {Object} [options] - Console adapter options
     * @returns {StreamingClientBuilder} this instance for chaining
     */
    withConsoleOutput(options = {}) {
        this.adapter = new ConsoleAdapter(options);
        return this;
    }

    /**
     * Builds and returns the configured StreamingClient
     * @returns {StreamingClientWithAdapter} The configured client with adapter
     */
    build() {
        const client = new StreamingClient(this.config);
        return new StreamingClientWithAdapter(client, this.adapter);
    }
}

/**
 * StreamingClientWithAdapter - StreamingClient wrapper with UI adapter integration
 *
 * Wraps a StreamingClient instance and automatically delegates events to the UI adapter.
 */
class StreamingClientWithAdapter {
    /**
     * Creates a new StreamingClientWithAdapter instance
     * @param {StreamingClient} client - The streaming client
     * @param {UIAdapter} adapter - The UI adapter (can be null)
     */
    constructor(client, adapter) {
        this.client = client;
        this.adapter = adapter;
    }

    /**
     * Executes a streaming request with automatic UI adapter integration
     * @param {string} url - The streaming endpoint URL
     * @param {Object} requestData - The request body data
     * @param {Object} [additionalCallbacks] - Additional callbacks to call
     * @returns {Promise<Object|null>} The final parsed response or null
     */
    async streamWithAdapter(url, requestData, additionalCallbacks = {}) {
        const query = requestData.query || requestData.prompt || JSON.stringify(requestData).substring(0, 50);

        if (this.adapter) {
            this.adapter.onStreamStart(query);
        }

        return this.client.stream(url, requestData, {
            onChunk: (chunk) => {
                if (this.adapter) {
                    this.adapter.onChunk(chunk);
                }
                if (additionalCallbacks.onChunk) {
                    additionalCallbacks.onChunk(chunk);
                }
            },

            onFinalResponse: (response) => {
                if (this.adapter) {
                    this.adapter.onFinalResponse(response);
                }
                if (additionalCallbacks.onFinalResponse) {
                    additionalCallbacks.onFinalResponse(response);
                }
            },

            onError: (error) => {
                if (this.adapter) {
                    this.adapter.onError(error);
                }
                if (additionalCallbacks.onError) {
                    additionalCallbacks.onError(error);
                }
            },

            onRetry: (attempt, maxAttempts) => {
                if (this.adapter) {
                    this.adapter.onRetry(attempt, maxAttempts);
                }
                if (additionalCallbacks.onRetry) {
                    additionalCallbacks.onRetry(attempt, maxAttempts);
                }
            },

            onComplete: () => {
                if (this.adapter) {
                    this.adapter.onComplete();
                }
                if (additionalCallbacks.onComplete) {
                    additionalCallbacks.onComplete();
                }
            },

            onAbort: () => {
                if (this.adapter) {
                    this.adapter.onAbort();
                }
                if (additionalCallbacks.onAbort) {
                    additionalCallbacks.onAbort();
                }
            }
        });
    }

    /**
     * Executes a streaming request without UI adapter (raw streaming)
     * @param {string} url - The streaming endpoint URL
     * @param {Object} requestData - The request body data
     * @param {Object} [callbacks] - Callback functions
     * @returns {Promise<Object|null>} The final parsed response or null
     */
    stream(url, requestData, callbacks = {}) {
        return this.client.stream(url, requestData, callbacks);
    }

    /**
     * Aborts the current streaming request
     */
    abort() {
        this.client.abort();
        if (this.adapter) {
            this.adapter.onAbort();
        }
    }

    /**
     * Resets the client and adapter state
     */
    reset() {
        this.client.reset();
    }

    /**
     * Checks if the client is currently streaming
     * @returns {boolean}
     */
    isStreaming() {
        return this.client.isStreaming();
    }

    /**
     * Gets the underlying streaming client
     * @returns {StreamingClient}
     */
    getClient() {
        return this.client;
    }

    /**
     * Gets the UI adapter
     * @returns {UIAdapter}
     */
    getAdapter() {
        return this.adapter;
    }

    /**
     * Sets a new UI adapter
     * @param {UIAdapter} adapter - The new adapter
     */
    setAdapter(adapter) {
        if (this.adapter) {
            this.adapter.destroy();
        }
        this.adapter = adapter;
    }

    /**
     * Destroys the adapter and cleans up resources
     */
    destroy() {
        this.client.reset();
        if (this.adapter) {
            this.adapter.destroy();
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { StreamingClientBuilder, StreamingClientWithAdapter };
}
