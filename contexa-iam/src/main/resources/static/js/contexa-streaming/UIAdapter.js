/**
 * UIAdapter - Base Class for Streaming UI Adapters
 *
 * Provides a standard interface for handling streaming UI updates.
 * Extend this class to implement custom UI behaviors for different
 * streaming visualization requirements.
 *
 * @example Creating a custom adapter
 * class CustomUIAdapter extends UIAdapter {
 *     onStreamStart(query) {
 *         document.getElementById('output').innerHTML = 'Processing: ' + query;
 *     }
 *
 *     onChunk(chunk) {
 *         document.getElementById('output').innerHTML += chunk;
 *     }
 *
 *     onFinalResponse(response) {
 *         document.getElementById('result').innerHTML = JSON.stringify(response);
 *     }
 * }
 *
 * @example Usage with StreamingClient
 * const adapter = new CustomUIAdapter();
 * const client = new StreamingClient();
 *
 * adapter.onStreamStart(query);
 * await client.stream(url, data, {
 *     onChunk: (chunk) => adapter.onChunk(chunk),
 *     onFinalResponse: (response) => adapter.onFinalResponse(response),
 *     onError: (error) => adapter.onError(error),
 *     onComplete: () => adapter.onComplete()
 * });
 */
class UIAdapter {
    /**
     * Creates a new UIAdapter instance
     * @param {Object} [options] - Configuration options
     */
    constructor(options = {}) {
        this.options = options;
    }

    /**
     * Called when streaming starts
     * Override this method to show loading indicators or initialize UI state
     * @param {string} query - The query being processed
     */
    onStreamStart(query) {
        // Override in subclass
    }

    /**
     * Called for each text chunk received during streaming
     * Override this method to display streaming text updates
     * @param {string} chunk - The text chunk received
     */
    onChunk(chunk) {
        // Override in subclass
    }

    /**
     * Called when a complete sentence is formed (optional)
     * Override this method for sentence-level rendering
     * @param {string} sentence - The complete sentence
     */
    onSentence(sentence) {
        // Override in subclass
    }

    /**
     * Called when the final response is received
     * Override this method to display the final result
     * @param {Object} response - The parsed final response
     */
    onFinalResponse(response) {
        // Override in subclass
    }

    /**
     * Called when an error occurs during streaming
     * Override this method to display error messages
     * @param {Error} error - The error that occurred
     */
    onError(error) {
        // Override in subclass
        console.error('Streaming error:', error);
    }

    /**
     * Called when a retry attempt is made
     * Override this method to show retry status
     * @param {number} attempt - Current retry attempt number
     * @param {number} maxAttempts - Maximum retry attempts
     */
    onRetry(attempt, maxAttempts) {
        // Override in subclass
    }

    /**
     * Called when streaming completes successfully
     * Override this method to clean up UI state
     */
    onComplete() {
        // Override in subclass
    }

    /**
     * Called when streaming is aborted
     * Override this method to handle abort scenarios
     */
    onAbort() {
        // Override in subclass
    }

    /**
     * Cleans up UI resources
     * Override this method to perform cleanup
     */
    destroy() {
        // Override in subclass
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = UIAdapter;
}
