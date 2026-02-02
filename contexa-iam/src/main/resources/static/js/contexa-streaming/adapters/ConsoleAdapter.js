/**
 * ConsoleAdapter - Console Output Adapter
 *
 * A simple UIAdapter implementation that outputs streaming events to the console.
 * Useful for debugging, testing, and headless environments.
 *
 * @example Basic usage
 * const adapter = new ConsoleAdapter();
 * adapter.onStreamStart('Hello world');
 * adapter.onChunk('Hello');
 * adapter.onChunk(' world');
 * adapter.onFinalResponse({ result: 'success' });
 * adapter.onComplete();
 *
 * @example With prefix
 * const adapter = new ConsoleAdapter({ prefix: '[MyApp]' });
 */
class ConsoleAdapter extends UIAdapter {
    /**
     * Creates a new ConsoleAdapter instance
     * @param {Object} [options] - Configuration options
     * @param {string} [options.prefix='[STREAM]'] - Prefix for console messages
     * @param {boolean} [options.showTimestamp=false] - Whether to show timestamps
     */
    constructor(options = {}) {
        super(options);
        this.prefix = options.prefix || '[STREAM]';
        this.showTimestamp = options.showTimestamp || false;
    }

    /**
     * Formats a log message with optional timestamp
     * @param {string} type - Message type
     * @param {string} message - The message
     * @returns {string} Formatted message
     */
    formatMessage(type, message) {
        const timestamp = this.showTimestamp ? `[${new Date().toISOString()}] ` : '';
        return `${timestamp}${this.prefix} ${type}: ${message}`;
    }

    onStreamStart(query) {
        console.log(this.formatMessage('START', query));
    }

    onChunk(chunk) {
        console.log(this.formatMessage('CHUNK', chunk));
    }

    onSentence(sentence) {
        console.log(this.formatMessage('SENTENCE', sentence));
    }

    onFinalResponse(response) {
        console.log(this.formatMessage('FINAL', JSON.stringify(response, null, 2)));
    }

    onError(error) {
        console.error(this.formatMessage('ERROR', error.message || error));
    }

    onRetry(attempt, maxAttempts) {
        console.warn(this.formatMessage('RETRY', `Attempt ${attempt}/${maxAttempts}`));
    }

    onComplete() {
        console.log(this.formatMessage('COMPLETE', 'Streaming finished'));
    }

    onAbort() {
        console.log(this.formatMessage('ABORT', 'Streaming aborted'));
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ConsoleAdapter;
}
