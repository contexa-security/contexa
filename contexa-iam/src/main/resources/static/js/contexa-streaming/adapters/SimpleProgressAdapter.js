/**
 * SimpleProgressAdapter - Simple Progress UI Adapter
 *
 * A lightweight UIAdapter implementation that displays a simple
 * progress indicator during streaming operations.
 *
 * @example Basic usage with container
 * const adapter = new SimpleProgressAdapter({
 *     container: document.getElementById('progress-container')
 * });
 *
 * @example With custom messages
 * const adapter = new SimpleProgressAdapter({
 *     container: document.body,
 *     loadingMessage: 'AI is thinking...',
 *     errorMessage: 'Something went wrong',
 *     className: 'my-progress'
 * });
 */
class SimpleProgressAdapter extends UIAdapter {
    /**
     * Creates a new SimpleProgressAdapter instance
     * @param {Object} [options] - Configuration options
     * @param {HTMLElement} [options.container] - Container element for the progress UI
     * @param {string} [options.loadingMessage='Processing...'] - Loading message
     * @param {string} [options.errorMessage='An error occurred'] - Error message
     * @param {string} [options.retryMessage='Retrying...'] - Retry message
     * @param {string} [options.className='streaming-progress'] - CSS class name
     */
    constructor(options = {}) {
        super(options);
        this.container = options.container || document.body;
        this.loadingMessage = options.loadingMessage || 'Processing...';
        this.errorMessage = options.errorMessage || 'An error occurred';
        this.retryMessage = options.retryMessage || 'Retrying...';
        this.className = options.className || 'streaming-progress';
        this.progressElement = null;
    }

    /**
     * Creates the progress element HTML
     * @param {string} query - The query being processed
     * @returns {string} HTML string
     */
    createProgressHTML(query) {
        return `
            <div class="${this.className}">
                <div class="${this.className}-spinner"></div>
                <div class="${this.className}-text">${this.escapeHtml(this.loadingMessage)}</div>
                <div class="${this.className}-query">${this.escapeHtml(query.substring(0, 50))}${query.length > 50 ? '...' : ''}</div>
            </div>
        `;
    }

    /**
     * Creates default styles for the progress indicator
     * @returns {string} CSS string
     */
    createDefaultStyles() {
        return `
            .${this.className} {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                padding: 20px 30px;
                background: rgba(0, 0, 0, 0.8);
                color: white;
                border-radius: 8px;
                text-align: center;
                z-index: 10000;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            .${this.className}-spinner {
                width: 30px;
                height: 30px;
                border: 3px solid rgba(255, 255, 255, 0.3);
                border-top-color: white;
                border-radius: 50%;
                margin: 0 auto 10px;
                animation: ${this.className}-spin 1s linear infinite;
            }
            .${this.className}-text {
                font-size: 14px;
                margin-bottom: 5px;
            }
            .${this.className}-query {
                font-size: 12px;
                opacity: 0.7;
            }
            .${this.className}-error {
                color: #ff6b6b;
            }
            .${this.className}-retry {
                color: #ffd93d;
            }
            @keyframes ${this.className}-spin {
                to { transform: rotate(360deg); }
            }
        `;
    }

    /**
     * Injects default styles if not already present
     */
    injectStyles() {
        const styleId = `${this.className}-styles`;
        if (!document.getElementById(styleId)) {
            const style = document.createElement('style');
            style.id = styleId;
            style.textContent = this.createDefaultStyles();
            document.head.appendChild(style);
        }
    }

    /**
     * Escapes HTML special characters
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    onStreamStart(query) {
        this.destroy();
        this.injectStyles();

        const wrapper = document.createElement('div');
        wrapper.innerHTML = this.createProgressHTML(query);
        this.progressElement = wrapper.firstElementChild;
        this.container.appendChild(this.progressElement);
    }

    onChunk(chunk) {
        const textEl = this.progressElement?.querySelector(`.${this.className}-text`);
        if (textEl) {
            const displayText = chunk.substring(0, 50) + (chunk.length > 50 ? '...' : '');
            textEl.textContent = displayText;
        }
    }

    onError(error) {
        const textEl = this.progressElement?.querySelector(`.${this.className}-text`);
        if (textEl) {
            textEl.textContent = this.errorMessage;
            textEl.classList.add(`${this.className}-error`);
        }
    }

    onRetry(attempt, maxAttempts) {
        const textEl = this.progressElement?.querySelector(`.${this.className}-text`);
        if (textEl) {
            textEl.textContent = `${this.retryMessage} (${attempt}/${maxAttempts})`;
            textEl.classList.add(`${this.className}-retry`);
        }
    }

    onComplete() {
        this.destroy();
    }

    onAbort() {
        this.destroy();
    }

    destroy() {
        if (this.progressElement && this.progressElement.parentNode) {
            this.progressElement.parentNode.removeChild(this.progressElement);
            this.progressElement = null;
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = SimpleProgressAdapter;
}
