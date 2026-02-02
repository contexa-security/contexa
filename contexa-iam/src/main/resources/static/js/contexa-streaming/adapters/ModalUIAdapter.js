/**
 * ModalUIAdapter - Modal-based Streaming UI Adapter
 *
 * A UIAdapter implementation that displays streaming progress in a modal dialog.
 * Provides a rich visual experience with animated steps and status updates.
 *
 * @example Basic usage
 * const adapter = new ModalUIAdapter();
 * adapter.onStreamStart('Analyzing your question...');
 * adapter.onChunk('Processing step 1');
 * adapter.onChunk('Processing step 2');
 * adapter.onFinalResponse({ result: 'success' });
 * adapter.onComplete();
 *
 * @example With custom options
 * const adapter = new ModalUIAdapter({
 *     modalId: 'my-modal',
 *     headerText: 'AI Processing...',
 *     hideDelay: 500
 * });
 */
class ModalUIAdapter extends UIAdapter {
    /**
     * Creates a new ModalUIAdapter instance
     * @param {Object} [options] - Configuration options
     * @param {string} [options.modalId='streaming-modal'] - Modal element ID
     * @param {string} [options.headerText='AI Analyzing...'] - Default header text
     * @param {number} [options.hideDelay=300] - Delay before hiding modal (ms)
     * @param {number} [options.animationDelay=100] - Animation delay (ms)
     */
    constructor(options = {}) {
        super(options);
        this.modalId = options.modalId || 'streaming-modal';
        this.headerText = options.headerText || 'AI Analyzing...';
        this.hideDelay = options.hideDelay || 300;
        this.animationDelay = options.animationDelay || 100;
        this.currentModal = null;
    }

    onStreamStart(query) {
        this.hide();
        this.injectStyles();

        const modalHtml = this.createModalHtml(query);
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        this.currentModal = document.getElementById(this.modalId);

        requestAnimationFrame(() => {
            if (this.currentModal) {
                this.currentModal.classList.add('show');
            }
        });
    }

    onChunk(chunk) {
        this.addStep(chunk);
    }

    onSentence(sentence) {
        this.addStep(sentence);
    }

    onFinalResponse(response) {
        this.updateHeader('Complete');
    }

    onError(error) {
        this.updateHeader('Error');
        this.addStep(`Error: ${error.message || error}`);

        const content = this.currentModal?.querySelector('#streaming-content');
        if (content) {
            content.classList.add('error-state');
        }
    }

    onRetry(attempt, maxAttempts) {
        this.updateHeader(`Retrying... (${attempt}/${maxAttempts})`);
        this.addStep(`Connection lost. Retrying... (${attempt}/${maxAttempts})`);
    }

    onComplete() {
        setTimeout(() => {
            this.hide();
        }, this.hideDelay);
    }

    onAbort() {
        this.hide();
    }

    /**
     * Hides and removes the current modal
     */
    hide() {
        if (this.currentModal) {
            this.currentModal.classList.remove('show');
            this.currentModal.style.display = 'none';

            const modal = this.currentModal;
            this.currentModal = null;

            setTimeout(() => {
                if (modal && modal.parentNode) {
                    modal.parentNode.removeChild(modal);
                }
            }, this.hideDelay);
        }

        const existingModal = document.getElementById(this.modalId);
        if (existingModal && existingModal.parentNode) {
            existingModal.parentNode.removeChild(existingModal);
        }
    }

    /**
     * Adds a step message to the modal content
     * @param {string} message - The step message to display
     */
    addStep(message) {
        const content = this.currentModal?.querySelector('#streaming-content');
        if (!content) {
            return;
        }

        const step = document.createElement('div');
        step.className = 'streaming-step';
        step.textContent = message;
        content.appendChild(step);

        requestAnimationFrame(() => {
            step.classList.add('visible');
            content.scrollTop = content.scrollHeight;
        });
    }

    /**
     * Updates the modal header text
     * @param {string} text - The new header text
     */
    updateHeader(text) {
        const header = this.currentModal?.querySelector('.streaming-header span:last-child');
        if (header) {
            header.textContent = text;
        }
    }

    /**
     * Creates the modal HTML structure
     * @param {string} query - The query being processed
     * @returns {string} The modal HTML
     */
    createModalHtml(query) {
        return `
        <div id="${this.modalId}" class="streaming-modal">
            <div class="streaming-modal-content">
                <div class="streaming-header">
                    <span class="streaming-icon"></span>
                    <span>${this.escapeHtml(this.headerText)}</span>
                </div>
                <div class="streaming-query">${this.escapeHtml(query)}</div>
                <div id="streaming-content" class="streaming-content"></div>
            </div>
        </div>`;
    }

    /**
     * Creates default styles for the modal
     * @returns {string} CSS string
     */
    createDefaultStyles() {
        return `
            .streaming-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            .streaming-modal.show {
                opacity: 1;
            }
            .streaming-modal-content {
                background: white;
                border-radius: 12px;
                padding: 24px;
                max-width: 500px;
                width: 90%;
                max-height: 80vh;
                overflow: hidden;
                display: flex;
                flex-direction: column;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            }
            .streaming-header {
                display: flex;
                align-items: center;
                gap: 10px;
                font-size: 18px;
                font-weight: 600;
                margin-bottom: 12px;
                color: #333;
            }
            .streaming-icon {
                width: 24px;
                height: 24px;
                border: 3px solid #007bff;
                border-top-color: transparent;
                border-radius: 50%;
                animation: streaming-spin 1s linear infinite;
            }
            .streaming-query {
                font-size: 14px;
                color: #666;
                margin-bottom: 16px;
                padding: 12px;
                background: #f8f9fa;
                border-radius: 8px;
                word-break: break-word;
            }
            .streaming-content {
                flex: 1;
                overflow-y: auto;
                max-height: 300px;
            }
            .streaming-content.error-state {
                color: #dc3545;
            }
            .streaming-step {
                padding: 8px 12px;
                margin: 4px 0;
                background: #f0f7ff;
                border-radius: 6px;
                font-size: 14px;
                opacity: 0;
                transform: translateY(10px);
                transition: opacity 0.3s ease, transform 0.3s ease;
            }
            .streaming-step.visible {
                opacity: 1;
                transform: translateY(0);
            }
            @keyframes streaming-spin {
                to { transform: rotate(360deg); }
            }
        `;
    }

    /**
     * Injects default styles if not already present
     */
    injectStyles() {
        const styleId = 'streaming-modal-styles';
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
        if (!text) {
            return '';
        }
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Checks if the modal is currently visible
     * @returns {boolean}
     */
    isVisible() {
        return this.currentModal !== null && this.currentModal.classList.contains('show');
    }

    /**
     * Clears all step messages from the modal
     */
    clearSteps() {
        const content = this.currentModal?.querySelector('#streaming-content');
        if (content) {
            content.innerHTML = '';
        }
    }

    destroy() {
        this.hide();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ModalUIAdapter;
}
