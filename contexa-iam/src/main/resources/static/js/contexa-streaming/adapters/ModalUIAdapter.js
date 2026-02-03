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
        const header = this.currentModal?.querySelector('.ctx-header-text');
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
        <div id="${this.modalId}" class="ctx-streaming-modal">
            <div class="ctx-modal-content">
                <div class="ctx-modal-header">
                    <div class="ctx-header-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z" opacity="0.3"/>
                            <path d="M12 6v6l4 2"/>
                        </svg>
                    </div>
                    <span class="ctx-header-text">${this.escapeHtml(this.headerText)}</span>
                </div>
                <div class="ctx-query-box">
                    <span class="ctx-query-label">Query</span>
                    <span class="ctx-query-text">${this.escapeHtml(query)}</span>
                </div>
                <div id="streaming-content" class="ctx-stream-content"></div>
                <div class="ctx-modal-footer">
                    <div class="ctx-loading-dots">
                        <span></span><span></span><span></span>
                    </div>
                    <span class="ctx-footer-text">Processing your request...</span>
                </div>
            </div>
        </div>`;
    }

    /**
     * Creates default styles for the modal
     * @returns {string} CSS string
     */
    createDefaultStyles() {
        return `
            .ctx-streaming-modal {
                position: fixed;
                inset: 0;
                background: rgba(0, 0, 0, 0.85);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                opacity: 0;
                visibility: hidden;
                transition: opacity 0.3s ease, visibility 0.3s ease;
            }
            .ctx-streaming-modal.show {
                opacity: 1;
                visibility: visible;
            }
            .ctx-modal-content {
                background: linear-gradient(145deg, rgba(15, 23, 42, 0.98), rgba(30, 41, 59, 0.98));
                border: 1px solid rgba(99, 102, 241, 0.25);
                border-radius: 16px;
                padding: 28px;
                width: 90%;
                max-width: 560px;
                max-height: 75vh;
                display: flex;
                flex-direction: column;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6),
                            0 0 0 1px rgba(255, 255, 255, 0.05) inset;
                transform: scale(0.95) translateY(10px);
                transition: transform 0.3s ease;
            }
            .ctx-streaming-modal.show .ctx-modal-content {
                transform: scale(1) translateY(0);
            }
            .ctx-modal-header {
                display: flex;
                align-items: center;
                gap: 14px;
                margin-bottom: 20px;
            }
            .ctx-header-icon {
                width: 36px;
                height: 36px;
                background: linear-gradient(135deg, #6366f1, #8b5cf6);
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: ctx-pulse 2s ease-in-out infinite;
            }
            .ctx-header-icon svg {
                width: 20px;
                height: 20px;
                color: #fff;
                animation: ctx-spin 3s linear infinite;
            }
            .ctx-header-text {
                font-size: 1.25rem;
                font-weight: 600;
                color: #f1f5f9;
                letter-spacing: -0.01em;
            }
            .ctx-query-box {
                background: rgba(15, 23, 42, 0.7);
                border: 1px solid rgba(71, 85, 105, 0.4);
                border-radius: 10px;
                padding: 14px 16px;
                margin-bottom: 20px;
                display: flex;
                align-items: baseline;
                gap: 10px;
            }
            .ctx-query-label {
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: #a5b4fc;
                flex-shrink: 0;
            }
            .ctx-query-text {
                font-size: 0.9rem;
                color: #cbd5e1;
                line-height: 1.5;
                word-break: break-word;
            }
            .ctx-stream-content {
                flex: 1;
                min-height: 180px;
                max-height: 280px;
                overflow-y: auto;
                background: rgba(0, 0, 0, 0.3);
                border-radius: 10px;
                padding: 16px;
                margin-bottom: 16px;
            }
            .ctx-stream-content::-webkit-scrollbar {
                width: 5px;
            }
            .ctx-stream-content::-webkit-scrollbar-track {
                background: rgba(30, 41, 59, 0.5);
                border-radius: 3px;
            }
            .ctx-stream-content::-webkit-scrollbar-thumb {
                background: rgba(99, 102, 241, 0.5);
                border-radius: 3px;
            }
            .ctx-stream-content::-webkit-scrollbar-thumb:hover {
                background: rgba(99, 102, 241, 0.7);
            }
            .ctx-stream-content.error-state {
                border-color: rgba(239, 68, 68, 0.5);
            }
            .ctx-stream-content.error-state .streaming-step {
                color: #fca5a5;
                border-left-color: #ef4444;
            }
            .streaming-step {
                padding: 10px 14px;
                margin: 8px 0;
                font-size: 0.875rem;
                line-height: 1.6;
                color: #e2e8f0;
                border-left: 2px solid rgba(99, 102, 241, 0.4);
                background: rgba(99, 102, 241, 0.05);
                border-radius: 0 6px 6px 0;
                opacity: 0;
                transform: translateX(-8px);
                transition: opacity 0.25s ease, transform 0.25s ease;
            }
            .streaming-step.visible {
                opacity: 1;
                transform: translateX(0);
            }
            .ctx-modal-footer {
                display: flex;
                align-items: center;
                gap: 12px;
                padding-top: 12px;
                border-top: 1px solid rgba(71, 85, 105, 0.3);
            }
            .ctx-loading-dots {
                display: flex;
                gap: 4px;
            }
            .ctx-loading-dots span {
                width: 6px;
                height: 6px;
                background: #6366f1;
                border-radius: 50%;
                animation: ctx-bounce 1.4s ease-in-out infinite;
            }
            .ctx-loading-dots span:nth-child(1) { animation-delay: -0.32s; }
            .ctx-loading-dots span:nth-child(2) { animation-delay: -0.16s; }
            .ctx-loading-dots span:nth-child(3) { animation-delay: 0s; }
            .ctx-footer-text {
                font-size: 0.8rem;
                color: #94a3b8;
                font-style: italic;
            }
            @keyframes ctx-spin {
                to { transform: rotate(360deg); }
            }
            @keyframes ctx-pulse {
                0%, 100% { box-shadow: 0 0 0 0 rgba(99, 102, 241, 0.4); }
                50% { box-shadow: 0 0 0 8px rgba(99, 102, 241, 0); }
            }
            @keyframes ctx-bounce {
                0%, 80%, 100% { transform: scale(0.8); opacity: 0.5; }
                40% { transform: scale(1.2); opacity: 1; }
            }
            @media (max-width: 640px) {
                .ctx-modal-content {
                    width: 95%;
                    padding: 20px;
                    max-height: 85vh;
                }
                .ctx-header-text { font-size: 1.1rem; }
                .ctx-query-box { flex-direction: column; gap: 6px; }
                .ctx-stream-content { max-height: 220px; }
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
