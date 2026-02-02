/**
 * ModalManager - Streaming Modal Management
 * Handles creation, display, and cleanup of streaming progress modals
 */
class ModalManager {
    constructor() {
        this.currentModal = null;
        this.modalId = 'streaming-modal';
    }

    /**
     * Shows the streaming modal with the given query
     * @param {string} query - The query being processed
     */
    show(query) {
        this.hide();

        const modalHtml = this.createModalHtml(query);
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        this.currentModal = document.getElementById(this.modalId);

        requestAnimationFrame(() => {
            if (this.currentModal) {
                this.currentModal.classList.add('show');
            }
        });
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
            }, AIStudioConfig.timing.MODAL_HIDE_DELAY);
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
     * Shows an error state in the modal
     * @param {string} errorMessage - The error message to display
     */
    showError(errorMessage) {
        this.updateHeader('Error');
        this.addStep(`Error: ${errorMessage}`);

        const content = this.currentModal?.querySelector('#streaming-content');
        if (content) {
            content.classList.add('error-state');
        }
    }

    /**
     * Shows a retry state in the modal
     * @param {number} attempt - Current retry attempt
     * @param {number} maxAttempts - Maximum retry attempts
     */
    showRetry(attempt, maxAttempts) {
        this.updateHeader(`Retrying... (${attempt}/${maxAttempts})`);
        this.addStep(`Connection lost. Retrying... (${attempt}/${maxAttempts})`);
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
                    <span>AI Analyzing...</span>
                </div>
                <div class="streaming-query">${this.escapeHtml(query)}</div>
                <div id="streaming-content" class="streaming-content"></div>
            </div>
        </div>`;
    }

    /**
     * Escapes HTML special characters
     * @param {string} text - The text to escape
     * @returns {string} The escaped text
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
     * Checks if a modal is currently displayed
     * @returns {boolean}
     */
    isVisible() {
        return this.currentModal !== null && this.currentModal.classList.contains('show');
    }

    /**
     * Gets the modal content element
     * @returns {HTMLElement|null}
     */
    getContentElement() {
        return this.currentModal?.querySelector('#streaming-content');
    }

    /**
     * Clears all step messages from the modal
     */
    clearSteps() {
        const content = this.getContentElement();
        if (content) {
            content.innerHTML = '';
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ModalManager;
}
