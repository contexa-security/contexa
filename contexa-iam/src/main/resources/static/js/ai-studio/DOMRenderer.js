/**
 * DOMRenderer - Batched DOM Update Manager
 * Optimizes DOM updates by batching them using requestAnimationFrame
 */
class DOMRenderer {
    constructor() {
        this.pendingUpdates = [];
        this.rafId = null;
    }

    /**
     * Queues a DOM update for batched execution
     * @param {HTMLElement} element - The element to update
     * @param {Function} updateFn - The update function to execute
     */
    queueUpdate(element, updateFn) {
        this.pendingUpdates.push({ element, updateFn });
        this.scheduleFlush();
    }

    /**
     * Schedules a flush of pending updates
     */
    scheduleFlush() {
        if (this.rafId) {
            return;
        }

        this.rafId = requestAnimationFrame(() => {
            this.flush();
            this.rafId = null;
        });
    }

    /**
     * Flushes all pending updates
     */
    flush() {
        const updates = this.pendingUpdates.splice(0);

        for (const { element, updateFn } of updates) {
            if (element && document.contains(element)) {
                try {
                    updateFn(element);
                } catch (error) {
                    console.error('DOMRenderer update error:', error);
                }
            }
        }
    }

    /**
     * Queues a text content update
     * @param {HTMLElement} element - The element to update
     * @param {string} text - The new text content
     */
    setText(element, text) {
        this.queueUpdate(element, (el) => {
            el.textContent = text;
        });
    }

    /**
     * Queues an innerHTML update
     * @param {HTMLElement} element - The element to update
     * @param {string} html - The new HTML content
     */
    setHtml(element, html) {
        this.queueUpdate(element, (el) => {
            el.innerHTML = html;
        });
    }

    /**
     * Queues a class toggle operation
     * @param {HTMLElement} element - The element to update
     * @param {string} className - The class name to toggle
     * @param {boolean} force - Force add or remove
     */
    toggleClass(element, className, force) {
        this.queueUpdate(element, (el) => {
            el.classList.toggle(className, force);
        });
    }

    /**
     * Queues adding a class
     * @param {HTMLElement} element - The element to update
     * @param {string} className - The class name to add
     */
    addClass(element, className) {
        this.queueUpdate(element, (el) => {
            el.classList.add(className);
        });
    }

    /**
     * Queues removing a class
     * @param {HTMLElement} element - The element to update
     * @param {string} className - The class name to remove
     */
    removeClass(element, className) {
        this.queueUpdate(element, (el) => {
            el.classList.remove(className);
        });
    }

    /**
     * Queues a style property update
     * @param {HTMLElement} element - The element to update
     * @param {string} property - The CSS property name
     * @param {string} value - The CSS property value
     */
    setStyle(element, property, value) {
        this.queueUpdate(element, (el) => {
            el.style[property] = value;
        });
    }

    /**
     * Queues an attribute update
     * @param {HTMLElement} element - The element to update
     * @param {string} attribute - The attribute name
     * @param {string} value - The attribute value
     */
    setAttribute(element, attribute, value) {
        this.queueUpdate(element, (el) => {
            el.setAttribute(attribute, value);
        });
    }

    /**
     * Queues a scroll to bottom operation
     * @param {HTMLElement} element - The scrollable element
     */
    scrollToBottom(element) {
        this.queueUpdate(element, (el) => {
            el.scrollTop = el.scrollHeight;
        });
    }

    /**
     * Queues appending a child element
     * @param {HTMLElement} parent - The parent element
     * @param {HTMLElement} child - The child element to append
     */
    appendChild(parent, child) {
        this.queueUpdate(parent, (el) => {
            el.appendChild(child);
        });
    }

    /**
     * Immediately executes all pending updates
     */
    flushSync() {
        if (this.rafId) {
            cancelAnimationFrame(this.rafId);
            this.rafId = null;
        }
        this.flush();
    }

    /**
     * Destroys the renderer and cancels pending updates
     */
    destroy() {
        if (this.rafId) {
            cancelAnimationFrame(this.rafId);
            this.rafId = null;
        }
        this.pendingUpdates = [];
    }

    /**
     * Gets the number of pending updates
     * @returns {number}
     */
    getPendingCount() {
        return this.pendingUpdates.length;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DOMRenderer;
}
