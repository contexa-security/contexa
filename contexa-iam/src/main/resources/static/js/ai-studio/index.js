/**
 * AI Studio Module Index
 *
 * Exports all AI Studio components for easy import.
 * AI Studio uses the shared ContexaLLM library when available,
 * with fallback to local StreamingHandler for backwards compatibility.
 *
 * @example Browser usage
 * const studio = new window.AIStudio.Core();
 * await studio.handleAIQuery('Hello');
 *
 * @example CommonJS usage
 * const { AIStudioCore, ModalManager } = require('./ai-studio');
 */

// Export for CommonJS environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AIStudioConfig: typeof AIStudioConfig !== 'undefined' ? AIStudioConfig : null,
        StreamingHandler: typeof StreamingHandler !== 'undefined' ? StreamingHandler : null,
        ModalManager: typeof ModalManager !== 'undefined' ? ModalManager : null,
        DOMRenderer: typeof DOMRenderer !== 'undefined' ? DOMRenderer : null,
        GraphManager: typeof GraphManager !== 'undefined' ? GraphManager : null,
        ResponseParser: typeof ResponseParser !== 'undefined' ? ResponseParser : null,
        AIStudioCore: typeof AIStudioCore !== 'undefined' ? AIStudioCore : null
    };
}

// Export for browser environments
if (typeof window !== 'undefined') {
    window.AIStudio = {
        Config: typeof AIStudioConfig !== 'undefined' ? AIStudioConfig : null,
        StreamingHandler: typeof StreamingHandler !== 'undefined' ? StreamingHandler : null,
        ModalManager: typeof ModalManager !== 'undefined' ? ModalManager : null,
        DOMRenderer: typeof DOMRenderer !== 'undefined' ? DOMRenderer : null,
        GraphManager: typeof GraphManager !== 'undefined' ? GraphManager : null,
        ResponseParser: typeof ResponseParser !== 'undefined' ? ResponseParser : null,
        Core: typeof AIStudioCore !== 'undefined' ? AIStudioCore : null
    };

    // Also expose the shared LLM library reference if available
    if (typeof ContexaLLM !== 'undefined') {
        window.AIStudio.LLM = ContexaLLM;
    }
}
