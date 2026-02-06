/**
 * AI Studio Configuration Module
 * Centralized configuration for timing, streaming, and marker constants
 */
const AIStudioConfig = {
    timing: {
        MIN_QUERY_INTERVAL: 2000,
        CYTOSCAPE_LOAD_TIMEOUT: 5000,
        CYTOSCAPE_LOAD_CHECK_INTERVAL: 100,
        TYPING_DEBOUNCE: 1000,
        MODAL_ANIMATION_DELAY: 100,
        MODAL_HIDE_DELAY: 300,
        STREAMING_STEP_DELAY_MIN: 500,
        STREAMING_STEP_DELAY_MAX: 1000
    },

    streaming: {
        MAX_RETRIES: 3,
        RETRY_DELAY: 1000,
        RETRY_MULTIPLIER: 1.5
    },

    markers: {
        FINAL_RESPONSE: '###FINAL_RESPONSE###',
        DONE: '[DONE]',
        ERROR_PREFIX: 'ERROR:',
        JSON_START: '===JSON_START===',
        JSON_END: '===JSON_END==='
    },

    api: {
        STUDIO_QUERY_STREAM: '/api/ai/studio/query/stream',
        STUDIO_QUERY: '/api/ai/studio/query',
        POLICY_GENERATE_STREAM: '/api/ai/policies/generate/stream'
    },

    validation: {
        MAX_QUERY_LENGTH: 500,
        MIN_QUERY_LENGTH: 1
    }
};

Object.freeze(AIStudioConfig);
Object.freeze(AIStudioConfig.timing);
Object.freeze(AIStudioConfig.streaming);
Object.freeze(AIStudioConfig.markers);
Object.freeze(AIStudioConfig.api);
Object.freeze(AIStudioConfig.validation);

if (typeof module !== 'undefined' && module.exports) {
    module.exports = AIStudioConfig;
}
