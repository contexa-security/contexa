/**
 * Contexa Streaming Library
 *
 * A reusable streaming library for LLM responses with customizable UI adapters.
 *
 * @example Basic usage
 * const client = new ContexaStreaming.StreamingClient();
 * const adapter = new ContexaStreaming.ModalUIAdapter();
 *
 * adapter.onStreamStart(query);
 * await client.stream('/api/llm/stream', { query }, {
 *     onChunk: (chunk) => adapter.onChunk(chunk),
 *     onFinalResponse: (response) => adapter.onFinalResponse(response),
 *     onComplete: () => adapter.onComplete()
 * });
 *
 * @example Using StreamingClientBuilder
 * const client = new ContexaStreaming.StreamingClientBuilder()
 *     .withModalUI()
 *     .withRetry({ maxRetries: 5 })
 *     .build();
 *
 * await client.streamWithAdapter('/api/llm/stream', { query: 'Hello' });
 */

// Export for browser environments
if (typeof window !== 'undefined') {
    window.ContexaStreaming = {
        StreamingClient: typeof StreamingClient !== 'undefined' ? StreamingClient : null,
        UIAdapter: typeof UIAdapter !== 'undefined' ? UIAdapter : null,
        ConsoleAdapter: typeof ConsoleAdapter !== 'undefined' ? ConsoleAdapter : null,
        SimpleProgressAdapter: typeof SimpleProgressAdapter !== 'undefined' ? SimpleProgressAdapter : null,
        ModalUIAdapter: typeof ModalUIAdapter !== 'undefined' ? ModalUIAdapter : null,
        StreamingClientBuilder: typeof StreamingClientBuilder !== 'undefined' ? StreamingClientBuilder : null
    };
}

// Export for CommonJS environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        StreamingClient: typeof StreamingClient !== 'undefined' ? StreamingClient : require('./StreamingClient'),
        UIAdapter: typeof UIAdapter !== 'undefined' ? UIAdapter : require('./UIAdapter'),
        ConsoleAdapter: typeof ConsoleAdapter !== 'undefined' ? ConsoleAdapter : require('./adapters/ConsoleAdapter'),
        SimpleProgressAdapter: typeof SimpleProgressAdapter !== 'undefined' ? SimpleProgressAdapter : require('./adapters/SimpleProgressAdapter'),
        ModalUIAdapter: typeof ModalUIAdapter !== 'undefined' ? ModalUIAdapter : require('./adapters/ModalUIAdapter'),
        StreamingClientBuilder: typeof StreamingClientBuilder !== 'undefined' ? StreamingClientBuilder : require('./StreamingClientBuilder')
    };
}
