package io.contexa.contexacore.std.llm.bulkhead;

import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;

public class OllamaEmbeddingBulkheadModel implements EmbeddingModel {

    private static final String BULKHEAD_KEY = "ollama-embedding";

    private final EmbeddingModel delegate;
    private final String modelName;
    private final OllamaBulkheadSettings settings;

    public OllamaEmbeddingBulkheadModel(EmbeddingModel delegate, String modelName, OllamaBulkheadSettings settings) {
        this.delegate = delegate;
        this.modelName = modelName;
        this.settings = settings;
    }

    @Override
    public EmbeddingResponse call(EmbeddingRequest request) {
        return OllamaBulkheadSupport.execute(BULKHEAD_KEY, "embedding", modelName, settings, () -> delegate.call(request));
    }

    @Override
    public float[] embed(Document document) {
        return OllamaBulkheadSupport.execute(BULKHEAD_KEY, "embedding", modelName, settings, () -> delegate.embed(document));
    }

    @Override
    public int dimensions() {
        return delegate.dimensions();
    }
}