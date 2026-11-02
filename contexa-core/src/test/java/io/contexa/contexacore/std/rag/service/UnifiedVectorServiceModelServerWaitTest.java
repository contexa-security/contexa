package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.llm.gate.CallKind;
import io.contexa.contexacore.std.llm.gate.ModelServer;
import io.contexa.contexacore.std.llm.gate.ModelServerGate;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * O-1 (3) in the vector service: the store and search time limits count from the embedding call's start. While the
 * embedding waits for the model server's gate (a decision is running on the same local server), the limit does not
 * run, so the record is stored instead of timing out and waiting for a retry.
 */
class UnifiedVectorServiceModelServerWaitTest {

    @Test
    void aStoreThatWaitsForTheModelServerIsNotCutByItsTimeLimit() throws Exception {
        ModelServerGate gate = new ModelServerGate(ModelServer.of("ollama", "http://localhost:11434"), 1, true,
                Duration.ZERO);
        AtomicInteger stored = new AtomicInteger();
        VectorStore store = new EmbeddingVectorStore(gate, stored);
        PgVectorStoreProperties properties = new PgVectorStoreProperties();
        properties.setStoreTimeoutMs(300L);
        UnifiedVectorService service = new UnifiedVectorService(properties, mock(VectorStoreCacheLayer.class), store);

        ModelServerGate.Permit decision = gate.enter(CallKind.CHAT, "qwen3:8b", 1_000L);
        Thread release = new Thread(() -> {
            sleep(600);
            decision.close();
        });
        release.start();

        service.storeDocument(new Document("record", Map.of("documentType", "behavior", "eventId", "event-1",
                "userId", "u-1")));

        assertThat(stored).hasValue(1);
        service.destroy();
    }

    /** A store whose add embeds through the gate, as PgVectorStore does through the gated embedding model. */
    private static final class EmbeddingVectorStore implements VectorStore {

        private final ModelServerGate gate;
        private final AtomicInteger stored;

        EmbeddingVectorStore(ModelServerGate gate, AtomicInteger stored) {
            this.gate = gate;
            this.stored = stored;
        }

        @Override
        public void add(List<Document> documents) {
            try (ModelServerGate.Permit ignored = gate.enter(CallKind.EMBEDDING, "mxbai-embed-large", 5_000L)) {
                sleep(50);
                stored.addAndGet(documents.size());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void delete(List<String> idList) {
        }

        @Override
        public void delete(Filter.Expression filterExpression) {
        }

        @Override
        public List<Document> similaritySearch(SearchRequest request) {
            return List.of();
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
