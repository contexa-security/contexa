package io.contexa.contexacore.std.llm.bulkhead;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;

@ExtendWith(MockitoExtension.class)
class OllamaEmbeddingBulkheadModelTest {

    @Mock
    private EmbeddingModel delegate;

    @BeforeEach
    void resetBulkheadRegistry() {
        OllamaBulkheadRegistry.resetForTests();
    }

    @Test
    @DisplayName("embedding bulkhead permit이 없으면 acquire timeout으로 빠르게 실패해야 한다")
    void shouldFailFastWhenEmbeddingPermitUnavailable() throws Exception {
        CountDownLatch firstCallEntered = new CountDownLatch(1);
        CountDownLatch releaseFirstCall = new CountDownLatch(1);
        SecurityEvent event = SecurityEvent.builder().eventId("evt-embedding").build();

        doAnswer(invocation -> {
            firstCallEntered.countDown();
            releaseFirstCall.await(2, TimeUnit.SECONDS);
            return new float[]{1.0f};
        }).when(delegate).embed(org.mockito.ArgumentMatchers.any(Document.class));

        OllamaEmbeddingBulkheadModel wrapper = new OllamaEmbeddingBulkheadModel(
                delegate,
                "nomic-embed-text-timeout",
                new OllamaBulkheadSettings(1, 50, 0, 0, 2, 2000)
        );

        var executor = Executors.newFixedThreadPool(2);
        try {
            Future<float[]> first = executor.submit(() -> {
                try (SecurityEventTelemetryContext.Scope ignored = SecurityEventTelemetryContext.open(event)) {
                    return wrapper.embed(new Document("first"));
                }
            });
            firstCallEntered.await(1, TimeUnit.SECONDS);

            try (SecurityEventTelemetryContext.Scope ignored = SecurityEventTelemetryContext.open(event)) {
                assertThatThrownBy(() -> wrapper.embed(new Document("second")))
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("bulkhead acquire timed out");
            }

            releaseFirstCall.countDown();
            assertThat(first.get(1, TimeUnit.SECONDS)).containsExactly(1.0f);
        } finally {
            executor.shutdownNow();
        }

        assertThat(event.getMetadata()).containsKey("embeddingAcquireMs");
    }

    @Test
    @DisplayName("embedding busy 실패가 임계치를 넘으면 circuit 이 열리고 다음 호출을 즉시 차단해야 한다")
    void shouldOpenEmbeddingCircuitAfterRepeatedBusyFailures() {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-embedding-circuit").build();

        doAnswer(invocation -> {
            throw new RuntimeException("503 service unavailable");
        }).when(delegate).embed(org.mockito.ArgumentMatchers.any(Document.class));

        OllamaEmbeddingBulkheadModel wrapper = new OllamaEmbeddingBulkheadModel(
                delegate,
                "nomic-embed-text-circuit",
                new OllamaBulkheadSettings(1, 1000, 0, 0, 1, 2000)
        );

        try (SecurityEventTelemetryContext.Scope ignored = SecurityEventTelemetryContext.open(event)) {
            assertThatThrownBy(() -> wrapper.embed(new Document("first")))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("503");
            assertThatThrownBy(() -> wrapper.embed(new Document("second")))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("circuit open");
        }

        assertThat(event.getMetadata()).containsEntry("embeddingCircuitOpen", true);
    }
}
