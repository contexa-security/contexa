package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.properties.ContexaRagProperties;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * IAM-D21: a stored document is recorded as one store operation. The extra generic event the store used to send was
 * of a type the metrics refuse, and that refusal turned every successful store into a failed one.
 */
class AbstractVectorLabServiceStoreTest {

    @Test
    void aStoredDocumentIsRecordedAsOneStoreOperationAndNoGenericEvent() {
        VectorStore vectorStore = mock(VectorStore.class);
        VectorStoreMetrics metrics = mock(VectorStoreMetrics.class);
        doThrow(new IllegalArgumentException("Unsupported event type")).when(metrics).recordEvent(anyString(), anyMap());
        TestLab lab = new TestLab(vectorStore, metrics);

        lab.storeDocument(new Document("Policy generation request: 'let auditors read reports'", Map.of()));

        verify(vectorStore).add(anyList());
        verify(metrics).recordOperation(eq("TestLab"), eq(AbstractVectorLabService.OperationType.STORE), eq(1),
                anyLong());
        verify(metrics, never()).recordEvent(anyString(), anyMap());
        verify(metrics, never()).recordError(anyString(), any(), any());
    }

    private static final class TestLab extends AbstractVectorLabService {

        private TestLab(VectorStore vectorStore, VectorStoreMetrics metrics) {
            super(vectorStore, metrics, new ContexaRagProperties());
        }

        @Override
        protected String getLabName() {
            return "TestLab";
        }

        @Override
        protected String getDocumentType() {
            return "test";
        }

        @Override
        protected Document enrichLabSpecificMetadata(Document document) {
            return document;
        }

        @Override
        protected void validateLabSpecificDocument(Document document) {
        }
    }
}
