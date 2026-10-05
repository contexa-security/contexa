package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.properties.ContexaRagProperties;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class BehaviorDocumentRetentionSchedulerTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-05T03:45:00Z"), ZoneOffset.UTC);

    private final VectorStore vectorStore = mock(VectorStore.class);
    private final ContexaRagProperties properties = new ContexaRagProperties();

    @Test
    void deletesBehaviourDocumentsDatedBeforeTheRetentionCutOffDay() {
        properties.getEtl().getBehavior().setRetentionDays(90);

        new BehaviorDocumentRetentionScheduler(vectorStore, properties, CLOCK).deleteExpiredBehaviorDocuments();

        FilterExpressionBuilder filter = new FilterExpressionBuilder();
        Filter.Expression expected = filter.and(
                filter.in("documentType", "behavior", "behavior_analysis"),
                filter.lt("timestamp", "2026-07-07")).build();
        verify(vectorStore).delete(expected);
    }

    @Test
    void retentionOfZeroDaysKeepsEveryDocument() {
        properties.getEtl().getBehavior().setRetentionDays(0);

        BehaviorDocumentRetentionScheduler scheduler = new BehaviorDocumentRetentionScheduler(vectorStore, properties, CLOCK);
        scheduler.deleteExpiredBehaviorDocuments();

        assertThat(scheduler.expiredBehaviorDocuments()).isNull();
        verify(vectorStore, never()).delete(any(Filter.Expression.class));
    }
}
