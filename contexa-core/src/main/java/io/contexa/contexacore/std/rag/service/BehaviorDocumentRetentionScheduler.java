/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.rag.service;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.properties.ContexaRagProperties;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.LocalDate;
import java.util.Objects;

/**
 * Enforces {@code contexa.rag.etl.behavior.retention-days}: behaviour documents (security decision memory and
 * behaviour analysis) older than the retention period are deleted from the vector store. A value of zero or less
 * keeps them indefinitely.
 * <p>
 * Behaviour documents carry their event time as an ISO local date-time string in the {@code timestamp} metadata,
 * so documents dated before the cut-off day compare lower than the cut-off date string.
 */
@Slf4j
public class BehaviorDocumentRetentionScheduler {

    public static final String LOCK_NAME = "behaviorDocumentRetentionCleanup";

    private final VectorStore vectorStore;
    private final ContexaRagProperties ragProperties;
    private final Clock clock;

    public BehaviorDocumentRetentionScheduler(VectorStore vectorStore, ContexaRagProperties ragProperties) {
        this(vectorStore, ragProperties, Clock.systemDefaultZone());
    }

    public BehaviorDocumentRetentionScheduler(VectorStore vectorStore, ContexaRagProperties ragProperties, Clock clock) {
        this.vectorStore = Objects.requireNonNull(vectorStore, "vectorStore must not be null");
        this.ragProperties = Objects.requireNonNull(ragProperties, "ragProperties must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Scheduled(cron = "${contexa.rag.etl.behavior.retention-cleanup-cron:0 45 3 * * *}")
    @SchedulerLock(name = LOCK_NAME, lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    public void deleteExpiredBehaviorDocuments() {
        Filter.Expression expired = expiredBehaviorDocuments();
        if (expired == null) {
            return;
        }
        try {
            vectorStore.delete(VectorStoreFilterValues.encode(expired, vectorStore));
        } catch (RuntimeException e) {
            log.error("[BehaviorDocumentRetention] Expired behaviour documents could not be deleted: retentionDays={}",
                    ragProperties.getEtl().getBehavior().getRetentionDays(), e);
        }
    }

    /** Filter of the behaviour documents past retention, or null when retention is disabled. */
    Filter.Expression expiredBehaviorDocuments() {
        int retentionDays = ragProperties.getEtl().getBehavior().getRetentionDays();
        if (retentionDays <= 0) {
            return null;
        }
        String cutoffDay = LocalDate.now(clock).minusDays(retentionDays).toString();
        FilterExpressionBuilder filter = new FilterExpressionBuilder();
        return filter.and(
                filter.in("documentType",
                        VectorDocumentType.BEHAVIOR.getValue(), VectorDocumentType.BEHAVIOR_ANALYSIS.getValue()),
                filter.lt("timestamp", cutoffDay)).build();
    }
}
