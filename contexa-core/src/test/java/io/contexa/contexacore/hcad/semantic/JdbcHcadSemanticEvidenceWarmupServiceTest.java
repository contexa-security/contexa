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
package io.contexa.contexacore.hcad.semantic;

import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JdbcHcadSemanticEvidenceWarmupServiceTest {

    private final HcadProperties hcadProperties = new HcadProperties();

    @Test
    void requestWarmup_existingAiDecisionSource_materializesCacheEntry() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        JdbcHcadSemanticEvidenceWarmupService service = new JdbcHcadSemanticEvidenceWarmupService(
                () -> jdbcOperations,
                hcadProperties,
                Runnable::run);
        when(jdbcOperations.queryForList(anyString(), any(Object[].class)))
                .thenReturn(List.of(Map.of(
                        "sample_count", 3L,
                        "avg_risk", 0.87d,
                        "avg_confidence", 0.92d)));

        HcadSemanticEvidenceWarmupResult result = service.requestWarmup(request(key()), cache);

        assertThat(result.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.WARMUP_QUEUED);
        ArgumentCaptor<HcadSemanticEvidenceEntry> entryCaptor =
                ArgumentCaptor.forClass(HcadSemanticEvidenceEntry.class);
        verify(cache).put(entryCaptor.capture(), any(Duration.class));
        assertThat(entryCaptor.getValue().evidenceGapCodes())
                .contains("CACHE_MISS_SOURCE_AVAILABLE", "WARMUP_COMPLETED");
        assertThat(entryCaptor.getValue().sourceVersion()).isEqualTo("ai_security_decision_observation");
        assertThat(entryCaptor.getValue().embeddingModel()).isEqualTo(key().embeddingModel());
        assertThat(entryCaptor.getValue().dimension()).isEqualTo(key().dimension());
        assertThat(entryCaptor.getValue().summaryJson())
                .contains("\"source\":\"ai_security_decision_observation\"")
                .contains("\"sampleCount\":3");
        verify(cache, never()).putSourceAbsent(any(), any());
    }

    @Test
    void requestWarmup_missingSource_storesShortNegativeCache() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        JdbcHcadSemanticEvidenceWarmupService service = new JdbcHcadSemanticEvidenceWarmupService(
                () -> jdbcOperations,
                hcadProperties,
                Runnable::run);
        when(jdbcOperations.queryForList(anyString(), any(Object[].class)))
                .thenReturn(List.of(Map.of(
                        "sample_count", 0L,
                        "avg_risk", 0.0d,
                        "avg_confidence", 0.0d)));
        HcadSemanticEvidenceKey key = key();

        HcadSemanticEvidenceWarmupResult result = service.requestWarmup(request(key), cache);

        assertThat(result.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.WARMUP_QUEUED);
        verify(cache).putSourceAbsent(any(HcadSemanticEvidenceKey.class), any(Duration.class));
        verify(cache, never()).put(any(), any());
    }

    @Test
    void requestWarmup_withoutJdbc_doesNotTouchCache() {
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        JdbcHcadSemanticEvidenceWarmupService service = new JdbcHcadSemanticEvidenceWarmupService(
                () -> null,
                hcadProperties,
                Runnable::run);

        HcadSemanticEvidenceWarmupResult result = service.requestWarmup(request(key()), cache);

        assertThat(result.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.CACHE_MISS_SOURCE_UNKNOWN);
        verify(cache, never()).put(any(), any());
        verify(cache, never()).putSourceAbsent(any(), any());
    }

    @Test
    void requestWarmup_failedSourceLookup_storesRetryBoundFailureEntry() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        JdbcHcadSemanticEvidenceWarmupService service = new JdbcHcadSemanticEvidenceWarmupService(
                () -> jdbcOperations,
                hcadProperties,
                Runnable::run);
        when(jdbcOperations.queryForList(anyString(), any(Object[].class)))
                .thenThrow(new DataAccessResourceFailureException("db down"));
        hcadProperties.getSemanticEvidence().setWarmupRetryTtlSeconds(17);

        HcadSemanticEvidenceWarmupResult result = service.requestWarmup(request(key()), cache);

        assertThat(result.status()).isEqualTo(HcadSemanticEvidenceCacheStatus.WARMUP_QUEUED);
        ArgumentCaptor<HcadSemanticEvidenceEntry> entryCaptor =
                ArgumentCaptor.forClass(HcadSemanticEvidenceEntry.class);
        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(cache).put(entryCaptor.capture(), ttlCaptor.capture());
        assertThat(entryCaptor.getValue().status()).isEqualTo(HcadSemanticEvidenceCacheStatus.WARMUP_FAILED);
        assertThat(entryCaptor.getValue().evidenceGapCodes()).contains("WARMUP_FAILED");
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofSeconds(17));
    }

    private HcadSemanticEvidenceWarmupRequest request(HcadSemanticEvidenceKey key) {
        return new HcadSemanticEvidenceWarmupRequest(null, key);
    }

    private HcadSemanticEvidenceKey key() {
        return HcadSemanticEvidenceKey.normalRequestSimilarity(
                "tenant-1",
                "admin",
                "/contexa/admin/orders",
                "baseline-v1",
                hcadProperties.getSemanticEvidence().getEmbeddingModel(),
                hcadProperties.getVector().getEmbeddingDimension(),
                hcadProperties.getSemanticEvidence().getEvidenceVersion());
    }
}
