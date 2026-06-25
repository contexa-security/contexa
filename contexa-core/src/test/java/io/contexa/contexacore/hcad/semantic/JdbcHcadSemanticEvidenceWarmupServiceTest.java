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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.Duration;
import java.time.LocalDateTime;
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

    @Test
    @DisplayName("Risk request similarity should materialize from successful CHALLENGE/BLOCK observations")
    void requestWarmup_riskRequestSimilarity_shouldPutRiskEvidence() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceKey key = riskKey();
        when(jdbcOperations.queryForList(anyString(), ArgumentMatchers.<Object>any(), ArgumentMatchers.<Object>any(), ArgumentMatchers.<Object>any()))
                .thenReturn(List.of(Map.of(
                        "sample_count", 3,
                        "avg_risk", 0.86d,
                        "avg_confidence", 0.9d,
                        "last_decision_at", LocalDateTime.now(),
                        "challenge_count", 2,
                        "block_count", 1)));
        JdbcHcadSemanticEvidenceWarmupService service = service(jdbcOperations);

        service.requestWarmup(new HcadSemanticEvidenceWarmupRequest(null, key), cache);

        ArgumentCaptor<HcadSemanticEvidenceEntry> entryCaptor = ArgumentCaptor.forClass(HcadSemanticEvidenceEntry.class);
        verify(cache).put(entryCaptor.capture(), any(Duration.class));
        HcadSemanticEvidenceEntry entry = entryCaptor.getValue();
        assertThat(entry.key().type()).isEqualTo(HcadSemanticEvidenceType.RISK_REQUEST_SIMILARITY);
        assertThat(entry.similarityToNormal()).isNull();
        assertThat(entry.similarityToRisk()).isGreaterThanOrEqualTo(0.86d);
        assertThat(entry.summaryJson()).contains("\"evidenceKind\":\"risk\"", "\"actionFamily\":\"CHALLENGE_BLOCK\"", "\"sampleCount\":3");
        verify(cache, never()).putSourceAbsent(any(), any(Duration.class));
    }

    @Test
    @DisplayName("Resource decision summary should materialize resource-level decision distribution")
    void requestWarmup_resourceDecisionSummary_shouldPutResourceEvidence() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceKey key = HcadSemanticEvidenceKey.resourceDecisionSummary(
                "tenant-a",
                "/contexa/admin/users/{id}",
                "policy-v1",
                "prompt-v1",
                "text-embedding-3-small",
                1024,
                "semantic-v1");
        when(jdbcOperations.queryForList(anyString(), ArgumentMatchers.<Object>any(), ArgumentMatchers.<Object>any()))
                .thenReturn(List.of(Map.of(
                        "sample_count", 10,
                        "avg_risk", 0.54d,
                        "avg_confidence", 0.88d,
                        "last_decision_at", LocalDateTime.now(),
                        "allow_count", 6,
                        "challenge_count", 3,
                        "block_count", 1)));
        JdbcHcadSemanticEvidenceWarmupService service = service(jdbcOperations);

        service.requestWarmup(new HcadSemanticEvidenceWarmupRequest(null, key), cache);

        ArgumentCaptor<HcadSemanticEvidenceEntry> entryCaptor = ArgumentCaptor.forClass(HcadSemanticEvidenceEntry.class);
        verify(cache).put(entryCaptor.capture(), any(Duration.class));
        HcadSemanticEvidenceEntry entry = entryCaptor.getValue();
        assertThat(entry.key().type()).isEqualTo(HcadSemanticEvidenceType.RESOURCE_LLM_DECISION_SUMMARY);
        assertThat(entry.similarityToNormal()).isNull();
        assertThat(entry.similarityToRisk()).isGreaterThanOrEqualTo(0.54d);
        assertThat(entry.summaryJson()).contains("\"evidenceKind\":\"resourceDecisionSummary\"", "\"allowCount\":6", "\"blockCount\":1");
    }

    @Test
    @DisplayName("Risk request similarity should cache source absent when no risk decision exists")
    void requestWarmup_riskRequestSimilarityWithoutRows_shouldPutSourceAbsent() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceCache cache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceKey key = riskKey();
        when(jdbcOperations.queryForList(anyString(), ArgumentMatchers.<Object>any(), ArgumentMatchers.<Object>any(), ArgumentMatchers.<Object>any()))
                .thenReturn(List.of(Map.of("sample_count", 0)));
        JdbcHcadSemanticEvidenceWarmupService service = service(jdbcOperations);

        service.requestWarmup(new HcadSemanticEvidenceWarmupRequest(null, key), cache);

        verify(cache).putSourceAbsent(any(), any(Duration.class));
        verify(cache, never()).put(any(), any(Duration.class));
    }

    private JdbcHcadSemanticEvidenceWarmupService service(JdbcOperations jdbcOperations) {
        HcadProperties properties = new HcadProperties();
        properties.getSemanticEvidence().setEmbeddingModel("text-embedding-3-small");
        properties.getVector().setEmbeddingDimension(1024);
        return new JdbcHcadSemanticEvidenceWarmupService(() -> jdbcOperations, properties, Runnable::run);
    }

    private HcadSemanticEvidenceKey riskKey() {
        return HcadSemanticEvidenceKey.riskRequestSimilarity(
                "tenant-a",
                "admin",
                "/contexa/admin/users/{id}",
                "policy-v1",
                "prompt-v1",
                "text-embedding-3-small",
                1024,
                "semantic-v1");
    }
}

