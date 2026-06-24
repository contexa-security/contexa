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
package io.contexa.contexacore.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "hcad_detection_evaluation", indexes = {
        @Index(name = "idx_hcad_eval_mode_created", columnList = "mode,created_at"),
        @Index(name = "idx_hcad_eval_outcome_created", columnList = "outcome_class,created_at"),
        @Index(name = "idx_hcad_eval_resource", columnList = "request_path,http_method"),
        @Index(name = "idx_hcad_eval_request_id", columnList = "request_id"),
        @Index(name = "idx_hcad_eval_event_id", columnList = "event_id"),
        @Index(name = "idx_hcad_eval_actor_created", columnList = "actor_session_key,created_at"),
        @Index(name = "idx_hcad_eval_window", columnList = "window_id")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class HcadDetectionEvaluation {

    @Id
    @Column(name = "evaluation_id", nullable = false, length = 64)
    private String evaluationId;

    @Column(name = "event_id", length = 128)
    private String eventId;

    @Column(name = "request_id", length = 160)
    private String requestId;

    @Column(name = "correlation_id", length = 160)
    private String correlationId;

    @Column(name = "test_run_id", length = 160)
    private String testRunId;

    @Column(name = "user_id", length = 160)
    private String userId;

    @Column(name = "context_binding_hash", length = 128)
    private String contextBindingHash;

    @Column(name = "actor_session_key", length = 128)
    private String actorSessionKey;

    @Column(name = "window_id", length = 64)
    private String windowId;

    @Column(name = "trigger_scope", length = 32)
    private String triggerScope;

    @Column(name = "request_count")
    @Builder.Default
    private Integer requestCount = 1;

    @Column(name = "http_method", length = 16)
    private String httpMethod;

    @Column(name = "request_path", length = 2048)
    private String requestPath;

    @Column(name = "normalized_path", length = 2048)
    private String normalizedPath;

    @Column(name = "resource_id", length = 512)
    private String resourceId;

    @Column(name = "client_ip", length = 64)
    private String clientIp;

    @Column(name = "mode", nullable = false, length = 32)
    private String mode;

    @Column(name = "early_analysis_score")
    private Integer earlyAnalysisScore;

    @Column(name = "band", length = 32)
    private String band;

    @Column(name = "eligible")
    private Boolean eligible;

    @Column(name = "triggered_llm", nullable = false)
    @Builder.Default
    private Boolean triggeredLlm = false;

    @Column(name = "duplicate_suppressed", nullable = false)
    @Builder.Default
    private Boolean duplicateSuppressed = false;

    @Column(name = "duplicate_suppressed_count")
    @Builder.Default
    private Integer duplicateSuppressedCount = 0;

    @Column(name = "negative_cache_hit", nullable = false)
    @Builder.Default
    private Boolean negativeCacheHit = false;

    @Column(name = "negative_cache_hit_count")
    @Builder.Default
    private Integer negativeCacheHitCount = 0;

    @Column(name = "protectable_observed", nullable = false)
    @Builder.Default
    private Boolean protectableObserved = false;

    @Column(name = "protectable_resource_id", length = 512)
    private String protectableResourceId;

    @Column(name = "protectable_resource_url", length = 2048)
    private String protectableResourceUrl;

    @Column(name = "protectable_http_method", length = 16)
    private String protectableHttpMethod;

    @Column(name = "resource_families", columnDefinition = "TEXT")
    private String resourceFamilies;

    @Column(name = "sample_paths", columnDefinition = "TEXT")
    private String samplePaths;

    @Column(name = "anchor_signals", columnDefinition = "TEXT")
    private String anchorSignals;

    @Column(name = "corroborating_signals", columnDefinition = "TEXT")
    private String corroboratingSignals;

    @Column(name = "reason_codes", columnDefinition = "TEXT")
    private String reasonCodes;

    @Column(name = "non_trigger_reason", length = 64)
    private String nonTriggerReason;

    @Column(name = "evidence_gap_codes", columnDefinition = "TEXT")
    private String evidenceGapCodes;

    @Column(name = "baseline_available")
    private Boolean baselineAvailable;

    @Column(name = "baseline_established")
    private Boolean baselineEstablished;

    @Column(name = "baseline_update_count")
    private Long baselineUpdateCount;

    @Column(name = "baseline_min_samples")
    private Integer baselineMinSamples;

    @Column(name = "baseline_compared_dimensions")
    private Integer baselineComparedDimensions;

    @Column(name = "baseline_mismatch_count")
    private Integer baselineMismatchCount;

    @Column(name = "baseline_match_ratio")
    private Double baselineMatchRatio;

    @Column(name = "baseline_mismatched_dimensions", columnDefinition = "TEXT")
    private String baselineMismatchedDimensions;

    @Column(name = "baseline_current_values_json", columnDefinition = "TEXT")
    private String baselineCurrentValuesJson;

    @Column(name = "baseline_reference_values_json", columnDefinition = "TEXT")
    private String baselineReferenceValuesJson;

    @Column(name = "trigger_decision_reason", length = 128)
    private String triggerDecisionReason;

    @Column(name = "signal_snapshot_json", columnDefinition = "TEXT")
    private String signalSnapshotJson;

    @Column(name = "signal_provenance_json", columnDefinition = "TEXT")
    private String signalProvenanceJson;

    @Column(name = "score_breakdown_json", columnDefinition = "TEXT")
    private String scoreBreakdownJson;

    @Column(name = "signal_explanations_json", columnDefinition = "TEXT")
    private String signalExplanationsJson;

    @Column(name = "context_explanation_json", columnDefinition = "TEXT")
    private String contextExplanationJson;

    @Column(name = "baseline_explanation_json", columnDefinition = "TEXT")
    private String baselineExplanationJson;

    @Column(name = "semantic_evidence_explanation_json", columnDefinition = "TEXT")
    private String semanticEvidenceExplanationJson;

    @Column(name = "freshness_explanation_json", columnDefinition = "TEXT")
    private String freshnessExplanationJson;

    @Column(name = "trigger_explanation_json", columnDefinition = "TEXT")
    private String triggerExplanationJson;

    @Column(name = "llm_action", length = 64)
    private String llmAction;

    @Column(name = "llm_proposed_action", length = 64)
    private String llmProposedAction;

    @Column(name = "llm_risk_score")
    private Double llmRiskScore;

    @Column(name = "llm_confidence")
    private Double llmConfidence;

    @Column(name = "llm_latency_ms")
    private Long llmLatencyMs;

    @Column(name = "llm_reasoning_summary", length = 1024)
    private String llmReasoningSummary;

    @Column(name = "llm_reasoning_hash", length = 64)
    private String llmReasoningHash;

    @Column(name = "llm_parser_failure", nullable = false)
    @Builder.Default
    private Boolean llmParserFailure = false;

    @Column(name = "llm_technical_fallback", nullable = false)
    @Builder.Default
    private Boolean llmTechnicalFallback = false;

    @Column(name = "llm_fallback_category", length = 128)
    private String llmFallbackCategory;

    @Column(name = "llm_fallback_reason", length = 1024)
    private String llmFallbackReason;

    @Column(name = "outcome_class", nullable = false, length = 32)
    @Builder.Default
    private String outcomeClass = "UNKNOWN";

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "triggered_at")
    private LocalDateTime triggeredAt;

    @Column(name = "decided_at")
    private LocalDateTime decidedAt;

    @PrePersist
    void prePersist() {
        if (evaluationId == null || evaluationId.isBlank()) {
            evaluationId = UUID.randomUUID().toString();
        }
        if (mode == null || mode.isBlank()) {
            mode = "SHADOW";
        }
        if (triggeredLlm == null) {
            triggeredLlm = false;
        }
        if (duplicateSuppressed == null) {
            duplicateSuppressed = false;
        }
        if (duplicateSuppressedCount == null) {
            duplicateSuppressedCount = 0;
        }
        if (negativeCacheHit == null) {
            negativeCacheHit = false;
        }
        if (negativeCacheHitCount == null) {
            negativeCacheHitCount = 0;
        }
        if (protectableObserved == null) {
            protectableObserved = false;
        }
        if (requestCount == null) {
            requestCount = 1;
        }
        if (llmParserFailure == null) {
            llmParserFailure = false;
        }
        if (llmTechnicalFallback == null) {
            llmTechnicalFallback = false;
        }
        if (outcomeClass == null || outcomeClass.isBlank()) {
            outcomeClass = "UNKNOWN";
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
