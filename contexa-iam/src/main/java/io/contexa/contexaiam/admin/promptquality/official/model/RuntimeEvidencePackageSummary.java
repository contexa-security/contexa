package io.contexa.contexaiam.admin.promptquality.official.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateDescriptor;

import java.time.Instant;

public record RuntimeEvidencePackageSummary(
        String packageId,
        String correlationId,
        String tenantId,
        String userId,
        Instant capturedAt,
        String requestPath,
        String resourceId,
        String protectableMethod,
        String httpMethod,
        String decisionAction,
        Double decisionConfidence,
        boolean sealed,
        boolean integrityValid,
        String promptHash,
        int promptTextLength,
        String stateLabel,
        String nextAction,
        String state,
        PromptQualityStateDescriptor stateDescriptor,
        String officialAggregateRunId,
        String officialDecision,
        Boolean officialBlocked,
        Integer officialPassedMetricCount,
        Integer officialFailedMetricCount,
        Integer officialExpectedMetricCount) {


    public RuntimeEvidencePackageSummary(
            String packageId,
            String correlationId,
            String tenantId,
            String userId,
            Instant capturedAt,
            String requestPath,
            String resourceId,
            String httpMethod,
            String decisionAction,
            Double decisionConfidence,
            boolean sealed,
            boolean integrityValid,
            String promptHash,
            int promptTextLength,
            String stateLabel,
            String nextAction,
            String state,
            PromptQualityStateDescriptor stateDescriptor) {
        this(
                packageId,
                correlationId,
                tenantId,
                userId,
                capturedAt,
                requestPath,
                resourceId,
                null,
                httpMethod,
                decisionAction,
                decisionConfidence,
                sealed,
                integrityValid,
                promptHash,
                promptTextLength,
                stateLabel,
                nextAction,
                state,
                stateDescriptor,
                null,
                null,
                null,
                null,
                null,
                null);
    }
    public RuntimeEvidencePackageSummary(
            String packageId,
            String correlationId,
            String tenantId,
            String userId,
            Instant capturedAt,
            String requestPath,
            String resourceId,
            String protectableMethod,
            String httpMethod,
            String decisionAction,
            Double decisionConfidence,
            boolean sealed,
            boolean integrityValid,
            String promptHash,
            int promptTextLength,
            String stateLabel,
            String nextAction) {
        this(
                packageId,
                correlationId,
                tenantId,
                userId,
                capturedAt,
                requestPath,
                resourceId,
                protectableMethod,
                httpMethod,
                decisionAction,
                decisionConfidence,
                sealed,
                integrityValid,
                promptHash,
                promptTextLength,
                stateLabel,
                nextAction,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
    }


    public RuntimeEvidencePackageSummary(
            String packageId,
            String correlationId,
            String tenantId,
            String userId,
            Instant capturedAt,
            String requestPath,
            String resourceId,
            String httpMethod,
            String decisionAction,
            Double decisionConfidence,
            boolean sealed,
            boolean integrityValid,
            String promptHash,
            int promptTextLength,
            String stateLabel,
            String nextAction) {
        this(
                packageId,
                correlationId,
                tenantId,
                userId,
                capturedAt,
                requestPath,
                resourceId,
                null,
                httpMethod,
                decisionAction,
                decisionConfidence,
                sealed,
                integrityValid,
                promptHash,
                promptTextLength,
                stateLabel,
                nextAction);
    }
    @JsonProperty("resourceUrl")
    public String resourceUrl() {
        return requestPath;
    }
}
