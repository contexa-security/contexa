package io.contexa.contexacore.saas.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

@Entity
@Table(name = "prompt_quality_certificate_ledger", indexes = {
        @Index(name = "idx_pqc_ledger_certificate", columnList = "certificate_id", unique = true),
        @Index(name = "idx_pqc_ledger_scope_latest", columnList = "scope_hash, recorded_at"),
        @Index(name = "idx_pqc_ledger_tenant_scope_latest", columnList = "tenant_id, scope_hash, recorded_at"),
        @Index(name = "idx_pqc_ledger_resource_latest", columnList = "resource_key, recorded_at"),
        @Index(name = "idx_pqc_ledger_resource_id_latest", columnList = "resource_id, recorded_at"),
        @Index(name = "idx_pqc_ledger_zero_trust", columnList = "zero_trust_state, recorded_at"),
        @Index(name = "idx_pqc_ledger_sealed_source", columnList = "evidence_source_type, sealed_evidence_package_id, recorded_at")
})
public class PromptQualityCertificateLedgerRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "certificate_id", nullable = false, length = 128)
    private String certificateId;

    @Column(name = "state", nullable = false, length = 64)
    private String state;

    @Column(name = "state_label", nullable = false, length = 128)
    private String stateLabel;

    @Column(name = "usable_for_llm_zero_trust", nullable = false)
    private boolean usableForLlmZeroTrust;

    @Column(name = "zero_trust_state", nullable = false, length = 64)
    private String zeroTrustState;

    @Column(name = "zero_trust_state_label", nullable = false, length = 128)
    private String zeroTrustStateLabel;

    @Column(name = "resource_operational_state", nullable = false, length = 64)
    private String resourceOperationalState = "PENDING_VERIFICATION";

    @Column(name = "resource_operational_state_label", nullable = false, length = 128)
    private String resourceOperationalStateLabel = "검증 대기";

    @Column(name = "issued_at", length = 64)
    private String issuedAt;

    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId = "default";

    @Column(name = "scope_hash", nullable = false, length = 128)
    private String scopeHash;

    @Column(name = "prompt_contract_version", nullable = false, length = 128)
    private String promptContractVersion = "official-prompt-contract-v1";

    @Column(name = "model_profile", nullable = false, length = 128)
    private String modelProfile = "default-model-profile";

    @Column(name = "verifier_version", nullable = false, length = 128)
    private String verifierVersion = "official-verifier-v1";

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "revoked_by", length = 255)
    private String revokedBy;

    @Column(name = "revocation_reason", length = 1000)
    private String revocationReason;

    @Column(name = "sealed_evidence_package_id", length = 160)
    private String sealedEvidencePackageId;

    @Column(name = "evidence_source_type", nullable = false, length = 64)
    private String evidenceSourceType = "UNKNOWN";

    @Column(name = "runtime_prompt_hash", length = 128)
    private String runtimePromptHash;

    @Column(name = "runtime_system_prompt_hash", length = 128)
    private String runtimeSystemPromptHash;

    @Column(name = "runtime_user_prompt_hash", length = 128)
    private String runtimeUserPromptHash;

    @Column(name = "runtime_decision_hash", length = 128)
    private String runtimeDecisionHash;

    @Column(name = "prompt_hash", length = 128)
    private String promptHash;

    @Column(name = "system_prompt_hash", length = 128)
    private String systemPromptHash;

    @Column(name = "user_prompt_hash", length = 128)
    private String userPromptHash;

    @Column(name = "context_hash", length = 128)
    private String contextHash;

    @Column(name = "evidence_request_ids_json", columnDefinition = "TEXT")
    private String evidenceRequestIdsJson;

    @Column(name = "run_ids_json", columnDefinition = "TEXT")
    private String runIdsJson;

    @Column(name = "resource_key", nullable = false, length = 600)
    private String resourceKey;

    @Column(name = "resource_url", nullable = false, length = 1000)
    private String resourceUrl;

    @Column(name = "resource_id", nullable = false, length = 255)
    private String resourceId;

    @Column(name = "http_method", nullable = false, length = 32)
    private String httpMethod;

    @Column(name = "protectable_method", length = 1000)
    private String protectableMethod;

    @Column(name = "criticality", length = 64)
    private String criticality;

    @Column(name = "verification_required", nullable = false)
    private boolean verificationRequired;

    @Column(name = "total_metric_count", nullable = false)
    private int totalMetricCount;

    @Column(name = "verified_metric_count", nullable = false)
    private int verifiedMetricCount;

    @Column(name = "failed_metric_count", nullable = false)
    private int failedMetricCount;

    @Column(name = "missing_metric_count", nullable = false)
    private int missingMetricCount;

    @Column(name = "summary", length = 3000)
    private String summary;

    @Column(name = "blocking_findings_json", columnDefinition = "TEXT")
    private String blockingFindingsJson;

    @Column(name = "six_w_json", columnDefinition = "TEXT")
    private String sixWJson;

    @Column(name = "issue_case_json", columnDefinition = "TEXT")
    private String issueCaseJson;

    @Column(name = "evidence_lineage_json", columnDefinition = "TEXT")
    private String evidenceLineageJson;

    @Column(name = "remediation_loop_json", columnDefinition = "TEXT")
    private String remediationLoopJson;

    @Column(name = "metrics_json", columnDefinition = "TEXT")
    private String metricsJson;

    @Column(name = "recommended_actions_json", columnDefinition = "TEXT")
    private String recommendedActionsJson;

    @Column(name = "recorded_at", nullable = false)
    private LocalDateTime recordedAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.certificateId = certificateId;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getStateLabel() {
        return stateLabel;
    }

    public void setStateLabel(String stateLabel) {
        this.stateLabel = stateLabel;
    }

    public boolean isUsableForLlmZeroTrust() {
        return usableForLlmZeroTrust;
    }

    public void setUsableForLlmZeroTrust(boolean usableForLlmZeroTrust) {
        this.usableForLlmZeroTrust = usableForLlmZeroTrust;
    }

    public String getZeroTrustState() {
        return zeroTrustState;
    }

    public void setZeroTrustState(String zeroTrustState) {
        this.zeroTrustState = zeroTrustState;
    }

    public String getZeroTrustStateLabel() {
        return zeroTrustStateLabel;
    }

    public void setZeroTrustStateLabel(String zeroTrustStateLabel) {
        this.zeroTrustStateLabel = zeroTrustStateLabel;
    }

    public String getResourceOperationalState() {
        return resourceOperationalState;
    }

    public void setResourceOperationalState(String resourceOperationalState) {
        this.resourceOperationalState = resourceOperationalState;
    }

    public String getResourceOperationalStateLabel() {
        return resourceOperationalStateLabel;
    }

    public void setResourceOperationalStateLabel(String resourceOperationalStateLabel) {
        this.resourceOperationalStateLabel = resourceOperationalStateLabel;
    }

    public String getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(String issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getScopeHash() {
        return scopeHash;
    }

    public void setScopeHash(String scopeHash) {
        this.scopeHash = scopeHash;
    }

    public String getPromptContractVersion() {
        return promptContractVersion;
    }

    public void setPromptContractVersion(String promptContractVersion) {
        this.promptContractVersion = promptContractVersion;
    }

    public String getModelProfile() {
        return modelProfile;
    }

    public void setModelProfile(String modelProfile) {
        this.modelProfile = modelProfile;
    }

    public String getVerifierVersion() {
        return verifierVersion;
    }

    public void setVerifierVersion(String verifierVersion) {
        this.verifierVersion = verifierVersion;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(String revokedBy) {
        this.revokedBy = revokedBy;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public String getSealedEvidencePackageId() {
        return sealedEvidencePackageId;
    }

    public void setSealedEvidencePackageId(String sealedEvidencePackageId) {
        this.sealedEvidencePackageId = sealedEvidencePackageId;
    }

    public String getEvidenceSourceType() {
        return evidenceSourceType;
    }

    public void setEvidenceSourceType(String evidenceSourceType) {
        this.evidenceSourceType = evidenceSourceType;
    }

    public String getRuntimePromptHash() {
        return runtimePromptHash;
    }

    public void setRuntimePromptHash(String runtimePromptHash) {
        this.runtimePromptHash = runtimePromptHash;
    }

    public String getRuntimeSystemPromptHash() {
        return runtimeSystemPromptHash;
    }

    public void setRuntimeSystemPromptHash(String runtimeSystemPromptHash) {
        this.runtimeSystemPromptHash = runtimeSystemPromptHash;
    }

    public String getRuntimeUserPromptHash() {
        return runtimeUserPromptHash;
    }

    public void setRuntimeUserPromptHash(String runtimeUserPromptHash) {
        this.runtimeUserPromptHash = runtimeUserPromptHash;
    }

    public String getRuntimeDecisionHash() {
        return runtimeDecisionHash;
    }

    public void setRuntimeDecisionHash(String runtimeDecisionHash) {
        this.runtimeDecisionHash = runtimeDecisionHash;
    }

    public String getPromptHash() {
        return promptHash;
    }

    public void setPromptHash(String promptHash) {
        this.promptHash = promptHash;
    }

    public String getSystemPromptHash() {
        return systemPromptHash;
    }

    public void setSystemPromptHash(String systemPromptHash) {
        this.systemPromptHash = systemPromptHash;
    }

    public String getUserPromptHash() {
        return userPromptHash;
    }

    public void setUserPromptHash(String userPromptHash) {
        this.userPromptHash = userPromptHash;
    }

    public String getContextHash() {
        return contextHash;
    }

    public void setContextHash(String contextHash) {
        this.contextHash = contextHash;
    }

    public String getEvidenceRequestIdsJson() {
        return evidenceRequestIdsJson;
    }

    public void setEvidenceRequestIdsJson(String evidenceRequestIdsJson) {
        this.evidenceRequestIdsJson = evidenceRequestIdsJson;
    }

    public String getRunIdsJson() {
        return runIdsJson;
    }

    public void setRunIdsJson(String runIdsJson) {
        this.runIdsJson = runIdsJson;
    }

    public String getResourceKey() {
        return resourceKey;
    }

    public void setResourceKey(String resourceKey) {
        this.resourceKey = resourceKey;
    }

    public String getResourceUrl() {
        return resourceUrl;
    }

    public void setResourceUrl(String resourceUrl) {
        this.resourceUrl = resourceUrl;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getProtectableMethod() {
        return protectableMethod;
    }

    public void setProtectableMethod(String protectableMethod) {
        this.protectableMethod = protectableMethod;
    }

    public String getCriticality() {
        return criticality;
    }

    public void setCriticality(String criticality) {
        this.criticality = criticality;
    }

    public boolean isVerificationRequired() {
        return verificationRequired;
    }

    public void setVerificationRequired(boolean verificationRequired) {
        this.verificationRequired = verificationRequired;
    }

    public int getTotalMetricCount() {
        return totalMetricCount;
    }

    public void setTotalMetricCount(int totalMetricCount) {
        this.totalMetricCount = totalMetricCount;
    }

    public int getVerifiedMetricCount() {
        return verifiedMetricCount;
    }

    public void setVerifiedMetricCount(int verifiedMetricCount) {
        this.verifiedMetricCount = verifiedMetricCount;
    }

    public int getFailedMetricCount() {
        return failedMetricCount;
    }

    public void setFailedMetricCount(int failedMetricCount) {
        this.failedMetricCount = failedMetricCount;
    }

    public int getMissingMetricCount() {
        return missingMetricCount;
    }

    public void setMissingMetricCount(int missingMetricCount) {
        this.missingMetricCount = missingMetricCount;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getBlockingFindingsJson() {
        return blockingFindingsJson;
    }

    public void setBlockingFindingsJson(String blockingFindingsJson) {
        this.blockingFindingsJson = blockingFindingsJson;
    }

    public String getSixWJson() {
        return sixWJson;
    }

    public void setSixWJson(String sixWJson) {
        this.sixWJson = sixWJson;
    }

    public String getIssueCaseJson() {
        return issueCaseJson;
    }

    public void setIssueCaseJson(String issueCaseJson) {
        this.issueCaseJson = issueCaseJson;
    }

    public String getEvidenceLineageJson() {
        return evidenceLineageJson;
    }

    public void setEvidenceLineageJson(String evidenceLineageJson) {
        this.evidenceLineageJson = evidenceLineageJson;
    }

    public String getRemediationLoopJson() {
        return remediationLoopJson;
    }

    public void setRemediationLoopJson(String remediationLoopJson) {
        this.remediationLoopJson = remediationLoopJson;
    }

    public String getMetricsJson() {
        return metricsJson;
    }

    public void setMetricsJson(String metricsJson) {
        this.metricsJson = metricsJson;
    }

    public String getRecommendedActionsJson() {
        return recommendedActionsJson;
    }

    public void setRecommendedActionsJson(String recommendedActionsJson) {
        this.recommendedActionsJson = recommendedActionsJson;
    }

    public LocalDateTime getRecordedAt() {
        return recordedAt;
    }

    public void setRecordedAt(LocalDateTime recordedAt) {
        this.recordedAt = recordedAt;
    }
}
