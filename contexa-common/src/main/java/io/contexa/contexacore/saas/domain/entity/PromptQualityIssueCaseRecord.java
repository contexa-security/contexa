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
@Table(name = "prompt_quality_issue_case", indexes = {
        @Index(name = "idx_pqc_issue_tenant_state", columnList = "tenant_id, state, updated_at"),
        @Index(name = "idx_pqc_issue_scope", columnList = "scope_hash, updated_at"),
        @Index(name = "idx_pqc_issue_resource", columnList = "tenant_id, resource_id, http_method, updated_at")
})
public class PromptQualityIssueCaseRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "case_id", nullable = false, length = 128, unique = true)
    private String caseId;

    @Column(name = "certificate_id", length = 128)
    private String certificateId;

    @Column(name = "source_type", nullable = false, length = 64)
    private String sourceType;

    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId;

    @Column(name = "scope_hash", length = 128)
    private String scopeHash;

    @Column(name = "resource_url", length = 1000)
    private String resourceUrl;

    @Column(name = "http_method", length = 32)
    private String httpMethod;

    @Column(name = "resource_id", length = 255)
    private String resourceId;

    @Column(name = "state", nullable = false, length = 64)
    private String state;

    @Column(name = "symptom", length = 3000)
    private String symptom;

    @Column(name = "expected_outcome", length = 3000)
    private String expectedOutcome;

    @Column(name = "actual_outcome", length = 3000)
    private String actualOutcome;

    @Column(name = "evidence_package_id", length = 255)
    private String evidencePackageId;

    @Column(name = "recurrence_count", nullable = false)
    private int recurrenceCount;

    @Column(name = "findings_json", columnDefinition = "TEXT")
    private String findingsJson;

    @Column(name = "recommended_actions_json", columnDefinition = "TEXT")
    private String recommendedActionsJson;

    @Column(name = "opened_at", nullable = false)
    private LocalDateTime openedAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCaseId() {
        return caseId;
    }

    public void setCaseId(String caseId) {
        this.caseId = caseId;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.certificateId = certificateId;
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType;
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

    public String getResourceUrl() {
        return resourceUrl;
    }

    public void setResourceUrl(String resourceUrl) {
        this.resourceUrl = resourceUrl;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getSymptom() {
        return symptom;
    }

    public void setSymptom(String symptom) {
        this.symptom = symptom;
    }

    public String getExpectedOutcome() {
        return expectedOutcome;
    }

    public void setExpectedOutcome(String expectedOutcome) {
        this.expectedOutcome = expectedOutcome;
    }

    public String getActualOutcome() {
        return actualOutcome;
    }

    public void setActualOutcome(String actualOutcome) {
        this.actualOutcome = actualOutcome;
    }

    public String getEvidencePackageId() {
        return evidencePackageId;
    }

    public void setEvidencePackageId(String evidencePackageId) {
        this.evidencePackageId = evidencePackageId;
    }

    public int getRecurrenceCount() {
        return recurrenceCount;
    }

    public void setRecurrenceCount(int recurrenceCount) {
        this.recurrenceCount = recurrenceCount;
    }

    public String getFindingsJson() {
        return findingsJson;
    }

    public void setFindingsJson(String findingsJson) {
        this.findingsJson = findingsJson;
    }

    public String getRecommendedActionsJson() {
        return recommendedActionsJson;
    }

    public void setRecommendedActionsJson(String recommendedActionsJson) {
        this.recommendedActionsJson = recommendedActionsJson;
    }

    public LocalDateTime getOpenedAt() {
        return openedAt;
    }

    public void setOpenedAt(LocalDateTime openedAt) {
        this.openedAt = openedAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
