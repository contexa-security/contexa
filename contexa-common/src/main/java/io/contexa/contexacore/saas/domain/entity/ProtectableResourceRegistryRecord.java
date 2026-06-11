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
@Table(name = "protectable_resource_registry", indexes = {
        @Index(name = "idx_prr_scope", columnList = "tenant_id, resource_id, http_method", unique = true),
        @Index(name = "idx_prr_url_method", columnList = "tenant_id, resource_url, http_method"),
        @Index(name = "idx_prr_operational_state", columnList = "tenant_id, operational_state, updated_at"),
        @Index(name = "idx_prr_signature", columnList = "tenant_id, annotation_signature_hash")
})
public class ProtectableResourceRegistryRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId = "default";

    @Column(name = "resource_id", nullable = false, length = 255)
    private String resourceId;

    @Column(name = "resource_url", nullable = false, length = 1000)
    private String resourceUrl;

    @Column(name = "http_method", nullable = false, length = 32)
    private String httpMethod;

    @Column(name = "criticality", length = 64)
    private String criticality;

    @Column(name = "verification_required", nullable = false)
    private boolean verificationRequired = true;

    @Column(name = "sync_enabled", nullable = false)
    private boolean syncEnabled;

    @Column(name = "owner_field", length = 255)
    private String ownerField;

    @Column(name = "bean_name", length = 255)
    private String beanName;

    @Column(name = "method_identifier", length = 1000)
    private String methodIdentifier;

    @Column(name = "source_class_name", length = 1000)
    private String sourceClassName;

    @Column(name = "source_method_name", length = 255)
    private String sourceMethodName;

    @Column(name = "annotation_signature_hash", nullable = false, length = 128)
    private String annotationSignatureHash;

    @Column(name = "certificate_state", nullable = false, length = 64)
    private String certificateState = "REVIEW_REQUIRED";

    @Column(name = "operational_state", nullable = false, length = 64)
    private String operationalState = "PENDING_VERIFICATION";

    @Column(name = "latest_certificate_id", length = 128)
    private String latestCertificateId;

    @Column(name = "last_verified_at")
    private LocalDateTime lastVerifiedAt;

    @Column(name = "signature_changed_at")
    private LocalDateTime signatureChangedAt;

    @Column(name = "discovered_at", nullable = false)
    private LocalDateTime discoveredAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "retired", nullable = false)
    private boolean retired;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
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

    public boolean isSyncEnabled() {
        return syncEnabled;
    }

    public void setSyncEnabled(boolean syncEnabled) {
        this.syncEnabled = syncEnabled;
    }

    public String getOwnerField() {
        return ownerField;
    }

    public void setOwnerField(String ownerField) {
        this.ownerField = ownerField;
    }

    public String getBeanName() {
        return beanName;
    }

    public void setBeanName(String beanName) {
        this.beanName = beanName;
    }

    public String getMethodIdentifier() {
        return methodIdentifier;
    }

    public void setMethodIdentifier(String methodIdentifier) {
        this.methodIdentifier = methodIdentifier;
    }

    public String getSourceClassName() {
        return sourceClassName;
    }

    public void setSourceClassName(String sourceClassName) {
        this.sourceClassName = sourceClassName;
    }

    public String getSourceMethodName() {
        return sourceMethodName;
    }

    public void setSourceMethodName(String sourceMethodName) {
        this.sourceMethodName = sourceMethodName;
    }

    public String getAnnotationSignatureHash() {
        return annotationSignatureHash;
    }

    public void setAnnotationSignatureHash(String annotationSignatureHash) {
        this.annotationSignatureHash = annotationSignatureHash;
    }

    public String getCertificateState() {
        return certificateState;
    }

    public void setCertificateState(String certificateState) {
        this.certificateState = certificateState;
    }

    public String getOperationalState() {
        return operationalState;
    }

    public void setOperationalState(String operationalState) {
        this.operationalState = operationalState;
    }

    public String getLatestCertificateId() {
        return latestCertificateId;
    }

    public void setLatestCertificateId(String latestCertificateId) {
        this.latestCertificateId = latestCertificateId;
    }

    public LocalDateTime getLastVerifiedAt() {
        return lastVerifiedAt;
    }

    public void setLastVerifiedAt(LocalDateTime lastVerifiedAt) {
        this.lastVerifiedAt = lastVerifiedAt;
    }

    public LocalDateTime getSignatureChangedAt() {
        return signatureChangedAt;
    }

    public void setSignatureChangedAt(LocalDateTime signatureChangedAt) {
        this.signatureChangedAt = signatureChangedAt;
    }

    public LocalDateTime getDiscoveredAt() {
        return discoveredAt;
    }

    public void setDiscoveredAt(LocalDateTime discoveredAt) {
        this.discoveredAt = discoveredAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public boolean isRetired() {
        return retired;
    }

    public void setRetired(boolean retired) {
        this.retired = retired;
    }
}
