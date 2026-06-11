package io.contexa.contexacore.saas.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

/**
 * Operator-approved override for a {@code @Protectable} resource declaration.
 * <p>
 * Each {@code overlay_*} column is optional. A {@code null} value means "use
 * the annotation default as-is"; a non-null value replaces the annotation
 * value when the registry is synchronised. When {@code overrideExpiresAt} is
 * set and has passed, the overlay is ignored and the annotation value is
 * restored.
 * <p>
 * The tuple {@code (tenantId, resourceId, httpMethod)} is unique and matches
 * the persisted overlay schema. Source resource URL remains an API/navigation
 * scope but is not a persisted overlay key while Flyway is disabled.
 */
@Entity
@Table(name = "protectable_resource_overlay", indexes = {
        @Index(name = "ux_protectable_overlay_scope", columnList = "tenant_id, resource_id, http_method", unique = true),
        @Index(name = "idx_protectable_overlay_expiry", columnList = "override_expires_at"),
        @Index(name = "idx_protectable_overlay_tenant_resource", columnList = "tenant_id, resource_id")
})
public class ProtectableResourceOverlayRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 64)
    private String tenantId;

    @Column(name = "resource_id", nullable = false, length = 256)
    private String resourceId;

    @Column(name = "http_method", nullable = false, length = 16)
    private String httpMethod;

    @Column(name = "overlay_criticality", length = 32)
    private String overlayCriticality;

    @Column(name = "overlay_verification_required")
    private Boolean overlayVerificationRequired;

    @Column(name = "overlay_sync")
    private Boolean overlaySync;

    @Column(name = "overlay_owner_field", length = 128)
    private String overlayOwnerField;

    @Column(name = "overlay_resource_url", length = 512)
    private String overlayResourceUrl;

    @Column(name = "override_reason", nullable = false, columnDefinition = "text")
    private String overrideReason;

    @Column(name = "override_approver", nullable = false, length = 128)
    private String overrideApprover;

    @Column(name = "override_approved_at", nullable = false)
    private LocalDateTime overrideApprovedAt;

    @Column(name = "override_expires_at")
    private LocalDateTime overrideExpiresAt;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "created_by", length = 255)
    private String createdBy;

    @Column(name = "updated_by", length = 255)
    private String updatedBy;

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

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getOverlayCriticality() {
        return overlayCriticality;
    }

    public void setOverlayCriticality(String overlayCriticality) {
        this.overlayCriticality = overlayCriticality;
    }

    public Boolean getOverlayVerificationRequired() {
        return overlayVerificationRequired;
    }

    public void setOverlayVerificationRequired(Boolean overlayVerificationRequired) {
        this.overlayVerificationRequired = overlayVerificationRequired;
    }

    public Boolean getOverlaySync() {
        return overlaySync;
    }

    public void setOverlaySync(Boolean overlaySync) {
        this.overlaySync = overlaySync;
    }

    public String getOverlayOwnerField() {
        return overlayOwnerField;
    }

    public void setOverlayOwnerField(String overlayOwnerField) {
        this.overlayOwnerField = overlayOwnerField;
    }

    public String getOverlayResourceUrl() {
        return overlayResourceUrl;
    }

    public void setOverlayResourceUrl(String overlayResourceUrl) {
        this.overlayResourceUrl = overlayResourceUrl;
    }

    public String getOverrideReason() {
        return overrideReason;
    }

    public void setOverrideReason(String overrideReason) {
        this.overrideReason = overrideReason;
    }

    public String getOverrideApprover() {
        return overrideApprover;
    }

    public void setOverrideApprover(String overrideApprover) {
        this.overrideApprover = overrideApprover;
    }

    public LocalDateTime getOverrideApprovedAt() {
        return overrideApprovedAt;
    }

    public void setOverrideApprovedAt(LocalDateTime overrideApprovedAt) {
        this.overrideApprovedAt = overrideApprovedAt;
    }

    public LocalDateTime getOverrideExpiresAt() {
        return overrideExpiresAt;
    }

    public void setOverrideExpiresAt(LocalDateTime overrideExpiresAt) {
        this.overrideExpiresAt = overrideExpiresAt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }
}
