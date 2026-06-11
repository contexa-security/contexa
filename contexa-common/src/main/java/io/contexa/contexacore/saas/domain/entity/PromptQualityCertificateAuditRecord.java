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
@Table(name = "prompt_quality_certificate_audit_event", indexes = {
        @Index(name = "idx_pqc_audit_tenant_time", columnList = "tenant_id, recorded_at"),
        @Index(name = "idx_pqc_audit_certificate", columnList = "certificate_id, recorded_at"),
        @Index(name = "idx_pqc_audit_scope", columnList = "scope_hash, recorded_at"),
        @Index(name = "idx_pqc_audit_type", columnList = "event_type, recorded_at")
})
public class PromptQualityCertificateAuditRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", nullable = false, length = 128, unique = true)
    private String eventId;

    @Column(name = "event_type", nullable = false, length = 128)
    private String eventType;

    @Column(name = "actor", nullable = false, length = 255)
    private String actor;

    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId;

    @Column(name = "certificate_id", length = 128)
    private String certificateId;

    @Column(name = "scope_hash", length = 128)
    private String scopeHash;

    @Column(name = "resource_url", length = 1000)
    private String resourceUrl;

    @Column(name = "resource_id", length = 255)
    private String resourceId;

    @Column(name = "http_method", length = 32)
    private String httpMethod;

    @Column(name = "previous_state", length = 128)
    private String previousState;

    @Column(name = "next_state", length = 128)
    private String nextState;

    @Column(name = "reason", length = 3000)
    private String reason;

    @Column(name = "recorded_at", nullable = false)
    private LocalDateTime recordedAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.certificateId = certificateId;
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

    public String getPreviousState() {
        return previousState;
    }

    public void setPreviousState(String previousState) {
        this.previousState = previousState;
    }

    public String getNextState() {
        return nextState;
    }

    public void setNextState(String nextState) {
        this.nextState = nextState;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public LocalDateTime getRecordedAt() {
        return recordedAt;
    }

    public void setRecordedAt(LocalDateTime recordedAt) {
        this.recordedAt = recordedAt;
    }
}
