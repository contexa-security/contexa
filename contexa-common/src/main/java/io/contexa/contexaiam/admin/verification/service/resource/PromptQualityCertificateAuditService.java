package io.contexa.contexaiam.admin.verification.service.resource;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.repository.PromptQualityCertificateAuditRepository;
import io.contexa.contexacore.saas.domain.entity.PromptQualityCertificateAuditRecord;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService.CertificateScope;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@Transactional(transactionManager = "contexaTransactionManager")
public class PromptQualityCertificateAuditService {

    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");
    private static final int RECENT_LIMIT = 100;

    private final PromptQualityCertificateAuditRepository repository;
    private final CopyOnWriteArrayList<PromptQualityAuditEvent> recentEvents = new CopyOnWriteArrayList<>();

    public PromptQualityCertificateAuditService() {
        this((PromptQualityCertificateAuditRepository) null);
    }

    @Autowired
    public PromptQualityCertificateAuditService(ObjectProvider<PromptQualityCertificateAuditRepository> repositoryProvider) {
        this(repositoryProvider != null ? repositoryProvider.getIfAvailable() : null);
    }

    PromptQualityCertificateAuditService(PromptQualityCertificateAuditRepository repository) {
        this.repository = repository;
    }

    public PromptQualityAuditEvent record(
            String eventType,
            String actor,
            CertificateScope scope,
            String certificateId,
            String previousState,
            String nextState,
            String reason
    ) {
        PromptQualityAuditEvent event = new PromptQualityAuditEvent(
                "pqc-audit-" + UUID.randomUUID(),
                valueOrDefault(eventType, "UNKNOWN_EVENT"),
                valueOrDefault(actor, "system"),
                scope != null ? scope.tenantId() : "default",
                certificateId,
                scope != null ? scope.scopeHash() : null,
                scope != null ? scope.resourceUrl() : null,
                scope != null ? scope.protectableResourceId() : null,
                scope != null ? scope.httpMethod() : null,
                previousState,
                nextState,
                reason,
                LocalDateTime.now(KOREA_ZONE).toString()
        );
        remember(event);
        if (repository != null) {
            repository.save(toRecord(event));
        }
        return event;
    }

    public List<PromptQualityAuditEvent> recent(String tenantId, String certificateId) {
        if (repository != null) {
            if (StringUtils.hasText(certificateId)) {
                return repository.findTop100ByCertificateIdOrderByRecordedAtDesc(certificateId).stream()
                        .map(this::fromRecord)
                        .toList();
            }
            if (StringUtils.hasText(tenantId)) {
                return repository.findTop100ByTenantIdOrderByRecordedAtDesc(tenantId).stream()
                        .map(this::fromRecord)
                        .toList();
            }
            return repository.findTop100ByOrderByRecordedAtDesc().stream()
                    .map(this::fromRecord)
                    .toList();
        }
        return recentEvents.stream()
                .filter(event -> !StringUtils.hasText(tenantId) || tenantId.equalsIgnoreCase(event.tenantId()))
                .filter(event -> !StringUtils.hasText(certificateId) || certificateId.equalsIgnoreCase(valueOrDefault(event.certificateId(), "")))
                .limit(RECENT_LIMIT)
                .toList();
    }

    private void remember(PromptQualityAuditEvent event) {
        recentEvents.add(0, event);
        while (recentEvents.size() > RECENT_LIMIT) {
            recentEvents.remove(recentEvents.size() - 1);
        }
    }

    private PromptQualityCertificateAuditRecord toRecord(PromptQualityAuditEvent event) {
        PromptQualityCertificateAuditRecord record = new PromptQualityCertificateAuditRecord();
        record.setEventId(event.eventId());
        record.setEventType(event.eventType());
        record.setActor(event.actor());
        record.setTenantId(event.tenantId());
        record.setCertificateId(event.certificateId());
        record.setScopeHash(event.scopeHash());
        record.setResourceUrl(event.resourceUrl());
        record.setResourceId(event.resourceId());
        record.setHttpMethod(event.httpMethod());
        record.setPreviousState(event.previousState());
        record.setNextState(event.nextState());
        record.setReason(event.reason());
        record.setRecordedAt(parseDateTime(event.recordedAt()));
        return record;
    }

    private PromptQualityAuditEvent fromRecord(PromptQualityCertificateAuditRecord record) {
        return new PromptQualityAuditEvent(
                record.getEventId(),
                record.getEventType(),
                record.getActor(),
                record.getTenantId(),
                record.getCertificateId(),
                record.getScopeHash(),
                record.getResourceUrl(),
                record.getResourceId(),
                record.getHttpMethod(),
                record.getPreviousState(),
                record.getNextState(),
                record.getReason(),
                record.getRecordedAt() != null ? record.getRecordedAt().toString() : null
        );
    }

    private LocalDateTime parseDateTime(String value) {
        if (!StringUtils.hasText(value)) {
            return LocalDateTime.now(KOREA_ZONE);
        }
        try {
            return LocalDateTime.parse(value);
        }
        catch (RuntimeException ignored) {
            return LocalDateTime.now(KOREA_ZONE);
        }
    }

    private String valueOrDefault(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    public record PromptQualityAuditEvent(
            String eventId,
            String eventType,
            String actor,
            String tenantId,
            String certificateId,
            String scopeHash,
            String resourceUrl,
            String resourceId,
            String httpMethod,
            String previousState,
            String nextState,
            String reason,
            String recordedAt) {
    }
}
