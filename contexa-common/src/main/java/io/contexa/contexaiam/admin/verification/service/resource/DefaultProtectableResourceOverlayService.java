package io.contexa.contexaiam.admin.verification.service.resource;

import io.contexa.contexacore.repository.ProtectableResourceOverlayRepository;
import io.contexa.contexacore.saas.domain.entity.ProtectableResourceOverlayRecord;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public class DefaultProtectableResourceOverlayService implements ProtectableResourceOverlayService {

    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");

    private final ProtectableResourceOverlayRepository repository;

    public DefaultProtectableResourceOverlayService(ProtectableResourceOverlayRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<ResolvedOverlay> findActive(String tenantId,
                                                 String resourceId,
                                                 String sourceResourceUrl,
                                                 String httpMethod,
                                                 LocalDateTime asOf) {
        String safeTenantId = normalizeTenant(tenantId);
        String safeResourceId = requireNonBlank(resourceId, "resourceId");
        String safeHttpMethod = normalizeMethod(httpMethod);
        return repository.findByTenantIdAndResourceIdAndHttpMethod(
                        safeTenantId,
                        safeResourceId,
                        safeHttpMethod)
                .map(this::toResolved)
                .filter(overlay -> overlay.isActiveAt(asOf != null ? asOf : LocalDateTime.now(KOREA_ZONE)));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OverlayView> listByTenant(String tenantId) {
        LocalDateTime now = LocalDateTime.now(KOREA_ZONE);
        return repository.findByTenantIdOrderByUpdatedAtDesc(normalizeTenant(tenantId)).stream()
                .map(record -> toView(record, now))
                .toList();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public OverlayView upsert(OverlayCommand command, String approver) {
        if (command == null) {
            throw new IllegalArgumentException("OverlayCommand is required.");
        }
        String tenantId = normalizeTenant(command.tenantId());
        String resourceId = requireNonBlank(command.resourceId(), "resourceId");
        String httpMethod = normalizeMethod(command.httpMethod());
        String reason = requireNonBlank(command.overrideReason(), "overrideReason");
        String actor = requireNonBlank(approver, "approver");
        if (Boolean.FALSE.equals(command.overlayVerificationRequired()) && !command.acknowledgeSecurityRisk()) {
            throw new IllegalArgumentException(
                    "Disabling verificationRequired requires acknowledgeSecurityRisk=true with audit approval.");
        }
        LocalDateTime now = LocalDateTime.now(KOREA_ZONE);

        ProtectableResourceOverlayRecord record = repository
                .findByTenantIdAndResourceIdAndHttpMethod(tenantId, resourceId, httpMethod)
                .orElseGet(ProtectableResourceOverlayRecord::new);

        boolean insert = record.getId() == null;
        if (insert) {
            record.setTenantId(tenantId);
            record.setResourceId(resourceId);
            record.setHttpMethod(httpMethod);
            record.setCreatedAt(now);
            record.setCreatedBy(actor);
        }
        record.setOverlayCriticality(trimToNull(command.overlayCriticality()));
        record.setOverlayVerificationRequired(command.overlayVerificationRequired());
        record.setOverlaySync(command.overlaySync());
        record.setOverlayOwnerField(trimToNull(command.overlayOwnerField()));
        record.setOverlayResourceUrl(trimToNull(command.overlayResourceUrl()));
        record.setOverrideReason(reason);
        record.setOverrideApprover(actor);
        record.setOverrideApprovedAt(now);
        record.setOverrideExpiresAt(command.overrideExpiresAt());
        record.setUpdatedAt(now);
        record.setUpdatedBy(actor);

        ProtectableResourceOverlayRecord saved = repository.save(record);
        return toView(saved, now);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void delete(String tenantId,
                       String resourceId,
                       String sourceResourceUrl,
                       String httpMethod,
                       String approver,
                       String reason) {
        requireNonBlank(approver, "approver");
        requireNonBlank(reason, "reason");
        repository.findByTenantIdAndResourceIdAndHttpMethod(
                        normalizeTenant(tenantId),
                        requireNonBlank(resourceId, "resourceId"),
                        normalizeMethod(httpMethod))
                .ifPresent(repository::delete);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public int purgeExpired(LocalDateTime cutoff) {
        LocalDateTime now = cutoff != null ? cutoff : LocalDateTime.now(KOREA_ZONE);
        List<ProtectableResourceOverlayRecord> expired = repository.findByOverrideExpiresAtBefore(now);
        if (expired.isEmpty()) {
            return 0;
        }
        repository.deleteAll(expired);
        return expired.size();
    }

    private ResolvedOverlay toResolved(ProtectableResourceOverlayRecord record) {
        return new ResolvedOverlay(
                record.getTenantId(),
                record.getResourceId(),
                "",
                record.getHttpMethod(),
                record.getOverlayCriticality(),
                record.getOverlayVerificationRequired(),
                record.getOverlaySync(),
                record.getOverlayOwnerField(),
                record.getOverlayResourceUrl(),
                record.getOverrideReason(),
                record.getOverrideApprover(),
                record.getOverrideApprovedAt(),
                record.getOverrideExpiresAt()
        );
    }

    private OverlayView toView(ProtectableResourceOverlayRecord record, LocalDateTime asOf) {
        LocalDateTime expiresAt = record.getOverrideExpiresAt();
        boolean active = expiresAt == null || asOf.isBefore(expiresAt);
        return new OverlayView(
                record.getTenantId(),
                record.getResourceId(),
                "",
                record.getHttpMethod(),
                record.getOverlayCriticality(),
                record.getOverlayVerificationRequired(),
                record.getOverlaySync(),
                record.getOverlayOwnerField(),
                record.getOverlayResourceUrl(),
                record.getOverrideReason(),
                record.getOverrideApprover(),
                record.getOverrideApprovedAt(),
                expiresAt,
                active
        );
    }

    private String normalizeTenant(String tenantId) {
        return StringUtils.hasText(tenantId) ? tenantId.trim() : "default";
    }

    private String normalizeMethod(String httpMethod) {
        return requireNonBlank(httpMethod, "httpMethod").trim().toUpperCase(Locale.ROOT);
    }

    private String requireNonBlank(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(field + " must not be blank.");
        }
        return value.trim();
    }

    private String trimToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
