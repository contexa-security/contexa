package io.contexa.contexaiam.admin.verification.service.resource;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Manages operator-approved overrides applied to {@code @Protectable} resource
 * declarations.
 * <p>
 * The overlay is consulted during
 * {@code ProtectableResourceCatalogService#syncRegistry()} to let operators
 * adjust {@code criticality}, {@code verificationRequired}, {@code sync},
 * {@code ownerField} and {@code resourceUrl} without redeploying the
 * annotation source. Overlays carry a mandatory approval trail and an
 * optional expiry, after which the annotation value takes over again.
 */
public interface ProtectableResourceOverlayService {

    default Optional<ResolvedOverlay> findActive(String tenantId,
                                                 String resourceId,
                                                 String httpMethod,
                                                 LocalDateTime asOf) {
        return findActive(tenantId, resourceId, null, httpMethod, asOf);
    }

    Optional<ResolvedOverlay> findActive(String tenantId,
                                         String resourceId,
                                         String sourceResourceUrl,
                                         String httpMethod,
                                         LocalDateTime asOf);

    List<OverlayView> listByTenant(String tenantId);

    OverlayView upsert(OverlayCommand command, String approver);

    default void delete(String tenantId,
                        String resourceId,
                        String httpMethod,
                        String approver,
                        String reason) {
        delete(tenantId, resourceId, null, httpMethod, approver, reason);
    }

    void delete(String tenantId,
                String resourceId,
                String sourceResourceUrl,
                String httpMethod,
                String approver,
                String reason);

    int purgeExpired(LocalDateTime cutoff);

    record OverlayCommand(
            String tenantId,
            String resourceId,
            String sourceResourceUrl,
            String httpMethod,
            String overlayCriticality,
            Boolean overlayVerificationRequired,
            Boolean overlaySync,
            String overlayOwnerField,
            String overlayResourceUrl,
            String overrideReason,
            LocalDateTime overrideExpiresAt,
            boolean acknowledgeSecurityRisk
    ) {
    }

    record ResolvedOverlay(
            String tenantId,
            String resourceId,
            String sourceResourceUrl,
            String httpMethod,
            String overlayCriticality,
            Boolean overlayVerificationRequired,
            Boolean overlaySync,
            String overlayOwnerField,
            String overlayResourceUrl,
            String overrideReason,
            String overrideApprover,
            LocalDateTime overrideApprovedAt,
            LocalDateTime overrideExpiresAt
    ) {
        public boolean isActiveAt(LocalDateTime asOf) {
            return overrideExpiresAt == null || asOf.isBefore(overrideExpiresAt);
        }
    }

    record OverlayView(
            String tenantId,
            String resourceId,
            String sourceResourceUrl,
            String httpMethod,
            String overlayCriticality,
            Boolean overlayVerificationRequired,
            Boolean overlaySync,
            String overlayOwnerField,
            String overlayResourceUrl,
            String overrideReason,
            String overrideApprover,
            LocalDateTime overrideApprovedAt,
            LocalDateTime overrideExpiresAt,
            boolean active
    ) {
    }
}
