package io.contexa.contexacore.repository;

import io.contexa.contexacore.saas.domain.entity.ProtectableResourceOverlayRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface ProtectableResourceOverlayRepository extends JpaRepository<ProtectableResourceOverlayRecord, Long> {

    Optional<ProtectableResourceOverlayRecord> findByTenantIdAndResourceIdAndHttpMethod(
            String tenantId,
            String resourceId,
            String httpMethod
    );

    List<ProtectableResourceOverlayRecord> findByTenantIdOrderByUpdatedAtDesc(String tenantId);

    List<ProtectableResourceOverlayRecord> findByOverrideExpiresAtBefore(LocalDateTime cutoff);
}
