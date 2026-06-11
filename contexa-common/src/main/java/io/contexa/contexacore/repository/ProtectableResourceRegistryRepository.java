package io.contexa.contexacore.repository;

import io.contexa.contexacore.saas.domain.entity.ProtectableResourceRegistryRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ProtectableResourceRegistryRepository extends JpaRepository<ProtectableResourceRegistryRecord, Long> {

    Optional<ProtectableResourceRegistryRecord> findByTenantIdAndResourceIdAndHttpMethod(
            String tenantId,
            String resourceId,
            String httpMethod
    );

    List<ProtectableResourceRegistryRecord> findByTenantIdOrderByResourceUrlAscHttpMethodAsc(String tenantId);

    List<ProtectableResourceRegistryRecord> findByTenantIdAndOperationalStateOrderByUpdatedAtDesc(
            String tenantId,
            String operationalState
    );
}
