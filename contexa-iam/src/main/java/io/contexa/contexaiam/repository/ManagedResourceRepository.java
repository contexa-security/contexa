package io.contexa.contexaiam.repository;

import io.contexa.contexacommon.entity.ManagedResource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface ManagedResourceRepository extends JpaRepository<ManagedResource, Long>, ManagedResourceRepositoryCustom {

    Optional<ManagedResource> findByResourceIdentifier(String resourceIdentifier);

    @Query("SELECT DISTINCT r.serviceOwner FROM ManagedResource r WHERE r.serviceOwner IS NOT NULL ORDER BY r.serviceOwner ASC")
    Set<String> findAllServiceOwners();

    @Query("SELECT r FROM ManagedResource r LEFT JOIN FETCH r.permission WHERE r.status IN :statuses")
    List<ManagedResource> findByStatusInWithPermission(List<ManagedResource.Status> statuses);



}
