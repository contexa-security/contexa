package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

    @Query("SELECT p FROM Permission p LEFT JOIN p.managedResource mr " +
            "WHERE mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.NEEDS_DEFINITION " +
            "AND mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.EXCLUDED " +
            "AND p.id NOT IN :excludeIds " +
            "AND (:keyword IS NULL OR LOWER(p.name) LIKE LOWER(CONCAT('%', :keyword, '%')) " +
            "OR LOWER(p.friendlyName) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Permission> searchAvailablePermissions(
            @Param("keyword") String keyword,
            @Param("excludeIds") Collection<Long> excludeIds,
            Pageable pageable);
    Optional<Permission> findByName(String name);

    
    List<Permission> findAllByNameIn(Set<String> names);

    
    @Query("SELECT p FROM Permission p " +
            "LEFT JOIN FETCH p.managedResource mr " +
            "WHERE mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.NEEDS_DEFINITION " +
            "AND mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.EXCLUDED")
    List<Permission> findDefinedPermissionsWithDetails();


    @Query("SELECT p FROM Permission p " +
            "JOIN p.managedResource mr " +
            "WHERE mr.resourceType = :resourceType " +
            "AND mr.resourceIdentifier = :resourceIdentifier")
    List<Permission> findByResourceTypeAndIdentifier(
            @org.springframework.data.repository.query.Param("resourceType") io.contexa.contexacommon.entity.ManagedResource.ResourceType resourceType,
            @org.springframework.data.repository.query.Param("resourceIdentifier") String resourceIdentifier
    );

    @Query("SELECT COUNT(rp) FROM RolePermission rp WHERE rp.permission.id = :permissionId")
    long countRoleAssignments(@org.springframework.data.repository.query.Param("permissionId") Long permissionId);
}