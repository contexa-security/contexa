/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.repository;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

    @Query(value = "SELECT p FROM Permission p LEFT JOIN FETCH p.managedResource mr " +
            "WHERE mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.NEEDS_DEFINITION " +
            "AND mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.EXCLUDED " +
            "AND p.id NOT IN :excludeIds " +
            "AND (:pattern IS NULL OR LOWER(p.name) LIKE :pattern " +
            "OR LOWER(p.friendlyName) LIKE :pattern)",
            countQuery = "SELECT COUNT(p) FROM Permission p LEFT JOIN p.managedResource mr " +
            "WHERE mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.NEEDS_DEFINITION " +
            "AND mr.status <> io.contexa.contexacommon.entity.ManagedResource.Status.EXCLUDED " +
            "AND p.id NOT IN :excludeIds " +
            "AND (:pattern IS NULL OR LOWER(p.name) LIKE :pattern " +
            "OR LOWER(p.friendlyName) LIKE :pattern)")
    Page<Permission> searchAvailablePermissions(
            @Param("pattern") String pattern,
            @Param("excludeIds") Collection<Long> excludeIds,
            Pageable pageable);
    Optional<Permission> findByName(String name);

    Page<Permission> findByNameContainingIgnoreCaseOrFriendlyNameContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
            String name, String friendlyName, String description, Pageable pageable);

    
    @Query("SELECT DISTINCT p FROM Permission p LEFT JOIN FETCH p.managedResource WHERE p.name IN :names")
    List<Permission> findAllByNameIn(@Param("names") Set<String> names);

    
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
            @Param("resourceType") ManagedResource.ResourceType resourceType,
            @Param("resourceIdentifier") String resourceIdentifier
    );

    @Query("SELECT COUNT(rp) FROM RolePermission rp WHERE rp.permission.id = :permissionId")
    long countRoleAssignments(@Param("permissionId") Long permissionId);

    @Modifying
    @Query("DELETE FROM Permission p WHERE p.id IN :ids")
    void deleteAllByIds(@Param("ids") Collection<Long> ids);
}