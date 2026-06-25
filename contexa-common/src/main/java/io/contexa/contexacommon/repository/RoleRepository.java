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

import io.contexa.contexacommon.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @Query(value = "SELECT * FROM role r WHERE r.expression = false " +
            "AND (CAST(:keyword AS text) IS NULL OR r.role_name ILIKE '%' || CAST(:keyword AS text) || '%' " +
            "OR r.role_desc ILIKE '%' || CAST(:keyword AS text) || '%') " +
            "ORDER BY r.role_id DESC",
            countQuery = "SELECT COUNT(*) FROM role r WHERE r.expression = false " +
            "AND (CAST(:keyword AS text) IS NULL OR r.role_name ILIKE '%' || CAST(:keyword AS text) || '%' " +
            "OR r.role_desc ILIKE '%' || CAST(:keyword AS text) || '%')",
            nativeQuery = true)
    Page<Role> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);
    Page<Role> findByRoleNameContainingIgnoreCaseOrRoleDescContainingIgnoreCase(String roleName, String roleDesc, Pageable pageable);

    Optional<Role> findByRoleName(String name);

    @Override
    void delete(Role role);

    @Query("select r from Role r where r.expression = false")
    List<Role> findAllRolesWithoutExpression();

    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission p LEFT JOIN FETCH p.managedResource WHERE r.id = :id")
    Optional<Role> findByIdWithPermissions(Long id);

    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission p LEFT JOIN FETCH p.managedResource")
    List<Role> findAllWithPermissions();

    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.rolePermissions rp LEFT JOIN FETCH rp.permission p LEFT JOIN FETCH p.managedResource WHERE r.id IN :ids")
    List<Role> findAllByIdWithPermissions(@Param("ids") Collection<Long> ids);

    
    @Query("SELECT r FROM Role r " +
            "LEFT JOIN FETCH r.rolePermissions rp " +
            "LEFT JOIN FETCH rp.permission p " +
            "LEFT JOIN FETCH p.managedResource " +
            "WHERE r.id = :id")
    Optional<Role> findByIdWithPermissionsAndResources(@Param("id") Long id);
}

