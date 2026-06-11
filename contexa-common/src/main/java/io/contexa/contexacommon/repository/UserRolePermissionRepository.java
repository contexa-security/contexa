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

import io.contexa.contexacommon.entity.UserRolePermission;
import io.contexa.contexacommon.entity.UserRolePermissionId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface UserRolePermissionRepository extends JpaRepository<UserRolePermission, UserRolePermissionId> {

    @Query("SELECT urp FROM UserRolePermission urp JOIN FETCH urp.permission WHERE urp.user.id = :userId AND urp.role.id = :roleId")
    List<UserRolePermission> findByUserIdAndRoleId(@Param("userId") Long userId, @Param("roleId") Long roleId);

    @Query("SELECT urp FROM UserRolePermission urp JOIN FETCH urp.permission JOIN FETCH urp.role WHERE urp.user.id = :userId")
    List<UserRolePermission> findByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM UserRolePermission urp WHERE urp.user.id = :userId AND urp.role.id = :roleId")
    void deleteByUserIdAndRoleId(@Param("userId") Long userId, @Param("roleId") Long roleId);

    @Modifying
    @Query("DELETE FROM UserRolePermission urp WHERE urp.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId);
}
