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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface PermissionService {
    Permission createPermission(Permission permission);
    Optional<Permission> getPermission(Long id);
    List<Permission> getAllPermissions();
    Page<Permission> searchPermissions(String keyword, Pageable pageable);
    Optional<AffectedPoliciesResponse> getAffectedPolicies(Long id);
    void deletePermission(Long id);
    Permission updatePermission(Long id, PermissionDto permissionDto);
    Optional<Permission> findByName(String name);
}