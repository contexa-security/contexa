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
package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPolicyResponse;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class PermissionServiceImpl implements PermissionService {
    private final PermissionRepository permissionRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final PolicyRepository policyRepository;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {@CacheEvict(value = "usersWithAuthorities", allEntries = true)},
            put = {@CachePut(value = "permissions", key = "#result.id")}
    )
    @Override
    public Permission createPermission(Permission permission) {
        if (permissionRepository.findByName(permission.getName()).isPresent()) {
            throw new IllegalArgumentException(msg("msg.permission.name.duplicate", permission.getName()));
        }
        return permissionRepository.save(permission);
    }

    @Cacheable(value = "permissions", key = "#id")
    @Override
    public Optional<Permission> getPermission(Long id) {
        return permissionRepository.findById(id);
    }

    @Cacheable(value = "permissions", key = "'allPermissions'")
    @Override
    public List<Permission> getAllPermissions() {
        return permissionRepository.findAll();
    }

    @Override
    @Protectable(verificationRequired = false)
    public Page<Permission> searchPermissions(String keyword, Pageable pageable) {
        if (StringUtils.hasText(keyword)) {
            String trimmedKeyword = keyword.trim();
            return permissionRepository.findByNameContainingIgnoreCaseOrFriendlyNameContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
                    trimmedKeyword,
                    trimmedKeyword,
                    trimmedKeyword,
                    pageable
            );
        }
        return permissionRepository.findAll(pageable);
    }

    @Override
    public Optional<AffectedPoliciesResponse> getAffectedPolicies(Long id) {
        return permissionRepository.findById(id)
                .map(permission -> {
                    long roleCount = permissionRepository.countRoleAssignments(id);
                    List<AffectedPolicyResponse> policyList = policyRepository
                            .findActivePoliciesReferencingExpression(permission.getName())
                            .stream()
                            .map(AffectedPolicyResponse::from)
                            .toList();
                    return AffectedPoliciesResponse.forPermission(permission.getName(), policyList, roleCount);
                });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "permissions", key = "#id"),
                    @CacheEvict(value = "permissions", key = "'allPermissions'")
            }
    )
    @Override
    public void deletePermission(Long id) {
        long roleCount = permissionRepository.countRoleAssignments(id);
        if (roleCount > 0) {
            throw new IllegalStateException(
                    "Cannot delete: permission is assigned to " + roleCount + " role(s)");
        }

        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found: " + id));

        ManagedResource resource = permission.getManagedResource();
        if (resource != null) {
            resource.setPermission(null);
            resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
            permission.setManagedResource(null);
            managedResourceRepository.save(resource);
        }

        permissionRepository.delete(permission);
    }

    @Caching(
            evict = {@CacheEvict(value = "usersWithAuthorities", allEntries = true)},
            put = {@CachePut(value = "permissions", key = "#result.id")}
    )
    @Transactional(transactionManager = "contexaTransactionManager")
    @Override
    public Permission updatePermission(Long id, PermissionDto permissionDto) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found: " + id));

        permission.setName(permissionDto.getName());
        permission.setFriendlyName(permissionDto.getFriendlyName());
        permission.setDescription(permissionDto.getDescription());
        permission.setTargetType(permissionDto.getTargetType());
        permission.setActionType(permissionDto.getActionType());
        permission.setConditionExpression(permissionDto.getConditionExpression());

        return permissionRepository.save(permission);
    }

    @Cacheable(value = "permissionsByName", key = "#name")
    @Override
    public Optional<Permission> findByName(String name) {
        return permissionRepository.findByName(name);
    }
}