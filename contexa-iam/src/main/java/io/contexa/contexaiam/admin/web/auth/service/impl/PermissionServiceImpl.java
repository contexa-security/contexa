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
import io.contexa.contexaiam.common.ConsoleInput;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
@CacheConfig(cacheManager = "contexaCacheManager")
public class PermissionServiceImpl extends AccountAuthoritiesService implements PermissionService {
    private final PermissionRepository permissionRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final PolicyRepository policyRepository;
    private final MessageSource messageSource;

    /** The lengths of the columns of a permission. */
    private static final int NAME_LENGTH = 255;
    private static final int TEXT_LENGTH = 255;
    private static final int DESCRIPTION_LENGTH = 1024;
    private static final int TYPE_LENGTH = 100;
    private static final int CONDITION_LENGTH = 2048;

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
        permission.setName(ConsoleInput.required(messageSource, "crud.field.permission.name", permission.getName(),
                NAME_LENGTH));
        checkFields(permission);
        if (permissionRepository.findByName(permission.getName()).isPresent()) {
            throw new IllegalArgumentException(msg("msg.permission.name.duplicate", permission.getName()));
        }
        try {
            // Flushed here, so a permission of the same name that another administrator saved a moment before is
            // refused with its reason, not with the constraint of the table.
            Permission saved = permissionRepository.save(permission);
            permissionRepository.flush();
            return saved;
        } catch (DataIntegrityViolationException e) {
            throw new IllegalArgumentException(msg("msg.permission.name.duplicate", permission.getName()), e);
        }
    }

    /** The fields of a permission other than its name, each within its column. */
    private void checkFields(Permission permission) {
        permission.setFriendlyName(ConsoleInput.optional(messageSource, "crud.field.permission.friendly.name",
                permission.getFriendlyName(), TEXT_LENGTH));
        permission.setDescription(ConsoleInput.optional(messageSource, "crud.field.permission.description",
                permission.getDescription(), DESCRIPTION_LENGTH));
        permission.setTargetType(ConsoleInput.optional(messageSource, "crud.field.permission.target.type",
                permission.getTargetType(), TYPE_LENGTH));
        permission.setActionType(ConsoleInput.optional(messageSource, "crud.field.permission.action.type",
                permission.getActionType(), TYPE_LENGTH));
        permission.setConditionExpression(ConsoleInput.optional(messageSource, "crud.field.permission.condition",
                permission.getConditionExpression(), CONDITION_LENGTH));
    }

    @Cacheable(value = "permissions", key = "#id")
    @Override
    public Optional<Permission> getPermission(Long id) {
        return permissionRepository.findWithManagedResourceById(id);
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
        return permissionRepository.findAllWithManagedResourceBy(pageable);
    }

    @Override
    public Optional<AffectedPoliciesResponse> getAffectedPolicies(Long id) {
        return permissionRepository.findById(id)
                .map(permission -> {
                    long roleCount = permissionRepository.countRoleAssignments(id);
                    List<AffectedPolicyResponse> policyList = policyRepository
                            .findActivePoliciesReferencing(List.of(permission.getName()))
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
        authoritiesChanged();
        long roleCount = permissionRepository.countRoleAssignments(id);
        Permission permission = permissionRepository.findById(id).orElse(null);
        if (roleCount > 0) {
            throw new IllegalStateException(msg("msg.permission.delete.assigned",
                    permission != null ? permission.getName() : String.valueOf(id), roleCount));
        }
        if (permission == null) {
            throw new IllegalArgumentException(msg("msg.permission.not.found.id", String.valueOf(id)));
        }

        // Counted before anything is changed, so a refusal leaves nothing behind. The database refuses the deletion of a
        // permission that roles were given to groups or accounts with, with a constraint nobody can read; it stays the
        // backstop when such a grant comes in between the count and the deletion. A permission is no part of who
        // administers the console, so the deletion does not take the lock that serializes those changes.
        long groups = permissionRepository.countGroupAssignments(id);
        long accounts = permissionRepository.countAccountAssignments(id);
        if (groups > 0 || accounts > 0) {
            throw new IllegalStateException(msg("msg.permission.delete.used", permission.getName(), groups, accounts));
        }

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
        authoritiesChanged();
        Permission permission = permissionRepository.findWithManagedResourceById(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.permission.not.found.id", String.valueOf(id))));

        String name = ConsoleInput.required(messageSource, "crud.field.permission.name", permissionDto.getName(),
                NAME_LENGTH);
        if (!name.equals(permission.getName())) {
            permissionRepository.findByName(name)
                    .filter(other -> !id.equals(other.getId()))
                    .ifPresent(other -> {
                        throw new IllegalArgumentException(msg("msg.permission.name.duplicate", name));
                    });
        }
        permission.setName(name);
        permission.setFriendlyName(permissionDto.getFriendlyName());
        permission.setDescription(permissionDto.getDescription());
        permission.setTargetType(permissionDto.getTargetType());
        permission.setActionType(permissionDto.getActionType());
        permission.setConditionExpression(permissionDto.getConditionExpression());
        checkFields(permission);

        try {
            Permission saved = permissionRepository.save(permission);
            permissionRepository.flush();
            return saved;
        } catch (DataIntegrityViolationException e) {
            throw new IllegalArgumentException(msg("msg.permission.name.duplicate", name), e);
        }
    }

    @Cacheable(value = "permissionsByName", key = "#name")
    @Override
    public Optional<Permission> findByName(String name) {
        return permissionRepository.findByName(name);
    }
}