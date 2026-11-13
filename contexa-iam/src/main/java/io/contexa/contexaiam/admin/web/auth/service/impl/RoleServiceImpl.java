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
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPolicyResponse;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.common.ConsoleInput;
import io.contexa.contexaiam.common.event.dto.RolePermissionsChangedEvent;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
@CacheConfig(cacheManager = "contexaCacheManager")
public class RoleServiceImpl extends AccountAuthoritiesService implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final IntegrationEventBus eventBus;
    private final CentralAuditFacade centralAuditFacade;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final PolicyRepository policyRepository;
    private final PolicySynchronizationService policySynchronizationService;
    private final MessageSource messageSource;
    private final LastAdministratorGuard lastAdministratorGuard;

    /** The lengths of the columns of a role. */
    private static final int NAME_LENGTH = 100;
    private static final int DESCRIPTION_LENGTH = 500;

    /**
     * What a new name of a role may be made of: no blank, no {@code >} that separates the roles of a hierarchy, and no
     * comma, quote or parenthesis that would break a condition naming the role.
     */
    private static final Pattern ROLE_NAME = Pattern.compile("[^\\s>,'\"()]+");

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Cacheable(value = "roles", key = "#id")
    public Role getRole(long id) {
        return roleRepository.findByIdWithPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.role.not.found.id", String.valueOf(id))));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<Role> findRole(long id) {
        return roleRepository.findByIdWithPermissions(id);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Cacheable(value = "roles", key = "'allRoles'")
    public List<Role> getRoles() {
        return roleRepository.findAllWithPermissions();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Cacheable(value = "rolesWithoutExpression", key = "'allRolesWithoutExpression'")
    public List<Role> getRolesWithoutExpression() {
        return roleRepository.findAllRolesWithoutExpression();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Protectable(verificationRequired = false)
    public Page<Role> searchRoles(String keyword, Pageable pageable) {
        String effectiveKeyword = StringUtils.hasText(keyword) ? keyword.trim() : null;
        Pageable effectivePageable = PageRequest.of(pageable.getPageNumber(), pageable.getPageSize());
        return roleRepository.searchByKeyword(effectiveKeyword, effectivePageable);
    }
    @Override
    public Optional<AffectedPoliciesResponse> getAffectedPolicies(Long id) {
        return roleRepository.findById(id)
                .map(role -> {
                    // The authority the role gives its holders; a condition written before that was kept in step with it
                    // asks for the name of the role itself.
                    Set<String> names = new LinkedHashSet<>();
                    names.add(RoleAuthority.authorityOf(role.getRoleName()));
                    names.add(role.getRoleName());
                    List<AffectedPolicyResponse> policyList = policyRepository
                            .findActivePoliciesReferencing(names)
                            .stream()
                            .map(AffectedPolicyResponse::from)
                            .toList();
                    return AffectedPoliciesResponse.forRole(role.getRoleName(), policyList);
                });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    public Role createRole(Role role, List<Long> permissionIds) {
        role.setRoleName(newRoleName(role.getRoleName(), null));
        role.setRoleDesc(ConsoleInput.optional(messageSource, "crud.field.role.description", role.getRoleDesc(),
                DESCRIPTION_LENGTH));

        if (permissionIds != null && !permissionIds.isEmpty()) {
            List<Permission> permissions = permissionRepository.findAllById(permissionIds);
            if (permissions.size() != permissionIds.size()) {
                throw new IllegalArgumentException(msg("msg.permission.not.found"));
            }
            Set<RolePermission> rolePermissions = permissions.stream()
                    .map(p -> RolePermission.builder().role(role).permission(p).build())
                    .collect(Collectors.toSet());
            role.setRolePermissions(rolePermissions);
        }

        Role saved;
        try {
            // Flushed here, so a role of the same name that another administrator saved a moment before is refused
            // with its reason, not with the constraint of the table.
            saved = roleRepository.save(role);
            roleRepository.flush();
        } catch (DataIntegrityViolationException e) {
            throw new IllegalArgumentException(msg("msg.role.name.duplicate", role.getRoleName()), e);
        }
        auditRoleChange(AuditEventCategory.ROLE_CREATED, saved);

        if (permissionIds != null && !permissionIds.isEmpty()) {
            eventBus.publish(new RolePermissionsChangedEvent(saved.getId()));
        }

        return saved;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    public Role updateRole(Role role, List<Long> permissionIds) {
        // First in the transaction: a change of who administers the console waits for the one before it.
        lastAdministratorGuard.serializeChanges();
        List<String> administrators = lastAdministratorGuard.administrators();
        authoritiesChanged();
        Role existingRole = roleRepository.findByIdWithPermissions(role.getId())
                .orElseThrow(() -> new IllegalArgumentException(
                        msg("msg.role.not.found.id", String.valueOf(role.getId()))));

        String roleName = ConsoleInput.required(messageSource, "crud.field.role.name", role.getRoleName(), NAME_LENGTH);
        if (!roleName.equals(existingRole.getRoleName())) {
            roleName = newRoleName(roleName, existingRole.getId());
        }
        existingRole.setRoleName(roleName);
        existingRole.setRoleDesc(ConsoleInput.optional(messageSource, "crud.field.role.description", role.getRoleDesc(),
                DESCRIPTION_LENGTH));
        existingRole.setExpression(role.isExpression());
        // Switched off, the role gives its holders nothing. The check of the last administrator below refuses switching
        // off the role that the console's last administrator holds ROLE_ADMIN by.
        existingRole.setEnabled(role.isEnabled());

        Set<Long> desiredPermissionIds = permissionIds != null ? new HashSet<>(permissionIds) : new HashSet<>();
        Set<RolePermission> currentRolePermissions = existingRole.getRolePermissions();

        currentRolePermissions.removeIf(rp -> !desiredPermissionIds.contains(rp.getPermission().getId()));

        Set<Long> currentPermissionIds = currentRolePermissions.stream()
                .map(rp -> rp.getPermission().getId())
                .collect(Collectors.toSet());

        Set<Long> newPermIds = desiredPermissionIds.stream()
                .filter(desiredId -> !currentPermissionIds.contains(desiredId))
                .collect(Collectors.toSet());
        if (!newPermIds.isEmpty()) {
            permissionRepository.findAllById(newPermIds).forEach(permission ->
                    currentRolePermissions.add(RolePermission.builder().role(existingRole).permission(permission).build()));
        }

        Role savedRole = roleRepository.save(existingRole);
        lastAdministratorGuard.refuseLosingEveryAdministrator(administrators);
        eventBus.publish(new RolePermissionsChangedEvent(savedRole.getId()));
        auditRoleChange(AuditEventCategory.ROLE_UPDATED, savedRole);

        return savedRole;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true),
                    @CacheEvict(value = "roles", key = "#id")
            }
    )
    public void deleteRole(long id) {
        lastAdministratorGuard.serializeChanges();
        List<String> administrators = lastAdministratorGuard.administrators();
        authoritiesChanged();
        // Check if role is referenced in any active hierarchy (exact token matching)
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.role.not.found.id", String.valueOf(id))));
        List<String> referencedIn = new ArrayList<>();
        roleHierarchyRepository.findAllByIsActiveTrue().forEach(hierarchy -> {
            String hs = hierarchy.getHierarchyString();
            if (hs != null) {
                String normalized = hs.replace("\\n", "\n");
                boolean referenced = Arrays.stream(normalized.split("[\\r\\n]+"))
                        .flatMap(line -> Arrays.stream(line.split("\\s*>\\s*")))
                        .map(String::trim)
                        .anyMatch(token -> token.equals(role.getRoleName()));
                if (referenced) {
                    referencedIn.add(hierarchy.getDescription() != null ? hierarchy.getDescription() : "ID:" + hierarchy.getId());
                }
            }
        });
        if (!referencedIn.isEmpty()) {
            throw new IllegalStateException(msg("msg.role.delete.referenced",
                    role.getRoleName(), String.join(", ", referencedIn)));
        }
        // Counted under the lock taken first and before anything is cleaned up, audited or deleted, so a refusal leaves
        // nothing behind. The database refuses the deletion of a role an account holds, with a constraint nobody can read,
        // and drops a role from the groups that hold it without a word.
        long accounts = roleRepository.countAccountsHolding(id);
        long groups = roleRepository.countGroupsHolding(id);
        if (accounts > 0 || groups > 0) {
            throw new IllegalStateException(msg("msg.role.delete.held", role.getRoleName(), accounts, groups));
        }
        policySynchronizationService.cleanupAutoPolicy(role.getRoleName());
        auditRoleChange(AuditEventCategory.ROLE_DELETED, role);
        roleRepository.deleteById(id);
        lastAdministratorGuard.refuseLosingEveryAdministrator(administrators);
    }

    /**
     * The name a role is given, checked against every other role by the authority it gives (RoleAuthority): a name that
     * differs from another only in case or in the {@code ROLE_} prefix gives the same authority, and one that gives
     * {@code ROLE_ADMIN} without being that role makes its holders administrators of the console.
     *
     * @param ownId the role being renamed, or {@code null} for a new one
     */
    private String newRoleName(String requested, Long ownId) {
        String name = ConsoleInput.required(messageSource, "crud.field.role.name", requested, NAME_LENGTH);
        if (!ROLE_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException(msg("msg.role.name.invalid", name));
        }
        String authority = RoleAuthority.authorityOf(name);
        if (ConsoleSession.ADMIN_AUTHORITY.equalsIgnoreCase(authority) && !ConsoleSession.ADMIN_AUTHORITY.equals(name)) {
            throw new IllegalArgumentException(msg("msg.role.name.reserved", name, ConsoleSession.ADMIN_AUTHORITY));
        }
        String key = authority.toUpperCase(Locale.ROOT);
        for (Role other : roleRepository.findAll()) {
            if (other == null || !StringUtils.hasText(other.getRoleName()) || Objects.equals(other.getId(), ownId)) {
                continue;
            }
            if (other.getRoleName().equals(name)) {
                throw new IllegalArgumentException(msg("msg.role.name.duplicate", name));
            }
            if (RoleAuthority.authorityOf(other.getRoleName()).toUpperCase(Locale.ROOT).equals(key)) {
                throw new IllegalArgumentException(msg("msg.role.name.same.authority", name, other.getRoleName()));
            }
        }
        return name;
    }

    private void auditRoleChange(AuditEventCategory category, Role role) {
        try {
            String principal = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) principal = auth.getName();

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(principal)
                    .resourceIdentifier(role.getRoleName() != null ? role.getRoleName() : "")
                    .eventSource("IAM")
                    .action(category.name())
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of(
                            "roleId", role.getId() != null ? role.getId() : 0L,
                            "roleName", role.getRoleName() != null ? role.getRoleName() : ""))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit role change: {}", role.getRoleName(), e);
        }
    }
}
