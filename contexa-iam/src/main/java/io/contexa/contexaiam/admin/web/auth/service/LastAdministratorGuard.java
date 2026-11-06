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

import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Keeps the console from losing its last administrator through a change of a user. An active administrator is an
 * enabled account of Contexa's own (not a copy of an application's user) holding {@code ROLE_ADMIN}: through a role of
 * its own or of one of its groups, the role enabled, or through a role the role hierarchy places above it, as the
 * console's sign-in grants it. A change that takes the last one (its groups, its direct roles, disabling it or deleting
 * it) is refused with {@link LastAdministratorException}, before anything of it is kept.
 * <p>
 * Changes of roles and groups themselves (a role disabled, the hierarchy rewritten, a group's roles changed) are not
 * read here. Who is locked out after all signs in again with another account named in the configuration
 * ({@code contexa.iam.seed.admin.*}), which the next start creates.
 */
@Slf4j
public class LastAdministratorGuard {

    private final UserRepository users;
    private final RoleRepository roles;
    private final RoleHierarchy hierarchy;
    private final MessageSource messages;

    public LastAdministratorGuard(UserRepository users, RoleRepository roles, RoleHierarchy hierarchy,
                                  MessageSource messages) {
        this.users = Objects.requireNonNull(users, "users");
        this.roles = Objects.requireNonNull(roles, "roles");
        this.hierarchy = Objects.requireNonNull(hierarchy, "hierarchy");
        this.messages = messages;
    }

    /** Whether the account, as it stands now, is an active administrator of the console. */
    public boolean activeAdministrator(Users user) {
        if (user == null || !user.isEnabled() || user.isBridgeManaged()) {
            return false;
        }
        Set<Long> administratorRoles = administratorRoles();
        return heldRoles(user).stream().anyMatch(administratorRoles::contains);
    }

    /**
     * Refuses the change made to the user when it took the console's last active administrator.
     *
     * @param wasActiveAdministrator whether the user was one before the change
     * @throws LastAdministratorException when no other active administrator remains
     */
    public void refuseLosingTheLast(Users changed, boolean wasActiveAdministrator) {
        if (wasActiveAdministrator && !activeAdministrator(changed)) {
            refuseUnlessAnotherRemains(changed);
        }
    }

    /**
     * Refuses the deletion of the console's last active administrator.
     *
     * @throws LastAdministratorException when no other active administrator remains
     */
    public void refuseDeletingTheLast(Users user) {
        if (activeAdministrator(user)) {
            refuseUnlessAnotherRemains(user);
        }
    }

    private void refuseUnlessAnotherRemains(Users user) {
        Set<Long> administratorRoles = administratorRoles();
        if (!administratorRoles.isEmpty()
                && users.countEnabledOwnAccountsHoldingAnyRole(user.getId(), administratorRoles) > 0) {
            return;
        }
        log.warn("[UserManagement] A change of the console's last active administrator was refused: username={}",
                user.getUsername());
        throw new LastAdministratorException(message(user.getUsername()));
    }

    /** The enabled roles that grant {@code ROLE_ADMIN}, themselves or through the role hierarchy. */
    private Set<Long> administratorRoles() {
        return roles.findAll().stream()
                .filter(role -> role != null && role.getId() != null && role.isEnabled()
                        && StringUtils.hasText(role.getRoleName()))
                .filter(role -> grantsAdministrator(role.getRoleName()))
                .map(Role::getId)
                .collect(Collectors.toSet());
    }

    private boolean grantsAdministrator(String roleName) {
        String authority = RoleAuthority.authorityOf(roleName);
        if (ConsoleSession.ADMIN_AUTHORITY.equals(authority)) {
            return true;
        }
        return hierarchy.getReachableGrantedAuthorities(List.of(new SimpleGrantedAuthority(authority))).stream()
                .anyMatch(reached -> ConsoleSession.ADMIN_AUTHORITY.equals(reached.getAuthority()));
    }

    /** The enabled roles the user holds, directly and through its groups. */
    private static Set<Long> heldRoles(Users user) {
        Stream<Role> direct = Optional.ofNullable(user.getUserRoles()).orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole);
        Stream<Role> grouped = Optional.ofNullable(user.getUserGroups()).orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles())
                        .<Collection<GroupRole>>map(groupRoles -> groupRoles).orElse(Collections.emptySet()).stream())
                .map(GroupRole::getRole);
        Set<Long> held = new HashSet<>();
        Stream.concat(direct, grouped)
                .filter(role -> role != null && role.getId() != null && role.isEnabled())
                .forEach(role -> held.add(role.getId()));
        return held;
    }

    private String message(String username) {
        String fallback = "This change would leave the console without an active administrator: " + username
                + " is the last enabled account holding ROLE_ADMIN. Give the role to another account first.";
        if (messages == null) {
            return fallback;
        }
        return messages.getMessage("msg.user.last.administrator", new Object[]{username}, fallback,
                LocaleContextHolder.getLocale());
    }
}
