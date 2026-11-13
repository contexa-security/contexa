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
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
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
 * Keeps the console from losing its last administrator. An active administrator is an enabled account of Contexa's own
 * (not a copy of an application's user) holding {@code ROLE_ADMIN}: through a role of its own or of one of its groups,
 * the role enabled, or through a role the role hierarchy places above it, as the console's sign-in grants it. A change
 * that takes the last one is refused with {@link LastAdministratorException}, before anything of it is kept. The change
 * is one of a user (its groups, its direct roles, disabling it or deleting it) or one of what the users hold: a role
 * renamed or deleted, a group's roles changed or the group deleted, the role hierarchy rewritten, deleted or switched
 * off.
 * <p>
 * Every such change goes the same way, as the first thing in its transaction: {@link #serializeChanges()} takes the
 * lock that lets one change at a time look at the administrators, then the change is made, then it is checked
 * ({@link #refuseLosingTheLast} and {@link #refuseDeletingTheLast} for a user, {@link #refuseLosingEveryAdministrator}
 * for roles, groups and the hierarchy). Two administrators who take each other's role at the same moment therefore do
 * not both pass: the second reads the state the first left, and is refused.
 * <p>
 * Who is locked out after all signs in again with an account named in the configuration
 * ({@code contexa.iam.seed.admin.*}), which the next start creates.
 */
@Slf4j
public class LastAdministratorGuard {

    /** How many administrators a refusal names. */
    private static final int NAMED_ADMINISTRATORS = 5;

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

    /**
     * Takes the lock every change of who may administer the console goes through, until the end of the transaction: the
     * rows of the roles. A change that waits here reads, once it has the lock, what the change before it left. Call it
     * before anything else is read in the transaction, since what was read earlier is not read again.
     */
    public void serializeChanges() {
        roles.findAllForUpdate();
    }

    /**
     * The enabled accounts of Contexa's own that hold {@code ROLE_ADMIN} now, by user name (at most a few, the first by
     * name): what a change of roles, groups or the hierarchy takes from them is checked against by
     * {@link #refuseLosingEveryAdministrator}. Empty when the console has none.
     */
    public List<String> administrators() {
        return administrators(hierarchy);
    }

    /** Whether the account, as it stands now, is an active administrator of the console. */
    public boolean activeAdministrator(Users user) {
        if (user == null || !user.isEnabled() || user.isBridgeManaged()) {
            return false;
        }
        Set<Long> administratorRoles = administratorRoles(hierarchy);
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

    /**
     * Refuses a change of roles, groups or the role hierarchy that left the console without an active administrator it
     * had before. Call it after the change is made.
     *
     * @param before the administrators from {@link #administrators()}, read before the change; when empty the console
     *               had none and nothing is refused
     * @throws LastAdministratorException when no active administrator remains
     */
    public void refuseLosingEveryAdministrator(List<String> before) {
        refuseLosingEvery(before, hierarchy);
    }

    /**
     * As {@link #refuseLosingEveryAdministrator(List)}, for a change of the role hierarchy: the administrators are read
     * by the hierarchy the change leaves, which is not yet the one the console runs on.
     *
     * @param hierarchyAfterTheChange the hierarchy the change leaves, one relation of {@code A > B} to a line
     */
    public void refuseLosingEveryAdministrator(List<String> before, String hierarchyAfterTheChange) {
        refuseLosingEvery(before, hierarchyOf(hierarchyAfterTheChange));
    }

    private void refuseLosingEvery(List<String> before, RoleHierarchy hierarchyAfter) {
        if (before == null || before.isEmpty() || !administrators(hierarchyAfter).isEmpty()) {
            return;
        }
        log.warn("[RoleManagement] A change that would leave the console without an active administrator was refused: "
                + "administrators={}", before);
        throw new LastAdministratorException(messageForEvery(before));
    }

    /**
     * Refuses a role hierarchy that gives {@code ROLE_ADMIN} to the holders of another role: a relation of
     * {@code A > ROLE_ADMIN}, or a path of relations that ends there, makes everyone who holds {@code A} an administrator
     * of the console. Every role is read, the switched-off ones too, since switching one on would grant it at once.
     *
     * @param hierarchyToCheck one relation of {@code A > B} to a line
     * @throws IllegalArgumentException naming the roles that would grant {@code ROLE_ADMIN}
     */
    public void refuseRolesAboveAdministrator(String hierarchyToCheck) {
        if (hierarchyToCheck == null || hierarchyToCheck.isBlank()) {
            return;
        }
        RoleHierarchy candidate = hierarchyOf(hierarchyToCheck);
        List<String> raised = roles.findAll().stream()
                .filter(role -> role != null && StringUtils.hasText(role.getRoleName()))
                .map(Role::getRoleName)
                .filter(name -> !ConsoleSession.ADMIN_AUTHORITY.equals(RoleAuthority.authorityOf(name)))
                .filter(name -> grantsAdministrator(name, candidate))
                .sorted()
                .toList();
        if (raised.isEmpty()) {
            return;
        }
        log.warn("[RoleManagement] A role hierarchy that would give ROLE_ADMIN to the holders of other roles was "
                + "refused: roles={}", raised);
        String names = String.join(", ", raised);
        String fallback = "No role can be placed above " + ConsoleSession.ADMIN_AUTHORITY + ": this hierarchy would give "
                + ConsoleSession.ADMIN_AUTHORITY + " to the holders of " + names + ".";
        throw new IllegalArgumentException(messages == null ? fallback : messages.getMessage(
                "msg.role.hierarchy.above.admin", new Object[]{names}, fallback, LocaleContextHolder.getLocale()));
    }

    private static RoleHierarchy hierarchyOf(String hierarchy) {
        String lines = hierarchy == null ? "" : hierarchy.replace("\\n", "\n");
        return RoleHierarchyImpl.fromHierarchy(lines);
    }

    private List<String> administrators(RoleHierarchy hierarchyToRead) {
        Set<Long> administratorRoles = administratorRoles(hierarchyToRead);
        if (administratorRoles.isEmpty()) {
            return List.of();
        }
        return users.findEnabledOwnUsernamesHoldingAnyRole(administratorRoles, PageRequest.of(0, NAMED_ADMINISTRATORS));
    }

    private void refuseUnlessAnotherRemains(Users user) {
        Set<Long> administratorRoles = administratorRoles(hierarchy);
        if (!administratorRoles.isEmpty()
                && users.countEnabledOwnAccountsHoldingAnyRole(user.getId(), administratorRoles) > 0) {
            return;
        }
        log.warn("[UserManagement] A change of the console's last active administrator was refused: username={}",
                user.getUsername());
        throw new LastAdministratorException(message(user.getUsername()));
    }

    /** The enabled roles that grant {@code ROLE_ADMIN}, themselves or through the role hierarchy. */
    private Set<Long> administratorRoles(RoleHierarchy hierarchyToRead) {
        return roles.findAll().stream()
                .filter(role -> role != null && role.getId() != null && role.isEnabled()
                        && StringUtils.hasText(role.getRoleName()))
                .filter(role -> grantsAdministrator(role.getRoleName(), hierarchyToRead))
                .map(Role::getId)
                .collect(Collectors.toSet());
    }

    private static boolean grantsAdministrator(String roleName, RoleHierarchy hierarchyToRead) {
        String authority = RoleAuthority.authorityOf(roleName);
        if (ConsoleSession.ADMIN_AUTHORITY.equals(authority)) {
            return true;
        }
        return hierarchyToRead.getReachableGrantedAuthorities(List.of(new SimpleGrantedAuthority(authority))).stream()
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

    private String messageForEvery(List<String> administrators) {
        String names = String.join(", ", administrators);
        String fallback = "This change would leave the console without an active administrator: " + names
                + " would no longer hold ROLE_ADMIN. Give the role to another account first.";
        if (messages == null) {
            return fallback;
        }
        return messages.getMessage("msg.admin.last.administrators", new Object[]{names}, fallback,
                LocaleContextHolder.getLocale());
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
