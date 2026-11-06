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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.repository.UserRoleRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorException;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.impl.GroupServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.UserManagementServiceImpl;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleAssignmentsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateUserGroupsRequest;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * The console keeps an active administrator on a real PostgreSQL database: two administrators who demote each other
 * at the same moment do not both succeed, and no edit of a role, a group or the role hierarchy takes the
 * {@code ROLE_ADMIN} of the last administrator. An edit that leaves another administrator, and an edit that touches
 * nothing the administrator holds, go through as before.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ConsoleAdministratorsPostgresTest {

    private static PostgresTestDatabase database;
    private static LocalContainerEntityManagerFactoryBean entityManagers;
    private static TransactionTemplate transactions;
    private static JdbcTemplate jdbc;
    private static RoleHierarchyImpl hierarchy;
    private static UserManagementServiceImpl userManagement;
    private static AccessCenterService accessCenter;
    private static RoleServiceImpl roleService;
    private static GroupServiceImpl groupService;
    private static RoleHierarchyService hierarchyService;

    /** Where the two edits of a race meet before either has finished: set by the test that races. */
    private static final AtomicReference<CyclicBarrier> MEETING = new AtomicReference<>();

    private long adminRole;
    private long userRole;
    private long ops;
    private long staff;
    private long alice;
    private long bob;

    @BeforeAll
    static void aConsoleOnTheCanonicalSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));

        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa");
        entityManagers.setPackagesToScan("io.contexa.contexacommon.entity", "io.contexa.contexaiam.domain.entity");
        entityManagers.setJpaPropertyMap(Map.of(
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy",
                "hibernate.implicit_naming_strategy",
                "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        entityManagers.afterPropertiesSet();
        transactions = new TransactionTemplate(new JpaTransactionManager(entityManagers.getObject()));
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagers.getObject());
        JpaRepositoryFactory repositories = new JpaRepositoryFactory(entityManager);

        UserRepository users = meeting(repositories.getRepository(UserRepository.class));
        GroupRepository groups = repositories.getRepository(GroupRepository.class);
        RoleRepository roles = repositories.getRepository(RoleRepository.class);
        RoleHierarchyRepository hierarchies = repositories.getRepository(RoleHierarchyRepository.class);
        PermissionRepository permissions = repositories.getRepository(PermissionRepository.class);
        UserRolePermissionRepository userRolePermissions = repositories.getRepository(UserRolePermissionRepository.class);
        GroupRolePermissionRepository groupRolePermissions = repositories.getRepository(GroupRolePermissionRepository.class);
        hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("");
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setUseCodeAsDefaultMessage(true);
        messages.setFallbackToSystemLocale(false);
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        LastAdministratorGuard guard = new LastAdministratorGuard(users, roles, hierarchy, messages);
        roleService = new RoleServiceImpl(roles, permissions, mock(IntegrationEventBus.class),
                mock(CentralAuditFacade.class), hierarchies, mock(PolicyRepository.class),
                mock(PolicySynchronizationService.class), messages, guard);
        groupService = new GroupServiceImpl(groups, roles, hierarchies, messages, guard);
        hierarchyService = new RoleHierarchyService(hierarchies, roles, hierarchy, messages, guard);
        userManagement = new UserManagementServiceImpl(users, groups, roles, mock(PasswordEncoder.class),
                new ModelMapper(), mock(CentralAuditFacade.class), mock(PasswordPolicyService.class),
                mock(SystemSettingsService.class), messages, userRolePermissions,
                repositories.getRepository(BridgeUserProfileRepository.class), mock(ApplicationEventPublisher.class),
                guard);
        accessCenter = new AccessCenterService(users, repositories.getRepository(UserRoleRepository.class), groups,
                roles, permissions, roleService, userRolePermissions, groupRolePermissions, guard);
        warmUp();
    }

    /** The first edits of a JVM take long enough to make two racing edits miss each other: they go first. */
    private static void warmUp() {
        long warm = group("warm", role("ROLE_WARM"));
        long first = user("warm1");
        long second = user("warm2");
        userGroup(first, warm);
        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(first, "warm1")));
        transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(second, groups(warm)));
        transactions.executeWithoutResult(s -> accessCenter.updateUserDirectRoles(second, roleIds()));
        transactions.executeWithoutResult(s -> userManagement.deleteUser(first));
    }

    @AfterAll
    static void close() {
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void anEmptyConsole() {
        MEETING.set(null);
        jdbc.execute("truncate ctxa_user_roles, ctxa_user_groups, ctxa_group_roles, ctxa_users, ctxa_role, "
                + "ctxa_app_group, ctxa_role_hierarchy_config restart identity cascade");
        hierarchy.setHierarchy("");
        adminRole = role("ROLE_ADMIN");
        userRole = role("ROLE_USER");
        ops = group("ops", adminRole);
        staff = group("staff", userRole);
        alice = user("alice");
        bob = user("bob");
        userGroup(alice, ops);
        userGroup(bob, staff);
    }

    // ----- two administrators who demote each other at the same moment -----

    @Test
    @DisplayName("two administrators who take each other's group at the same moment do not both succeed")
    void twoAdministratorsDemoteEachOtherThroughTheirGroups() throws Exception {
        long ops2 = group("ops2", adminRole);
        userGroup(bob, ops2);
        meetBeforeEitherFinishes();

        List<Throwable> outcomes = concurrently(
                () -> transactions.executeWithoutResult(s -> userManagement.modifyUser(form(bob, "bob"))),
                () -> transactions.executeWithoutResult(s -> userManagement.modifyUser(form(alice, "alice"))));

        assertExactlyOneWasRefused(outcomes);
        assertThat(administrators()).hasSize(1);
    }

    @Test
    @DisplayName("two administrators who delete each other at the same moment do not both succeed")
    void twoAdministratorsDeleteEachOther() throws Exception {
        long ops2 = group("ops2", adminRole);
        userGroup(bob, ops2);
        meetBeforeEitherFinishes();

        List<Throwable> outcomes = concurrently(
                () -> transactions.executeWithoutResult(s -> userManagement.deleteUser(bob)),
                () -> transactions.executeWithoutResult(s -> userManagement.deleteUser(alice)));

        assertExactlyOneWasRefused(outcomes);
        assertThat(administrators()).hasSize(1);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_users where username in ('alice', 'bob')",
                Integer.class)).isEqualTo(1);
    }

    @Test
    @DisplayName("two administrators who take each other's groups in the access center at the same moment do not both succeed")
    void twoAdministratorsDemoteEachOtherInTheAccessCenter() throws Exception {
        long ops2 = group("ops2", adminRole);
        userGroup(bob, ops2);
        meetBeforeEitherFinishes();

        List<Throwable> outcomes = concurrently(
                () -> transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(bob, groups())),
                () -> transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(alice, groups())));

        assertExactlyOneWasRefused(outcomes);
        assertThat(administrators()).hasSize(1);
    }

    @Test
    @DisplayName("an administrator who gives up the role and another who gives up the group at the same moment do not both succeed")
    void aDirectRoleAndAGroupGoAtTheSameMoment() throws Exception {
        userRole(bob, adminRole);
        meetBeforeEitherFinishes();

        List<Throwable> outcomes = concurrently(
                () -> transactions.executeWithoutResult(s -> accessCenter.updateUserDirectRoles(bob, roleIds())),
                () -> transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(alice, groups())));

        assertExactlyOneWasRefused(outcomes);
        assertThat(administrators()).hasSize(1);
    }

    // ----- edits of roles, groups and the role hierarchy that would take the last administrator -----

    @Test
    @DisplayName("renaming the role of the last administrator is refused")
    void renamingTheAdministratorRole() {
        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> roleService.updateRole(
                Role.builder().id(adminRole).roleName("ROLE_ROOT").roleDesc("renamed").build(), List.of())));
    }

    @Test
    @DisplayName("deleting the role of the last administrator is refused: the group of the administrator holds it")
    void deletingTheAdministratorRole() {
        assertThatThrownBy(() -> transactions.executeWithoutResult(s -> roleService.deleteRole(adminRole)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("held by 0 account(s) and 1 group(s)");

        assertThat(administrators()).containsExactly("alice");
        assertThat(jdbc.queryForObject("select count(*) from ctxa_role where role_name = 'ROLE_ADMIN'", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_group_roles where group_id = ? and role_id = ?",
                Integer.class, ops, adminRole)).isEqualTo(1);
    }

    @Test
    @DisplayName("taking the role from the group of the last administrator is refused")
    void takingTheRoleFromTheGroup() {
        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> groupService.updateGroup(
                Group.builder().id(ops).name("ops").build(), List.of())));
    }

    @Test
    @DisplayName("deleting the group of the last administrator is refused")
    void deletingTheGroup() {
        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> groupService.deleteGroup(ops)));
        assertThat(jdbc.queryForObject("select count(*) from ctxa_app_group where group_name = 'ops'", Integer.class))
                .isEqualTo(1);
    }

    @Test
    @DisplayName("taking the role from the group in the access center is refused")
    void takingTheRoleFromTheGroupInTheAccessCenter() {
        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(
                s -> accessCenter.updateGroupRoles(ops, roleIds())));
    }

    @Test
    @DisplayName("an administrator by the role hierarchy loses it when the hierarchy is rewritten, deleted or switched off: refused")
    void editingTheRoleHierarchyThatMakesTheAdministrator() {
        long superRole = role("ROLE_SUPER");
        long supers = group("supers", superRole);
        userGroup(alice, supers);
        jdbc.update("delete from ctxa_user_groups where user_id = ? and group_id = ?", alice, ops);
        long line = hierarchyLine("ROLE_SUPER > ROLE_ADMIN");

        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> hierarchyService.updateRoleHierarchy(
                RoleHierarchyEntity.builder().id(line).hierarchyString("ROLE_SUPER > ROLE_USER").isActive(true)
                        .build())));
        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> hierarchyService.deleteRoleHierarchy(line)));
        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> hierarchyService.activateRoleHierarchy(line)));

        // The refusals rolled back, and the hierarchy the console runs on is still the one stored.
        assertThat(hierarchy.getReachableGrantedAuthorities(List.of(new SimpleGrantedAuthority("ROLE_SUPER"))))
                .extracting(Object::toString).contains("ROLE_ADMIN");
        assertThat(jdbc.queryForObject("select is_active from ctxa_role_hierarchy_config where hierarchy_id = ?",
                Boolean.class, line)).isTrue();
    }

    @Test
    @DisplayName("renaming the role that makes the last administrator by the hierarchy is refused")
    void renamingTheRoleTheHierarchyNames() {
        long superRole = role("ROLE_SUPER");
        long supers = group("supers", superRole);
        userGroup(alice, supers);
        jdbc.update("delete from ctxa_user_groups where user_id = ? and group_id = ?", alice, ops);
        hierarchyLine("ROLE_SUPER > ROLE_ADMIN");

        assertRefusedAndNothingKept(() -> transactions.executeWithoutResult(s -> roleService.updateRole(
                Role.builder().id(superRole).roleName("ROLE_BOSS").build(), List.of())));
    }

    // ----- what stays as it was -----

    @Test
    @DisplayName("a role an account holds directly is refused with who holds it, not with the constraint of the database")
    void aRoleHeldDirectlyIsRefusedWithWhoHoldsIt() {
        long direct = role("ROLE_DIRECT");
        userRole(bob, direct);

        assertThatThrownBy(() -> transactions.executeWithoutResult(s -> roleService.deleteRole(direct)))
                .isInstanceOf(IllegalStateException.class).isNotInstanceOf(LastAdministratorException.class)
                .hasMessage("Cannot delete role 'ROLE_DIRECT'. It is held by 1 account(s) and 0 group(s). "
                        + "Revoke it from them first.");

        assertThat(jdbc.queryForObject("select count(*) from ctxa_role where role_name = 'ROLE_DIRECT'", Integer.class))
                .isEqualTo(1);
        assertThat(administrators()).containsExactly("alice");
    }

    @Test
    @DisplayName("a role held by accounts and by groups says how many of each, and goes once they hold it no more")
    void aRoleHeldByBothIsDeletedOnceRevoked() {
        long shared = role("ROLE_SHARED");
        userRole(bob, shared);
        userRole(alice, shared);
        long team = group("team", shared);

        assertThatThrownBy(() -> transactions.executeWithoutResult(s -> roleService.deleteRole(shared)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("held by 2 account(s) and 1 group(s)");

        jdbc.update("delete from ctxa_user_roles where role_id = ?", shared);
        jdbc.update("delete from ctxa_group_roles where group_id = ?", team);
        transactions.executeWithoutResult(s -> roleService.deleteRole(shared));

        assertThat(jdbc.queryForObject("select count(*) from ctxa_role where role_name = 'ROLE_SHARED'", Integer.class))
                .isZero();
    }

    @Test
    @DisplayName("with another administrator the same edits go through")
    void withAnotherAdministratorTheEditsGoThrough() {
        long ops2 = group("ops2", adminRole);
        userGroup(bob, ops2);

        transactions.executeWithoutResult(s -> groupService.updateGroup(
                Group.builder().id(ops).name("ops").build(), List.of()));
        assertThat(administrators()).containsExactly("bob");
        transactions.executeWithoutResult(s -> groupService.deleteGroup(ops));
        transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(alice, groups()));
        assertThat(administrators()).containsExactly("bob");
        // Bob is the last one now, and the group he is in holds the role: it is not deleted.
        assertThatThrownBy(() -> transactions.executeWithoutResult(s -> roleService.deleteRole(adminRole)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("held by 0 account(s) and 1 group(s)");
        assertThat(administrators()).containsExactly("bob");
    }

    @Test
    @DisplayName("an edit of what the last administrator does not hold goes through")
    void anEditOfWhatTheAdministratorDoesNotHold() {
        transactions.executeWithoutResult(s -> roleService.updateRole(
                Role.builder().id(userRole).roleName("ROLE_MEMBER").roleDesc("renamed").build(), List.of()));
        transactions.executeWithoutResult(s -> groupService.updateGroup(
                Group.builder().id(staff).name("staff").build(), List.of(userRole, adminRole)));
        transactions.executeWithoutResult(s -> groupService.deleteGroup(staff));
        transactions.executeWithoutResult(s -> roleService.deleteRole(userRole));
        // Adding to what the administrator holds is not a loss either.
        transactions.executeWithoutResult(s -> groupService.updateGroup(
                Group.builder().id(ops).name("ops").build(), List.of(adminRole, role("ROLE_AUDITOR"))));

        assertThat(administrators()).containsExactly("alice");
    }

    // ----- an edit of an account that keeps groups it already has -----

    @Test
    @DisplayName("editing an account that keeps the two groups it has keeps both")
    void anAccountKeepsTheTwoGroupsItIsEditedWith() {
        long extra = group("extra");
        userGroup(bob, extra);

        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(bob, "bob", staff, extra)));

        assertThat(groupsOf(bob)).containsExactlyInAnyOrder(staff, extra);
    }

    @Test
    @DisplayName("editing an account that keeps its one group keeps it")
    void anAccountKeepsTheOneGroupItIsEditedWith() {
        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(bob, "bob", staff)));

        assertThat(groupsOf(bob)).containsExactly(staff);
    }

    @Test
    @DisplayName("editing an account that keeps one of its groups, drops one and takes one changes exactly those")
    void anAccountKeepsOneGroupDropsOneAndTakesOne() {
        long extra = group("extra");
        long other = group("other");
        userGroup(bob, extra);

        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(bob, "bob", staff, other)));

        assertThat(groupsOf(bob)).containsExactlyInAnyOrder(staff, other);
    }

    @Test
    @DisplayName("editing the last administrator who keeps the two groups the account has keeps both")
    void anAdministratorKeepsTheTwoGroupsItIsEditedWith() {
        long extra = group("extra");
        userGroup(alice, extra);

        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(alice, "alice", ops, extra)));

        assertThat(groupsOf(alice)).containsExactlyInAnyOrder(ops, extra);
        assertThat(administrators()).containsExactly("alice");
    }

    @Test
    @DisplayName("editing the last administrator who keeps the one group the account has keeps it")
    void anAdministratorKeepsTheOneGroupItIsEditedWith() {
        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(alice, "alice", ops)));

        assertThat(groupsOf(alice)).containsExactly(ops);
        assertThat(administrators()).containsExactly("alice");
    }

    @Test
    @DisplayName("an administrator who gives up one of two groups and keeps the one that makes it an administrator keeps just that one")
    void anAdministratorGivesUpTheGroupThatIsNotTheAdministrators() {
        long extra = group("extra");
        userGroup(alice, extra);

        transactions.executeWithoutResult(s -> userManagement.modifyUser(form(alice, "alice", ops)));

        assertThat(groupsOf(alice)).containsExactly(ops);
    }

    @Test
    @DisplayName("the direct role of the last administrator is kept by an edit that keeps it")
    void anAdministratorKeepsItsDirectRole() {
        userRole(alice, adminRole);

        transactions.executeWithoutResult(s -> accessCenter.updateUserDirectRoles(alice, roleIds(adminRole)));

        assertThat(jdbc.queryForList("select role_id from ctxa_user_roles where user_id = ?", Long.class, alice))
                .containsExactly(adminRole);
    }

    @Test
    @DisplayName("the role of the group of the last administrator is kept by an edit that keeps it")
    void aGroupKeepsItsAdministratorRole() {
        transactions.executeWithoutResult(s -> accessCenter.updateGroupRoles(ops, roleIds(adminRole)));
        transactions.executeWithoutResult(s -> groupService.updateGroup(Group.builder().id(ops).name("ops").build(),
                List.of(adminRole)));

        assertThat(jdbc.queryForList("select role_id from ctxa_group_roles where group_id = ?", Long.class, ops))
                .containsExactly(adminRole);
        assertThat(administrators()).containsExactly("alice");
    }

    @Test
    @DisplayName("the groups of the last administrator in the access center are kept the same way")
    void theAccessCenterKeepsTheGroupsOfAnAdministratorToo() {
        long extra = group("extra");
        userGroup(alice, extra);

        transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(alice, groups(ops, extra)));

        assertThat(groupsOf(alice)).containsExactlyInAnyOrder(ops, extra);
        assertThat(administrators()).containsExactly("alice");
    }

    @Test
    @DisplayName("the groups of an account in the access center are kept the same way")
    void theAccessCenterKeepsTheGroupsToo() {
        long extra = group("extra");
        userGroup(bob, extra);

        transactions.executeWithoutResult(s -> accessCenter.updateUserGroups(bob, groups(staff, extra)));

        assertThat(groupsOf(bob)).containsExactlyInAnyOrder(staff, extra);
    }

    @Test
    @DisplayName("the two direct roles of an account in the access center are kept the same way")
    void theAccessCenterKeepsTheDirectRolesToo() {
        long first = role("ROLE_FIRST");
        long second = role("ROLE_SECOND");
        userRole(bob, first);
        userRole(bob, second);

        transactions.executeWithoutResult(s -> accessCenter.updateUserDirectRoles(bob, roleIds(first, second)));

        assertThat(jdbc.queryForList("select role_id from ctxa_user_roles where user_id = ? order by 1", Long.class, bob))
                .containsExactlyInAnyOrder(first, second);
    }

    // ----- deletions that reach what is assigned to the group -----

    @Test
    @DisplayName("a group whose roles were given with their permissions in the access center is deleted with them")
    void aGroupWithRolePermissionsIsDeleted() {
        long read = jdbc.queryForObject("insert into ctxa_permission (permission_name) values ('READ') returning permission_id",
                Long.class);
        long sales = role("ROLE_SALES");
        long team = group("team");
        AccessCenterDtos.AccessRoleAssignmentRequest assignment = new AccessCenterDtos.AccessRoleAssignmentRequest();
        assignment.setRoleId(sales);
        assignment.setCrudPermissions(List.of("READ"));
        AccessRoleAssignmentsRequest request = new AccessRoleAssignmentsRequest();
        request.setRoleAssignments(List.of(assignment));
        transactions.executeWithoutResult(s -> accessCenter.updateGroupRoles(team, request));
        assertThat(jdbc.queryForObject("select count(*) from ctxa_group_role_permissions where group_id = ? and permission_id = ?",
                Integer.class, team, read)).isEqualTo(1);

        transactions.executeWithoutResult(s -> groupService.deleteGroup(team));

        assertThat(jdbc.queryForObject("select count(*) from ctxa_app_group where group_name = 'team'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_group_role_permissions where group_id = ?", Integer.class,
                team)).isZero();
    }

    // ----- helpers -----

    private static List<Long> groupsOf(long userId) {
        return jdbc.queryForList("select group_id from ctxa_user_groups where user_id = ? order by 1", Long.class, userId);
    }

    private void assertRefusedAndNothingKept(Runnable edit) {
        List<String> before = administrators();
        assertThat(before).containsExactly("alice");
        List<Map<String, Object>> rolesBefore = jdbc.queryForList("select role_id, role_name from ctxa_role order by 1");
        List<Map<String, Object>> holdingsBefore = jdbc.queryForList(
                "select group_id, role_id from ctxa_group_roles order by 1, 2");
        List<Map<String, Object>> hierarchiesBefore = jdbc.queryForList(
                "select hierarchy_id, hierarchy_string, is_active from ctxa_role_hierarchy_config order by 1");

        assertThatThrownBy(edit::run).isInstanceOf(LastAdministratorException.class)
                .hasMessageContaining("without an active administrator").hasMessageContaining("alice");

        assertThat(administrators()).isEqualTo(before);
        assertThat(jdbc.queryForList("select role_id, role_name from ctxa_role order by 1")).isEqualTo(rolesBefore);
        assertThat(jdbc.queryForList("select group_id, role_id from ctxa_group_roles order by 1, 2"))
                .isEqualTo(holdingsBefore);
        assertThat(jdbc.queryForList(
                "select hierarchy_id, hierarchy_string, is_active from ctxa_role_hierarchy_config order by 1"))
                .isEqualTo(hierarchiesBefore);
    }

    private void assertExactlyOneWasRefused(List<Throwable> outcomes) {
        assertThat(administrators()).as("administrators left in the console").isNotEmpty();
        assertThat(outcomes).hasSize(2);
        assertThat(outcomes.stream().filter(outcome -> outcome == null)).as("edits that went through").hasSize(1);
        assertThat(outcomes.stream().filter(outcome -> outcome instanceof LastAdministratorException))
                .as("edits refused, outcomes: " + outcomes).hasSize(1);
    }

    /** The two edits of the next race reach the check of the last administrator together, when they can. */
    private void meetBeforeEitherFinishes() {
        MEETING.set(new CyclicBarrier(2));
    }

    /**
     * The user repository the guard counts through: while a race is set up, the first count of each edit waits for the
     * other edit's count, so that both look before either has finished. An edit that cannot get there because the
     * other holds the console's lock stops waiting after a moment.
     */
    private static UserRepository meeting(UserRepository real) {
        return (UserRepository) Proxy.newProxyInstance(UserRepository.class.getClassLoader(),
                new Class<?>[]{UserRepository.class}, (proxy, method, args) -> {
                    if (method.getName().equals("countEnabledOwnAccountsHoldingAnyRole")) {
                        CyclicBarrier barrier = MEETING.get();
                        if (barrier != null) {
                            try {
                                barrier.await(5, TimeUnit.SECONDS);
                            } catch (TimeoutException | BrokenBarrierException ignored) {
                                // the other edit is not coming: it waits for the console's lock
                            }
                        }
                    }
                    try {
                        return method.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    private static List<Throwable> concurrently(Runnable first, Runnable second) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Throwable>> futures = new ArrayList<>();
            for (Runnable edit : List.of(first, second)) {
                Callable<Throwable> task = () -> {
                    go.await();
                    try {
                        edit.run();
                        return null;
                    } catch (Throwable t) {
                        return t;
                    }
                };
                futures.add(executor.submit(task));
            }
            go.countDown();
            List<Throwable> outcomes = new ArrayList<>();
            for (Future<Throwable> future : futures) {
                outcomes.add(future.get(60, TimeUnit.SECONDS));
            }
            return outcomes;
        } finally {
            executor.shutdownNow();
        }
    }

    /** The enabled accounts of Contexa's own holding ROLE_ADMIN, directly or through a group, by user name. */
    private static List<String> administrators() {
        return jdbc.queryForList("select distinct u.username from ctxa_users u "
                + "left join ctxa_user_roles ur on ur.user_id = u.id "
                + "left join ctxa_user_groups ug on ug.user_id = u.id "
                + "left join ctxa_group_roles gr on gr.group_id = ug.group_id "
                + "join ctxa_role r on r.role_id in (ur.role_id, gr.role_id) and r.enabled and r.role_name in ('ROLE_ADMIN', 'ROLE_SUPER') "
                + "where u.enabled and not u.bridge_managed order by 1", String.class);
    }

    private static UserDto form(long id, String username, long... groupIds) {
        UserDto form = new UserDto();
        form.setId(id);
        form.setUsername(username);
        form.setName(username);
        form.setEmail(username + "@console.example");
        form.setEnabled(true);
        form.setSelectedGroupIds(Arrays.stream(groupIds).boxed().toList());
        return form;
    }

    private static UpdateUserGroupsRequest groups(long... groupIds) {
        UpdateUserGroupsRequest request = new UpdateUserGroupsRequest();
        request.setGroupIds(Arrays.stream(groupIds).boxed().toList());
        return request;
    }

    private static AccessRoleAssignmentsRequest roleIds(long... roleIds) {
        AccessRoleAssignmentsRequest request = new AccessRoleAssignmentsRequest();
        request.setRoleIds(Arrays.stream(roleIds).boxed().toList());
        return request;
    }

    private static long role(String name) {
        return jdbc.queryForObject("insert into ctxa_role (role_name) values (?) returning role_id", Long.class, name);
    }

    private static long group(String name, long... roleIds) {
        long id = jdbc.queryForObject("insert into ctxa_app_group (group_name) values (?) returning group_id", Long.class,
                name);
        for (long roleId : roleIds) {
            jdbc.update("insert into ctxa_group_roles (group_id, role_id) values (?, ?)", id, roleId);
        }
        return id;
    }

    private static long user(String username) {
        return jdbc.queryForObject("insert into ctxa_users (username, email, password, name) values (?, ?, 'x', ?) "
                + "returning id", Long.class, username, username + "@console.example", username);
    }

    private static void userGroup(long userId, long groupId) {
        jdbc.update("insert into ctxa_user_groups (user_id, group_id) values (?, ?)", userId, groupId);
    }

    private static void userRole(long userId, long roleId) {
        jdbc.update("insert into ctxa_user_roles (user_id, role_id, assigned_at) values (?, ?, current_timestamp)", userId,
                roleId);
    }

    private static long hierarchyLine(String hierarchyString) {
        long id = jdbc.queryForObject("insert into ctxa_role_hierarchy_config (hierarchy_string, is_active) "
                + "values (?, true) returning hierarchy_id", Long.class, hierarchyString);
        hierarchy.setHierarchy(hierarchyString);
        return id;
    }
}
