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

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.repository.PasswordHistoryRepository;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.repository.UserRoleRepository;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorException;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.impl.GroupServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.PermissionServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleServiceImpl;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateUserGroupsRequest;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.ChangeRecord;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * K75 and K76 on a real PostgreSQL database, through the console's services in transactions: a change of a group, a
 * permission, a role hierarchy, a role assignment of the access center, the password policy and the system settings
 * is audited once it is committed, with its category, action, actor and target, and the dashboard's recent admin
 * changes count it by its kind; a change the last administrator's guard refuses records nothing, nor does a save that
 * changed nothing. A change of the policy's days says at once which accounts are past their password.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class AdminChangeAuditPostgresTest {

    private static PostgresTestDatabase database;
    private static LocalContainerEntityManagerFactoryBean entityManagers;
    private static TransactionTemplate transactions;
    private static JdbcTemplate jdbc;
    private static RoleHierarchyImpl hierarchy;
    private static GroupServiceImpl groupService;
    private static PermissionServiceImpl permissionService;
    private static RoleHierarchyService hierarchyService;
    private static AccessCenterService accessCenter;
    private static PasswordPolicyService passwordPolicy;
    private static SystemSettingsService systemSettings;

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
        entityManagers.setPersistenceUnitName("contexa-admin-audit");
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
        UserRepository users = repositories.getRepository(UserRepository.class);
        GroupRepository groups = repositories.getRepository(GroupRepository.class);
        RoleRepository roles = repositories.getRepository(RoleRepository.class);
        RoleHierarchyRepository hierarchies = repositories.getRepository(RoleHierarchyRepository.class);
        PermissionRepository permissions = repositories.getRepository(PermissionRepository.class);
        hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("");
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setUseCodeAsDefaultMessage(true);
        messages.setFallbackToSystemLocale(false);
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        CentralAuditFacade audit = mock(CentralAuditFacade.class);
        // The facade writes the record as the audit log keeps it; a call before the commit would show as a row of a
        // change that rolled back.
        doAnswer(call -> {
            AuditRecord record = call.getArgument(0);
            jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision, "
                            + "outcome, event_category, event_source) values (?, ?, ?, ?, ?, ?, ?, ?)",
                    Timestamp.valueOf(record.getTimestamp()), record.getPrincipalName(),
                    record.getResourceIdentifier(), record.getAction(), record.getDecision(), record.getOutcome(),
                    record.getEventCategory().name(), record.getEventSource());
            return null;
        }).when(audit).recordAsync(any());

        LastAdministratorGuard guard = new LastAdministratorGuard(users, roles, hierarchy, messages);
        RoleServiceImpl roleService = new RoleServiceImpl(roles, permissions, mock(IntegrationEventBus.class),
                mock(CentralAuditFacade.class), hierarchies, mock(PolicyRepository.class),
                mock(PolicySynchronizationService.class), messages, guard);
        groupService = new GroupServiceImpl(groups, roles, hierarchies, messages, guard);
        groupService.setCentralAuditFacade(audit);
        permissionService = new PermissionServiceImpl(permissions, mock(ManagedResourceRepository.class),
                mock(PolicyRepository.class), messages, guard);
        permissionService.setCentralAuditFacade(audit);
        hierarchyService = new RoleHierarchyService(hierarchies, roles, hierarchy, messages, guard);
        hierarchyService.setCentralAuditFacade(audit);
        accessCenter = new AccessCenterService(users, repositories.getRepository(UserRoleRepository.class), groups,
                roles, permissions, roleService, repositories.getRepository(UserRolePermissionRepository.class),
                repositories.getRepository(GroupRolePermissionRepository.class), guard);
        accessCenter.setCentralAuditFacade(audit);
        passwordPolicy = new PasswordPolicyService(repositories.getRepository(PasswordPolicyRepository.class),
                repositories.getRepository(PasswordHistoryRepository.class), mock(PasswordEncoder.class));
        passwordPolicy.setAccounts(users);
        passwordPolicy.setCentralAuditFacade(audit);
        systemSettings = new SystemSettingsService(repositories.getRepository(SystemSettingsRepository.class), roles);
        systemSettings.setCentralAuditFacade(audit);
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
    void anEmptyConsoleSignedInAsAnAdministrator() {
        jdbc.execute("truncate ctxa_user_roles, ctxa_user_groups, ctxa_group_roles, ctxa_users, ctxa_role, "
                + "ctxa_app_group, ctxa_role_hierarchy_config, ctxa_permission, ctxa_password_policy, "
                + "ctxa_system_settings restart identity cascade");
        hierarchy.setHierarchy("");
        adminRole = role("ROLE_ADMIN");
        userRole = role("ROLE_USER");
        ops = group("ops", adminRole);
        staff = group("staff", userRole);
        alice = user("alice", null);
        bob = user("bob", null);
        jdbc.update("insert into ctxa_user_groups (user_id, group_id) values (?, ?)", alice, ops);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("admin", null, List.of()));
        // the policy and the settings as the console saved them once; the changes below are of one value each
        inTransaction(() -> passwordPolicy.updatePolicy(policy(90)));
        inTransaction(() -> {
            systemSettings.updateSettings(settings(90));
            return null;
        });
        jdbc.execute("truncate ctxa_audit_log restart identity");
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void theChangesThatHadNoRecordAreAuditedAndCountedByTheDashboard() {
        Instant from = Instant.now().minus(Duration.ofHours(1));
        Group auditors = inTransaction(() -> groupService.createGroup(newGroup("auditors"), List.of(userRole)));
        inTransaction(() -> groupService.updateGroup(renamed(auditors, "auditors-eu"), List.of()));
        inTransaction(() -> {
            groupService.deleteGroup(auditors.getId());
            return null;
        });
        Permission export = inTransaction(() -> permissionService.createPermission(newPermission("REPORT_EXPORT")));
        inTransaction(() -> permissionService.updatePermission(export.getId(), dto("REPORT_EXPORT_ALL")));
        RoleHierarchyEntity line = inTransaction(() -> hierarchyService.createRoleHierarchy(
                RoleHierarchyEntity.builder().hierarchyString("ROLE_ADMIN > ROLE_USER").description("Admins read")
                        .isActive(false).build()));
        inTransaction(() -> hierarchyService.activateRoleHierarchy(line.getId()));
        inTransaction(() -> accessCenter.updateUserGroups(bob, groups(staff)));
        // the last administrator's guard refuses a change after its rows were written: nothing is recorded
        assertThatThrownBy(() -> inTransaction(() -> accessCenter.updateUserGroups(alice, groups())))
                .isInstanceOf(LastAdministratorException.class);
        inTransaction(() -> passwordPolicy.updatePolicy(policy(30)));
        inTransaction(() -> passwordPolicy.updatePolicy(policy(30)));
        inTransaction(() -> {
            systemSettings.updateSettings(settings(30));
            return null;
        });
        inTransaction(() -> {
            systemSettings.updateSettings(settings(30));
            return null;
        });

        assertThat(jdbc.queryForList("select event_category || ' ' || action || ' ' || resource_identifier "
                + "|| ' ' || principal_name from ctxa_audit_log order by id", String.class)).containsExactly(
                "GROUP_CREATED GROUP_CREATED auditors admin",
                "GROUP_UPDATED GROUP_UPDATED auditors-eu admin",
                "GROUP_DELETED GROUP_DELETED auditors-eu admin",
                "PERMISSION_CREATED PERMISSION_CREATED REPORT_EXPORT admin",
                "PERMISSION_UPDATED PERMISSION_UPDATED REPORT_EXPORT_ALL admin",
                "ROLE_HIERARCHY_CHANGED ROLE_HIERARCHY_CREATED Admins read admin",
                "ROLE_HIERARCHY_CHANGED ROLE_HIERARCHY_ACTIVATED Admins read admin",
                "ROLE_ASSIGNMENT_CHANGED USER_GROUPS_ASSIGNED bob admin",
                "PASSWORD_POLICY_CHANGED PASSWORD_POLICY_CHANGED passwordExpiryDays admin",
                "SYSTEM_SETTINGS_CHANGED SYSTEM_SETTINGS_CHANGED auditLogRetentionDays admin");

        DashboardQueries queries = new DashboardQueries(() -> jdbc);
        Instant to = Instant.now().plus(Duration.ofMinutes(1));
        Map<String, Long> kinds = queries.changesByKind(from, to);
        assertThat(kinds).containsEntry("GROUP", 3L).containsEntry("PERMISSION", 2L).containsEntry("HIERARCHY", 2L)
                .containsEntry("ASSIGNMENT", 1L).containsEntry("PASSWORD", 1L).containsEntry("SETTINGS", 1L)
                .containsEntry("MENU", 0L).containsEntry("USER", 0L);
        List<ChangeRecord> recent = queries.recentChanges(from, to, 20);
        assertThat(recent).hasSize(10);
        assertThat(recent).extracting(ChangeRecord::category, ChangeRecord::action).first()
                .isEqualTo(tuple("SYSTEM_SETTINGS_CHANGED", "SYSTEM_SETTINGS_CHANGED"));
    }

    @Test
    void theAccountsSayWhetherTheirPasswordIsPastThePolicysDays() {
        long carol = user("carol", LocalDateTime.now().minusDays(40));
        long dave = user("dave", LocalDateTime.now().minusDays(5));
        jdbc.update("update ctxa_users set credentials_expired = true where id = ?", dave);

        inTransaction(() -> passwordPolicy.updatePolicy(policy(30)));
        assertThat(expired(carol)).isTrue();
        assertThat(expired(dave)).as("five days of thirty").isFalse();
        assertThat(expired(alice)).as("a password never changed is not read").isFalse();

        inTransaction(() -> passwordPolicy.updatePolicy(policy(60)));
        assertThat(expired(carol)).as("a policy that lets passwords live longer frees them at once").isFalse();

        inTransaction(() -> passwordPolicy.updatePolicy(policy(30)));
        inTransaction(() -> passwordPolicy.updatePolicy(policy(0)));
        assertThat(expired(carol)).as("passwords that live for ever").isFalse();
    }

    private static <T> T inTransaction(Supplier<T> work) {
        return transactions.execute(status -> work.get());
    }

    private boolean expired(long userId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("select credentials_expired from ctxa_users where id = ?",
                Boolean.class, userId));
    }

    private static PasswordPolicy policy(int expiryDays) {
        PasswordPolicy policy = PasswordPolicy.builder().build();
        policy.setPasswordExpiryDays(expiryDays);
        return policy;
    }

    private static SystemSettingsForm settings(int retentionDays) {
        SystemSettingsForm form = new SystemSettingsForm();
        form.setAuditLogRetentionDays(retentionDays);
        return form;
    }

    private static Group newGroup(String name) {
        Group group = new Group();
        group.setName(name);
        return group;
    }

    private static Group renamed(Group group, String name) {
        Group renamed = new Group();
        renamed.setId(group.getId());
        renamed.setName(name);
        return renamed;
    }

    private static Permission newPermission(String name) {
        Permission permission = new Permission();
        permission.setName(name);
        permission.setFriendlyName("Report export");
        return permission;
    }

    private static PermissionDto dto(String name) {
        PermissionDto dto = new PermissionDto();
        dto.setName(name);
        dto.setFriendlyName("Report export");
        return dto;
    }

    private static UpdateUserGroupsRequest groups(long... groupIds) {
        UpdateUserGroupsRequest request = new UpdateUserGroupsRequest();
        request.setGroupIds(Arrays.stream(groupIds).boxed().toList());
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

    private static long user(String username, LocalDateTime passwordChangedAt) {
        return jdbc.queryForObject("insert into ctxa_users (username, email, password, name, password_changed_at) "
                        + "values (?, ?, 'x', ?, ?) returning id", Long.class, username, username + "@console.example",
                username, passwordChangedAt != null ? Timestamp.valueOf(passwordChangedAt) : null);
    }
}
