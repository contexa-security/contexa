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
package io.contexa.contexaiam.admin.web.dashboard;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessCenterStats;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AttentionPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AttentionRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ChangeRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ChangesPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DashboardView;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Signal;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.AccountSignal;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.Accounts;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.Alarm;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.BlockRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.ChangeRecord;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Header;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Overview;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Period;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.UserChallenges;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plan step 9: what the dashboard gathers from the screens' services: the users to look at (N17), the admin changes
 * (N19, N21), the blocks by latest state (N6), the policy check that could not run, and the periods it accepts.
 */
class DashboardServiceImplTest {

    private final Instant now = Instant.parse("2026-11-17T04:20:00Z");
    private final ZeroTrustConsoleService console = mock(ZeroTrustConsoleService.class);
    private final ZeroTrustDecisionRecords records = mock(ZeroTrustDecisionRecords.class);
    private final DashboardQueries queries = mock(DashboardQueries.class);
    private final AccessCenterService accessCenter = mock(AccessCenterService.class);
    private final LastAdministratorGuard administrators = mock(LastAdministratorGuard.class);
    private final VerificationCoverageService coverage = mock(VerificationCoverageService.class);
    private final RoleHierarchyRepository hierarchies = mock(RoleHierarchyRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private final PasswordPolicyService passwordPolicy = mock(PasswordPolicyService.class);
    private final ManagedResourceRepository resources = mock(ManagedResourceRepository.class);
    private final PolicyRepository policies = mock(PolicyRepository.class);
    private final PolicyValidationService validation = mock(PolicyValidationService.class);
    private final PolicyCenterCommandService policyCenter = mock(PolicyCenterCommandService.class);
    private final IpAccessRuleService ipRules = mock(IpAccessRuleService.class);
    private final AuditLogRepository auditLog = mock(AuditLogRepository.class);
    private final SystemSettingsService settings = mock(SystemSettingsService.class);
    private final AgentRegistry agents = mock(AgentRegistry.class);
    private DashboardServiceImpl service;

    @BeforeEach
    void setUp() {
        StaticMessageSource messages = new StaticMessageSource();
        messages.addMessage("pv.prompt.cortex.security-decision", Locale.ENGLISH, "Security decision");
        messages.addMessage(DashboardServiceImpl.FOLDER_ACTOR_WORDS, Locale.ENGLISH, "Document folder");
        messages.addMessage(DashboardServiceImpl.FOLDER_ACTOR_WORDS, Locale.KOREAN, "문서 폴더");
        messages.addMessage("admin.password.policy.min.length", Locale.ENGLISH, "Minimum length");
        messages.addMessage("admin.password.policy.expiry.days", Locale.ENGLISH, "Password expiry (days)");
        messages.addMessage("admin.system.settings.audit.retention", Locale.ENGLISH, "Audit log retention (days)");
        messages.addMessage("menu.security.events", Locale.ENGLISH, "Security events");
        service = new DashboardServiceImpl(new DashboardSources(console, records, queries, accessCenter, administrators,
                coverage, hierarchies, roles, passwordPolicy, resources, policies, validation, policyCenter, ipRules,
                auditLog, settings, new PolicyCombiningProperties(), agents, null, null, null, messages),
                Clock.fixed(now, ZoneId.systemDefault()));
    }

    // ----- the users to look at (N17) -----

    @Test
    void theSignalsOfAUserAreGatheredFromEveryMenuIntoOneRow() {
        when(queries.blocksInForce(anyInt())).thenReturn(List.of(
                new BlockRow("u-park", "park.jiwoo", "BLOCKED", now.minusSeconds(600), 2, "req-1")));
        when(administrators.administratorsWithoutMfa(anyInt())).thenReturn(List.of("ops.admin"));
        when(queries.accountSignals(any(), anyInt())).thenReturn(List.of(
                new AccountSignal("Park.Jiwoo", 4, false, now.minusSeconds(60)),
                new AccountSignal("ops.admin", 3, true, now.minusSeconds(3600))));
        when(console.challengedAtLeast(eq("week"), eq(3L), anyInt())).thenReturn(List.of(
                new UserChallenges("park.jiwoo", 6, now.minusSeconds(7200).toString())));

        AttentionPart attention = service.attention("week", now);

        assertThat(attention.withSignals()).isEqualTo(2);
        assertThat(attention.capped()).isFalse();
        AttentionRow park = attention.rows().get(0);
        assertThat(park.user()).isEqualTo("park.jiwoo");
        // The block first, how often it came, then the account's failures and the period's step-ups.
        assertThat(park.signals()).extracting(Signal::kind, Signal::count).containsExactly(
                tuple("BLOCKED", null), tuple("REPEATED", 2L), tuple("LOGIN_FAILURES", 4L), tuple("CHALLENGES", 6L));
        // The latest of the user's signals: the failed login a minute ago.
        assertThat(park.lastAt()).isEqualTo(now.minusSeconds(60).toString());
        assertThat(park.requestId()).isEqualTo("req-1");
        assertThat(attention.rows().get(1).signals()).extracting(Signal::kind)
                .containsExactly("ADMIN_NO_MFA", "LOCKED", "LOGIN_FAILURES");
    }

    @Test
    void moreProblemSignalsComeFirstThenMoreWarningsThenTheLatestAndOnlyEightAreShown() {
        List<BlockRow> blocks = new ArrayList<>();
        // Ten users with one warning each (a release request), the latest first.
        for (int i = 0; i < 10; i++) {
            blocks.add(new BlockRow("u" + i, "user" + i, "UNBLOCK_REQUESTED", now.minusSeconds(60L * (i + 1)), 1,
                    "req-" + i));
        }
        when(queries.blocksInForce(anyInt())).thenReturn(blocks);
        // An administrator without MFA (a problem) whose account also failed three times (a warning).
        when(administrators.administratorsWithoutMfa(anyInt())).thenReturn(List.of("admin.x"));
        when(queries.accountSignals(any(), anyInt())).thenReturn(List.of(new AccountSignal("admin.x", 3, false, null)));
        when(console.challengedAtLeast(any(), anyLong(), anyInt())).thenReturn(List.of());

        AttentionPart attention = service.attention("week", now);

        assertThat(attention.withSignals()).isEqualTo(11);
        assertThat(attention.rows()).hasSize(8);
        assertThat(attention.rows()).extracting(AttentionRow::user)
                .containsExactly("admin.x", "user0", "user1", "user2", "user3", "user4", "user5", "user6");
    }

    @Test
    void theRuleIsThreeFailedLoginsInARowAndThreeStepUpsInThePeriod() {
        when(queries.blocksInForce(anyInt())).thenReturn(List.of());
        when(administrators.administratorsWithoutMfa(anyInt())).thenReturn(List.of());
        // A locked account with two failures is looked at for its lock, not for the failures.
        when(queries.accountSignals(any(), anyInt())).thenReturn(List.of(new AccountSignal("locked.two", 2, true, null)));
        when(console.challengedAtLeast(any(), anyLong(), anyInt())).thenReturn(List.of());

        AttentionPart attention = service.attention("week", now);

        assertThat(attention.rows()).singleElement().satisfies(row -> assertThat(row.signals())
                .extracting(Signal::kind).containsExactly("LOCKED"));
        verify(console).challengedAtLeast("week", 3L, DashboardServiceImpl.ATTENTION_READ);
        assertThat(DashboardQueries.LOGIN_FAILURES_AT_LEAST).isEqualTo(3);
    }

    @Test
    void aSourceReadToItsLimitMakesTheCountALowerBound() {
        List<String> many = new ArrayList<>();
        for (int i = 0; i < DashboardServiceImpl.ATTENTION_READ; i++) {
            many.add("admin" + i);
        }
        when(queries.blocksInForce(anyInt())).thenReturn(List.of());
        when(administrators.administratorsWithoutMfa(anyInt())).thenReturn(many);
        when(queries.accountSignals(any(), anyInt())).thenReturn(List.of());
        when(console.challengedAtLeast(any(), anyLong(), anyInt())).thenReturn(List.of());

        AttentionPart attention = service.attention("week", now);

        assertThat(attention.capped()).isTrue();
        assertThat(attention.withSignals()).isEqualTo(DashboardServiceImpl.ATTENTION_READ);
    }

    // ----- the recent admin changes (N19, N21) -----

    @Test
    void aChangeIsNamedByItsActionOrByItsKindAndItsTargetInWords() {
        Role role = new Role();
        role.setRoleName("ROLE_FINANCE");
        role.setRoleDesc("Finance staff");
        when(roles.findByRoleName("ROLE_FINANCE")).thenReturn(Optional.of(role));
        when(roles.findByRoleName("ROLE_GONE")).thenReturn(Optional.empty());
        Map<String, Long> kinds = new LinkedHashMap<>();
        kinds.put("POLICY", 3L);
        kinds.put("USER", 0L);
        kinds.put("MODE", 1L);
        when(queries.changesByKind(any(), any())).thenReturn(kinds);
        when(queries.recentChanges(any(), any(), eq(DashboardServiceImpl.CHANGES_SHOWN))).thenReturn(List.of(
                change("POLICY_UPDATED", "APPROVED", "Payment window", null),
                change("POLICY_UPDATED", "REJECTED", "Export rule", null),
                change("POLICY_UPDATED", "POLICY_UPDATED", "Export rule", null),
                change("ROLE_UPDATED", "ROLE_UPDATED", "ROLE_FINANCE", null),
                change("ROLE_DELETED", "ROLE_DELETED", "ROLE_GONE", null),
                change("ZERO_TRUST_MODE_CHANGED", "CHANGE", "contexa.security.zerotrust.mode", "SHADOW"),
                change("PROMPT_VERSION_CHANGED", "PROMPT_VERSION_CANARY_STARTED", "cortex.security-decision@v2", null),
                change("USER_MODIFIED", "USER_UNLOCKED", "yoon.minji", null),
                change("ADMIN_OVERRIDE", "SOMETHING_NEW", "lee.minseo", null),
                change("AGENT_KILL_SWITCH", "KILL_SWITCH_OFF", "*", null),
                change("AGENT_LEARNING_CONTROLLED", "QUARANTINE", "report-bot", null)));

        ChangesPart changes = service.changes(now.minusSeconds(3600), now, Locale.ENGLISH);

        assertThat(changes.byKind()).extracting(count -> count.key()).containsExactly("POLICY", "MODE", "USER");
        assertThat(changes.recent()).extracting(ChangeRow::kind, ChangeRow::action, ChangeRow::target).containsExactly(
                tuple("POLICY", "POLICY_APPROVED", "Payment window"),
                tuple("POLICY", "POLICY_REJECTED", "Export rule"),
                tuple("POLICY", "POLICY_UPDATED", "Export rule"),
                tuple("ROLE", "ROLE_UPDATED", "Finance staff"),
                tuple("ROLE", "ROLE_DELETED", "GONE"),
                tuple("MODE", "ZERO_TRUST_MODE_CHANGED", "SHADOW"),
                tuple("PROMPT", "PROMPT_VERSION_CANARY_STARTED", "Security decision v2"),
                tuple("USER", "USER_UNLOCKED", "yoon.minji"),
                tuple("OVERRIDE", null, "lee.minseo"),
                tuple("AGENT", "KILL_SWITCH_OFF", "*"),
                tuple("AGENT", null, "report-bot"));
    }

    @Test
    void theChangesRecordedSinceK75AreNamedByTheirKindActionAndTarget() {
        when(queries.changesByKind(any(), any())).thenReturn(Map.of("GROUP", 1L));
        when(queries.recentChanges(any(), any(), eq(DashboardServiceImpl.CHANGES_SHOWN))).thenReturn(List.of(
                change("GROUP_UPDATED", "GROUP_UPDATED", "ops", null),
                change("PERMISSION_DELETED", "PERMISSION_DELETED", "REPORT_EXPORT", null),
                change("ROLE_HIERARCHY_CHANGED", "ROLE_HIERARCHY_ACTIVATED", "Finance chain", null),
                change("ROLE_ASSIGNMENT_CHANGED", "USER_ROLES_ASSIGNED", "kim.sora", null),
                change("PASSWORD_POLICY_CHANGED", "PASSWORD_POLICY_CHANGED", "minLength,passwordExpiryDays", null),
                change("MENU_CHANGED", "MENU_SWITCHED", "menu.security.events", null),
                change("MENU_CHANGED", "MENU_REORDERED", "", null),
                change("SYSTEM_SETTINGS_CHANGED", "SYSTEM_SETTINGS_CHANGED", "auditLogRetentionDays,unknownField",
                        null)));

        ChangesPart changes = service.changes(now.minusSeconds(3600), now, Locale.ENGLISH);

        assertThat(changes.recent()).extracting(ChangeRow::kind, ChangeRow::action, ChangeRow::target).containsExactly(
                tuple("GROUP", "GROUP_UPDATED", "ops"),
                tuple("PERMISSION", "PERMISSION_DELETED", "REPORT_EXPORT"),
                tuple("HIERARCHY", "ROLE_HIERARCHY_ACTIVATED", "Finance chain"),
                tuple("ASSIGNMENT", "USER_ROLES_ASSIGNED", "kim.sora"),
                tuple("PASSWORD", "PASSWORD_POLICY_CHANGED", "Minimum length, Password expiry (days)"),
                tuple("MENU", "MENU_SWITCHED", "Security events"),
                tuple("MENU", "MENU_REORDERED", ""),
                tuple("SETTINGS", "SYSTEM_SETTINGS_CHANGED", "Audit log retention (days), unknownField"));
    }

    @Test
    void aVersionFromTheDocumentFolderReadsAsTheDocumentFolder() {
        when(queries.changesByKind(any(), any())).thenReturn(Map.of("PROMPT", 2L));
        when(queries.recentChanges(any(), any(), eq(DashboardServiceImpl.CHANGES_SHOWN))).thenReturn(List.of(
                new ChangeRecord(now.minusSeconds(60), "folder:node-1", "PROMPT_VERSION_CHANGED",
                        "PROMPT_VERSION_FOLDER_REGISTERED", "cortex.security-decision@v3", null),
                change("PROMPT_VERSION_CHANGED", "PROMPT_VERSION_CREATED", "cortex.security-decision@v2", null)));

        ChangesPart english = service.changes(now.minusSeconds(3600), now, Locale.ENGLISH);
        ChangesPart korean = service.changes(now.minusSeconds(3600), now, Locale.KOREAN);

        assertThat(english.recent()).extracting(ChangeRow::actor, ChangeRow::action).containsExactly(
                tuple("Document folder", "PROMPT_VERSION_FOLDER_REGISTERED"), tuple("admin", "PROMPT_VERSION_CREATED"));
        assertThat(korean.recent()).extracting(ChangeRow::actor).containsExactly("문서 폴더", "admin");
    }

    // ----- the whole answer -----

    @Test
    void theAnswerReadsEachCardFromItsScreensService() {
        stubTheWholeAnswer();
        when(validation.validateAllForDashboard()).thenThrow(new IllegalStateException("broken policy"));

        DashboardView view = service.dashboard(null, Locale.ENGLISH);

        verify(console).period("week");
        assertThat(view.period().key()).isEqualTo("week");
        // N6: the users blocked now are the sum of their latest states.
        assertThat(view.blocked().inForce()).isEqualTo(5);
        assertThat(view.blocked().byLatestStatus()).extracting(count -> count.key())
                .containsExactly("BLOCKED", "UNBLOCK_REQUESTED");
        // A policy check that could not run counts nothing, rather than nothing found.
        assertThat(view.policy().healthStatus()).isEqualTo("UNKNOWN");
        assertThat(view.policy().conflictCount()).isNull();
        assertThat(view.policy().pendingApproval()).isEqualTo(4);
        // The protection's base leaves the excluded resources out: the total keeps them for the tooltip only.
        assertThat(view.policy().resourceTotal()).isEqualTo(7);
        assertThat(view.policy().resourcePolicyConnected() + view.policy().resourcePermissionCreated()
                + view.policy().resourceNeedsDefinition()).isEqualTo(5);
        // N2, N4: the administrators by the console's rule, the MFA among the accounts of people.
        assertThat(view.iam().admins()).isEqualTo(3);
        assertThat(view.iam().adminsWithoutMfa()).isEqualTo(1);
        assertThat(view.iam().activeAccounts()).isEqualTo(90);
        assertThat(view.iam().userCount()).isEqualTo(100);
        // N10: the agents by status, the states nobody is in left out; no delegations without a registry.
        assertThat(view.agents().byStatus()).extracting(count -> count.key()).containsExactly("ACTIVE");
        assertThat(view.agents().delegations()).isZero();
        assertThat(view.agents().callLimit()).isEqualTo(2);
        assertThat(view.agents().lastAt()).containsKey("callLimit").doesNotContainKey("denialAlarm");
        assertThat(view.security().ipDeny()).isEqualTo(7);
        assertThat(view.system().missingMethodDecision()).isEqualTo("PERMIT");
        // Only SHADOW reads the adoption.
        verify(console, never()).adoption(any(), any());
    }

    @Test
    void theDashboardsPeriodsAreTheFourOfItsChips() {
        assertThatThrownBy(() -> service.dashboard("custom", Locale.ENGLISH))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.dashboard("year", Locale.ENGLISH))
                .isInstanceOf(IllegalArgumentException.class);
        verify(console, never()).period(anyString());
    }

    private void stubTheWholeAnswer() {
        when(console.period(anyString())).thenAnswer(call -> new Period(call.getArgument(0),
                now.minusSeconds(7 * 86400).toString(), now.toString()));
        Header header = new Header(null, "ENFORCE", null, 0, 0, List.of(), List.of(), false, null);
        when(console.overview(anyString(), isNull(), isNull(), isNull(), any())).thenReturn(new Overview(header, null,
                null, null, null, null, List.of(), List.of(), List.of(), null));
        when(console.components(anyString(), any())).thenReturn(List.of());
        when(resources.countGroupByStatus()).thenReturn(List.<Object[]>of(
                new Object[] {ManagedResource.Status.POLICY_CONNECTED, 5L},
                new Object[] {ManagedResource.Status.EXCLUDED, 2L}));
        when(policies.countGroupByApprovalStatus()).thenReturn(List.<Object[]>of(
                new Object[] {Policy.ApprovalStatus.PENDING, 3L}, new Object[] {null, 1L}));
        when(queries.byDay(anyList(), any(), any(), any())).thenReturn(List.of());
        when(accessCenter.getStats()).thenReturn(new AccessCenterStats(100, 2, 3, 4));
        PasswordPolicy policy = PasswordPolicy.builder().build();
        when(passwordPolicy.getCurrentPolicy()).thenReturn(policy);
        when(queries.accounts(any(), any(), any())).thenReturn(new Accounts(90, 60, 1, 2, 3));
        when(administrators.administratorCount()).thenReturn(3L);
        when(administrators.administratorsWithoutMfaCount()).thenReturn(1L);
        when(ipRules.countDenyRules()).thenReturn(7L);
        Map<String, Long> blocks = new LinkedHashMap<>();
        blocks.put("UNBLOCK_REQUESTED", 2L);
        blocks.put("BLOCKED", 3L);
        when(queries.blocksByLatestStatus()).thenReturn(blocks);
        Map<AgentStatus, Long> agentCounts = new EnumMap<>(AgentStatus.class);
        agentCounts.put(AgentStatus.ACTIVE, 4L);
        when(agents.countByStatus(null)).thenReturn(agentCounts);
        Map<String, Alarm> alarms = new LinkedHashMap<>();
        alarms.put(DashboardServiceImpl.CALL_LIMIT, new Alarm(2, now.minusSeconds(60)));
        alarms.put(DashboardServiceImpl.DENIAL_ALARM, new Alarm(0, null));
        when(queries.alarms(anyList(), any(), any())).thenReturn(alarms);
        when(settings.getSettings()).thenReturn(SystemSettings.builder().build());
        when(queries.changesByKind(any(), any())).thenReturn(Map.of());
        when(queries.recentChanges(any(), any(), anyInt())).thenReturn(List.of());
        when(queries.blocksInForce(anyInt())).thenReturn(List.of());
        when(administrators.administratorsWithoutMfa(anyInt())).thenReturn(List.of());
        when(queries.accountSignals(any(), anyInt())).thenReturn(List.of());
        when(console.challengedAtLeast(any(), anyLong(), anyInt())).thenReturn(List.of());
        when(queries.topDenials(anyString(), any(), any(), anyInt())).thenReturn(List.of());
    }

    private ChangeRecord change(String category, String action, String resource, String decision) {
        return new ChangeRecord(now.minusSeconds(60), "admin", category, action, resource, decision);
    }
}
