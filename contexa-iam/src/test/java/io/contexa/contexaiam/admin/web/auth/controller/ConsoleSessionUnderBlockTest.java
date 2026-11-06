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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.store.InMemoryBlockMfaStateStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaiam.admin.web.agent.controller.AgentStopApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentStopController;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The block list stays open to a console session under a BLOCK, so that the BLOCK can be read and answered. A stolen
 * session must not use that to lift the BLOCK of someone else or to stop and resume the agents: it reads the list, and
 * every change on the way is a 403 that stays in the audit. Its own release takes a verification, as before.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class ConsoleSessionUnderBlockTest {

    private static final String ADMIN = "rcboss";
    private static final String OWN_KEY = "console::rcboss";
    private static final String SESSION = "console-session";
    private static final String USER_AGENT = "browser";
    private static final String JSON_RESOLVE = "{\"resolvedAction\":\"ALLOW\",\"reason\":\"checked\"}";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryBlockMfaStateStore verifications = new InMemoryBlockMfaStateStore(actions);
    private final BlockedUserJpaRepository rows = mock(BlockedUserJpaRepository.class);
    private final AdminOverrideService overrides = mock(AdminOverrideService.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final BlockingSignalBroadcaster signals = mock(BlockingSignalBroadcaster.class);
    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final BlockedUserService blockedUsers = new BlockedUserService(rows, overrides, actions,
            mock(ApplicationEventPublisher.class), audit, signals, messages);
    private final InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
    private final AgentContainmentAdminService stops = new AgentContainmentAdminService(
            new AgentContainmentService(actions, registry, null, null, null, mock(CentralAuditFacade.class)),
            registry, null, null);

    private MockMvc mvc;

    @BeforeEach
    void aConsole() {
        blockedUsers.setBlockMfaStateStore(verifications);
        stops.setBlockedUsers(blockedUsers);
        InternalResourceViewResolver views = new InternalResourceViewResolver();
        views.setPrefix("/views/");
        views.setSuffix(".html");
        mvc = MockMvcBuilders.standaloneSetup(new BlacklistController(blockedUsers, messages),
                        new BlacklistApiController(blockedUsers, messages), new AgentStopController(stops, messages),
                        new AgentStopApiController(stops))
                .setViewResolvers(views)
                .build();
        SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken(ADMIN, "password")));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    private void aBlockOnTheSession() {
        actions.saveAction(OWN_KEY, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(OWN_KEY);
    }

    private BlockedUser aRecordOf(String userId, BlockedUserStatus status) {
        BlockedUser row = BlockedUser.builder().id(7L).userId(userId).username(userId).requestId("req-7")
                .blockedAt(LocalDateTime.now()).status(status).blockCount(1).build();
        when(rows.findById(7L)).thenReturn(Optional.of(row));
        return row;
    }

    private void aStoppedAgent() {
        registry.register(new AgentRegistrationRequest(null, "sync-agent", "Sync", "SYNC", "sync-client", "carol", true));
        registry.suspend(null, "sync-agent", "BLOCK: Bulk export at night");
    }

    private void aRunningAgent() {
        registry.register(new AgentRegistrationRequest(null, "report-agent", "Report", "SYNC", "report-client", "carol",
                true));
    }

    /** The session as the console's chain hands it over. */
    private static RequestPostProcessor console() {
        return request -> {
            ConsoleSession.mark(request);
            request.setRequestedSessionId(SESSION);
            request.addHeader("User-Agent", USER_AGENT);
            return request;
        };
    }

    private ResultActions perform(MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.with(console()).principal(new TestingAuthenticationToken(ADMIN, "password")));
    }

    private void aVerificationInThisSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        console().postProcessRequest(request);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        verifications.setVerified(OWN_KEY, SessionFingerprintUtil.verificationContext(request));
    }

    private void assertAuditedRefusal(String action) {
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getPrincipalName()).isEqualTo(ADMIN);
        assertThat(record.getValue().getAction()).isEqualTo(action);
        assertThat(record.getValue().getOutcome()).isEqualTo("REFUSED");
    }

    private void assertNothingLifted(BlockedUser row, BlockedUserStatus status) {
        assertThat(row.getStatus()).isEqualTo(status);
        assertThat(row.getResolvedBy()).isNull();
        verify(overrides, never()).approve(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(),
                any());
        verify(rows, never()).delete(any());
    }

    static Stream<MockHttpServletRequestBuilder> theChangesOfABlockRecord() {
        return Stream.of(
                post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"),
                post("/contexa/admin/api/blacklist/7/resolve").contentType(MediaType.APPLICATION_JSON).content(JSON_RESOLVE));
    }

    @ParameterizedTest
    @MethodSource("theChangesOfABlockRecord")
    @DisplayName("a session under a BLOCK does not lift someone else's")
    void theBlockOfSomeoneElse(MockHttpServletRequestBuilder request) throws Exception {
        aBlockOnTheSession();
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(request).andExpect(status().isForbidden());

        assertNothingLifted(row, BlockedUserStatus.BLOCKED);
        assertAuditedRefusal("RESOLVE_BLOCK");
    }

    static Stream<MockHttpServletRequestBuilder> theDeletionsOfABlockRecord() {
        return Stream.of(post("/contexa/admin/blacklist/7/delete"), delete("/contexa/admin/api/blacklist/7"));
    }

    @ParameterizedTest
    @MethodSource("theDeletionsOfABlockRecord")
    @DisplayName("nor deletes the record of someone else")
    void theRecordOfSomeoneElse(MockHttpServletRequestBuilder request) throws Exception {
        aBlockOnTheSession();
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.RESOLVED);

        perform(request).andExpect(status().isForbidden());

        assertNothingLifted(row, BlockedUserStatus.RESOLVED);
        assertAuditedRefusal("DELETE_BLOCK_RECORD");
    }

    @Test
    @DisplayName("nor a record already resolved: the answer is the same 403, with no hint of the record's state")
    void aResolvedRecord() throws Exception {
        aBlockOnTheSession();
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.RESOLVED);

        perform(post("/contexa/admin/api/blacklist/7/resolve").contentType(MediaType.APPLICATION_JSON).content(JSON_RESOLVE))
                .andExpect(status().isForbidden());

        assertNothingLifted(row, BlockedUserStatus.RESOLVED);
    }

    @Test
    @DisplayName("nor releases the CHALLENGE of someone else")
    void theChallengeOfSomeoneElse() throws Exception {
        aBlockOnTheSession();
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());

        perform(post("/contexa/admin/blacklist/challenge-release").param("userId", "alice").param("reason", "checked"))
                .andExpect(status().isForbidden());

        assertThat(actions.getActionFromHash("alice")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertAuditedRefusal("RELEASE_CHALLENGE");
    }

    @Test
    @DisplayName("the kill switch is out of its reach: the running agents go on")
    void theKillSwitch() throws Exception {
        aBlockOnTheSession();
        aRunningAgent();

        perform(post("/contexa/admin/blacklist/agents/kill-switch").param("reason", "incident"))
                .andExpect(status().isForbidden());

        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.ACTIVE);
        assertAuditedRefusal("KILL_SWITCH");
    }

    @Test
    @DisplayName("the release of the kill switch too: the stopped agents stay stopped")
    void theReleaseOfTheKillSwitch() throws Exception {
        aRunningAgent();
        stops.killSwitch(null, null, "second-admin", "incident");
        aBlockOnTheSession();

        perform(post("/contexa/admin/blacklist/agents/kill-switch/release").param("reason", "over"))
                .andExpect(status().isForbidden());

        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.SUSPENDED);
        assertAuditedRefusal("KILL_SWITCH_RELEASE");
    }

    @Test
    @DisplayName("and the release of an agent a decision stopped")
    void theReleaseOfAnAgent() throws Exception {
        aBlockOnTheSession();
        aStoppedAgent();

        perform(post("/contexa/admin/blacklist/agents/release-agent").param("agentId", "sync-agent")
                .param("reason", "reviewed"))
                .andExpect(status().isForbidden());

        assertThat(registry.find(null, "sync-agent")).map(agent -> agent.status()).contains(AgentStatus.SUSPENDED);
        assertAuditedRefusal("RELEASE_AGENT");
    }

    @Test
    @DisplayName("and the release of an agent that acted for a person")
    void theReleaseOfADelegatedAgent() throws Exception {
        aBlockOnTheSession();
        actions.saveAction("alice::agent::report-agent", ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag("alice::agent::report-agent");

        perform(post("/contexa/admin/blacklist/agents/release-delegation").param("userId", "alice")
                .param("agentId", "report-agent").param("reason", "reviewed"))
                .andExpect(status().isForbidden());

        assertThat(actions.getActionFromHash("alice::agent::report-agent")).isEqualTo(ZeroTrustAction.BLOCK);
        assertAuditedRefusal("RELEASE_DELEGATION");
    }

    static Stream<String> theActionsOfTheStopsApi() {
        return Stream.of("RELEASE_DELEGATION", "RELEASE_AGENT", "KILL_SWITCH", "KILL_SWITCH_RELEASE");
    }

    @ParameterizedTest
    @MethodSource("theActionsOfTheStopsApi")
    @DisplayName("the stops' API gives the same answer, whatever stands in front of it")
    void theStopsApi(String action) throws Exception {
        aBlockOnTheSession();
        aRunningAgent();

        perform(post("/contexa/admin/api/agents/stops").contentType(MediaType.APPLICATION_JSON)
                .content("{\"action\":\"" + action + "\",\"userId\":\"alice\",\"agentId\":\"report-agent\",\"reason\":\"r\"}"))
                .andExpect(status().isForbidden());

        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.ACTIVE);
        assertAuditedRefusal(action);
    }

    @Test
    @DisplayName("a failed audit does not turn a refusal into a change")
    void anAuditThatFails() throws Exception {
        doThrow(new IllegalStateException("audit down")).when(audit).recordAsync(any());
        aBlockOnTheSession();
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().isForbidden());

        assertNothingLifted(row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("the session reads the list, a record and the stops")
    void itReads() throws Exception {
        aBlockOnTheSession();
        aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(get("/contexa/admin/blacklist")).andExpect(status().isOk());
        perform(get("/contexa/admin/blacklist/7")).andExpect(status().isOk());
        perform(get("/contexa/admin/api/blacklist")).andExpect(status().isOk());
        perform(get("/contexa/admin/api/blacklist/7")).andExpect(status().isOk());
        perform(get("/contexa/admin/blacklist/agents")).andExpect(status().isOk());
        perform(get("/contexa/admin/api/agents/stops")).andExpect(status().isOk());

        verify(audit, never()).recordAsync(any());
    }

    @Test
    @DisplayName("the list says the session only reads; a session without a BLOCK is not told so")
    void theListSaysSo() throws Exception {
        aRecordOf("alice", BlockedUserStatus.BLOCKED);
        assertThat(perform(get("/contexa/admin/blacklist")).andReturn().getModelAndView().getModel().get("underOwnBlock"))
                .isEqualTo(false);
        assertThat(perform(get("/contexa/admin/blacklist/7")).andReturn().getModelAndView().getModel().get("mayLift"))
                .isEqualTo(true);
        assertThat(perform(get("/contexa/admin/blacklist/agents")).andReturn().getModelAndView().getModel()
                .get("underOwnBlock")).isEqualTo(false);

        aBlockOnTheSession();

        assertThat(perform(get("/contexa/admin/blacklist")).andReturn().getModelAndView().getModel().get("underOwnBlock"))
                .isEqualTo(true);
        assertThat(perform(get("/contexa/admin/blacklist/7")).andReturn().getModelAndView().getModel().get("mayLift"))
                .isEqualTo(false);
        assertThat(perform(get("/contexa/admin/blacklist/agents")).andReturn().getModelAndView().getModel()
                .get("underOwnBlock")).isEqualTo(true);
    }

    @Test
    @DisplayName("the page of its own record offers the release once the session verified it is the owner")
    void itsOwnRecordAfterAVerification() throws Exception {
        aBlockOnTheSession();
        aRecordOf(OWN_KEY, BlockedUserStatus.BLOCKED);
        assertThat(perform(get("/contexa/admin/blacklist/7")).andReturn().getModelAndView().getModel().get("mayLift"))
                .isEqualTo(false);

        aVerificationInThisSession();

        assertThat(perform(get("/contexa/admin/blacklist/7")).andReturn().getModelAndView().getModel().get("mayLift"))
                .isEqualTo(true);
    }

    @Test
    @DisplayName("a verification opens its own release and nothing else: the BLOCK of someone else stays out of reach")
    void aVerificationOpensItsOwnRelease() throws Exception {
        aBlockOnTheSession();
        aVerificationInThisSession();
        BlockedUser other = aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().isForbidden());

        assertNothingLifted(other, BlockedUserStatus.BLOCKED);

        BlockedUser own = aRecordOf(OWN_KEY, BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "verified"))
                .andExpect(status().is3xxRedirection());

        assertThat(own.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
        assertThat(own.getResolvedBy()).isEqualTo(ADMIN);
    }

    @Test
    @DisplayName("its own release without a verification stays what it was: refused on the page, and audited")
    void itsOwnReleaseWithoutAVerification() throws Exception {
        aBlockOnTheSession();
        BlockedUser row = aRecordOf(OWN_KEY, BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "it was me"))
                .andExpect(status().is3xxRedirection());

        assertNothingLifted(row, BlockedUserStatus.BLOCKED);
        assertAuditedRefusal("RESOLVE_BLOCK");
    }

    @Test
    @DisplayName("an administrator who stands under no BLOCK works as before")
    void anAdministratorWithoutABlock() throws Exception {
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);
        aRunningAgent();

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().is3xxRedirection());
        perform(post("/contexa/admin/blacklist/agents/kill-switch").param("reason", "incident"))
                .andExpect(status().is3xxRedirection());

        assertThat(row.getResolvedBy()).isEqualTo(ADMIN);
        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.SUSPENDED);
    }

    @Test
    @DisplayName("the application's user of the same name is someone else: their BLOCK does not reach the console")
    void theApplicationsUserOfTheName() throws Exception {
        actions.saveAction(ADMIN, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(ADMIN);
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().is3xxRedirection());

        assertThat(row.getResolvedBy()).isEqualTo(ADMIN);
    }

    @Test
    @DisplayName("once another administrator lifted the BLOCK the session works again")
    void aBlockLifted() throws Exception {
        aBlockOnTheSession();
        actions.approveOverrideAtomically(OWN_KEY, ZeroTrustAction.ALLOW);
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().is3xxRedirection());

        assertThat(row.getResolvedBy()).isEqualTo(ADMIN);
    }

    @Test
    @DisplayName("where decisions are not enforced a stored BLOCK stops nothing, here as anywhere")
    void noEnforcement() throws Exception {
        blockedUsers.setEnforcing(() -> false);
        aBlockOnTheSession();
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().is3xxRedirection());

        assertThat(row.getResolvedBy()).isEqualTo(ADMIN);
    }

    /**
     * The release path stands behind no access or CHALLENGE filter, so a session under a CHALLENGE or an ESCALATE of its
     * own reaches it as a session under a BLOCK does: it reads the lists and changes nothing, for someone else or for
     * the agents, until it passes the step-up.
     */
    @ParameterizedTest
    @EnumSource(value = ZeroTrustAction.class, names = {"CHALLENGE", "ESCALATE"})
    @DisplayName("a session under a CHALLENGE or an ESCALATE of its own only reads")
    void aSessionUnderAChallengeOrAnEscalationOnlyReads(ZeroTrustAction restriction) throws Exception {
        actions.saveAction(OWN_KEY, restriction, Map.of());
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);
        aRunningAgent();

        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().isForbidden());
        perform(post("/contexa/admin/api/blacklist/7/resolve").contentType(MediaType.APPLICATION_JSON)
                .content(JSON_RESOLVE)).andExpect(status().isForbidden());
        perform(post("/contexa/admin/blacklist/agents/kill-switch").param("reason", "incident"))
                .andExpect(status().isForbidden());
        perform(post("/contexa/admin/api/agents/stops").contentType(MediaType.APPLICATION_JSON)
                .content("{\"action\":\"KILL_SWITCH\",\"reason\":\"r\"}"))
                .andExpect(status().isForbidden());
        actions.saveAction("bob", ZeroTrustAction.CHALLENGE, Map.of());
        perform(post("/contexa/admin/blacklist/challenge-release").param("userId", "bob").param("reason", "checked"))
                .andExpect(status().isForbidden());

        assertNothingLifted(row, BlockedUserStatus.BLOCKED);
        assertThat(registry.find(null, "report-agent")).map(agent -> agent.status()).contains(AgentStatus.ACTIVE);
        assertThat(actions.getActionFromHash("bob")).isEqualTo(ZeroTrustAction.CHALLENGE);
        perform(get("/contexa/admin/blacklist")).andExpect(status().isOk());
        assertThat(perform(get("/contexa/admin/blacklist")).andReturn().getModelAndView().getModel()
                .get("underOwnBlock")).isEqualTo(true);
        assertThat(perform(get("/contexa/admin/blacklist/7")).andReturn().getModelAndView().getModel().get("mayLift"))
                .isEqualTo(false);
    }

    /**
     * The console's step-up answers a CHALLENGE in the session that passed it: that session acts again, and another
     * session of the administrator, which did not answer it, still only reads.
     */
    @Test
    @DisplayName("the step-up answers the session's CHALLENGE in that session only")
    void theStepUpAnswersTheChallengeInItsSession() throws Exception {
        actions.saveAction(OWN_KEY, ZeroTrustAction.CHALLENGE, Map.of());
        BlockedUser row = aRecordOf("alice", BlockedUserStatus.BLOCKED);
        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().isForbidden());

        aStepUpPassedInThisSession();

        performIn("another-session", post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW")
                .param("reason", "checked")).andExpect(status().isForbidden());
        assertNothingLifted(row, BlockedUserStatus.BLOCKED);
        perform(post("/contexa/admin/blacklist/7/resolve").param("resolvedAction", "ALLOW").param("reason", "checked"))
                .andExpect(status().is3xxRedirection());
        assertThat(row.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
        assertThat(row.getResolvedBy()).isEqualTo(ADMIN);
    }

    /** What the console's step-up records for a CHALLENGE it resolves ({@code ChallengeResolution.releaseChallenge}). */
    private void aStepUpPassedInThisSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        console().postProcessRequest(request);
        String context = SessionFingerprintUtil.generateContextBindingHash(request);
        actions.holdChallengeForOtherSessions(OWN_KEY, context);
        actions.saveActionWithPrevious(OWN_KEY, ZeroTrustAction.ALLOW, context);
    }

    private ResultActions performIn(String session, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.with(console()).with(other -> {
            other.setRequestedSessionId(session);
            return other;
        }).principal(new TestingAuthenticationToken(ADMIN, "password")));
    }

    /** A new way to change something here needs a look: it stands behind no filter for a session under a BLOCK. */
    @Test
    @DisplayName("the ways to change something in the block list are the ones above")
    void theWaysToChangeSomething() {
        assertThat(writeHandlers(BlacklistController.class, BlacklistApiController.class, AgentStopController.class))
                .containsExactly("AgentStopController.killSwitch", "AgentStopController.releaseAgent",
                        "AgentStopController.releaseDelegation", "AgentStopController.releaseKillSwitch",
                        "BlacklistApiController.deleteBlockRecord", "BlacklistApiController.resolveBlock",
                        "BlacklistController.deleteBlockRecord", "BlacklistController.releaseChallenge",
                        "BlacklistController.resolveBlock");
    }

    private static List<String> writeHandlers(Class<?>... controllers) {
        List<Class<? extends Annotation>> writes = List.of(PostMapping.class, PutMapping.class, DeleteMapping.class,
                PatchMapping.class);
        TreeSet<String> handlers = new TreeSet<>();
        for (Class<?> controller : controllers) {
            for (Method method : controller.getDeclaredMethods()) {
                if (Arrays.stream(method.getAnnotations()).anyMatch(annotation -> writes.contains(annotation.annotationType()))) {
                    handlers.add(controller.getSimpleName() + "." + method.getName());
                }
            }
        }
        return List.copyOf(handlers);
    }
}
