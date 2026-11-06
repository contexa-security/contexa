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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.store.InMemoryBlockMfaStateStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
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
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A session under a BLOCK reaches the block list, so a stolen console session could lift the very BLOCK that
 * stopped it. Its own release takes another administrator, or a verification passed in that session.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class BlockedUserServiceOwnReleaseTest {

    private static final String OWN_KEY = "console::rcboss";
    private static final String ADMIN = "rcboss";
    private static final String SESSION = "console-session";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryBlockMfaStateStore verifications = new InMemoryBlockMfaStateStore(actions);
    private final BlockedUserJpaRepository rows = mock(BlockedUserJpaRepository.class);
    private final AdminOverrideService overrides = mock(AdminOverrideService.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final BlockedUserService service = new BlockedUserService(rows, overrides, actions,
            mock(ApplicationEventPublisher.class), audit, mock(BlockingSignalBroadcaster.class),
            I18nTestSupport.englishMessageSource());

    @BeforeEach
    void aConsoleSession() {
        service.setBlockMfaStateStore(verifications);
        aRequest(SESSION, true);
    }

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static MockHttpServletRequest aRequest(String session, boolean console) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/admin/blacklist/7/resolve");
        request.setRequestedSessionId(session);
        request.addHeader("User-Agent", "browser");
        if (console) {
            ConsoleSession.mark(request);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }

    private static String contextOf(MockHttpServletRequest request) {
        return SessionFingerprintUtil.verificationContext(request);
    }

    private static String here() {
        return SessionFingerprintUtil.verificationContext(
                ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest());
    }

    private BlockedUser row(String userId, BlockedUserStatus status) {
        BlockedUser row = BlockedUser.builder().id(7L).userId(userId).username(ADMIN).requestId("req-7")
                .blockedAt(LocalDateTime.now()).status(status).blockCount(1).build();
        when(rows.findById(7L)).thenReturn(Optional.of(row));
        return row;
    }

    private void assertRefused(Runnable release, BlockedUser row, BlockedUserStatus status) {
        assertThatThrownBy(release::run).isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("another administrator");
        assertThat(row.getStatus()).isEqualTo(status);
        assertThat(row.getResolvedBy()).isNull();
        verify(overrides, never()).approve(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any());
        verify(rows, never()).delete(any());
    }

    private void assertResolved(BlockedUser row, String by) {
        assertThat(row.getStatus()).isEqualTo(BlockedUserStatus.RESOLVED);
        assertThat(row.getResolvedBy()).isEqualTo(by);
    }

    @ParameterizedTest
    @ValueSource(strings = {"console::rcboss", "console::RCBOSS", "CONSOLE::rcboss", "Console::RcBoss",
            "console::\uFF52\uFF43\uFF42\uFF4F\uFF53\uFF53", "\uFF43\uFF4F\uFF4E\uFF53\uFF4F\uFF4C\uFF45::rcboss",
            "console\uFF1A\uFF1Arcboss", " console::rcboss ", "console::rcboss\u3000"})
    @DisplayName("a session does not lift its own BLOCK, however the record spells the name")
    void itsOwnRecordInEverySpelling(String recorded) {
        BlockedUser row = row(recorded, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"RCBOSS", "RcBoss", "\uFF52\uFF43\uFF42\uFF4F\uFF53\uFF53", " rcboss ", "rcboss\u3000"})
    @DisplayName("nor does signing in under another spelling of the name make it someone else's")
    void signedInUnderAnotherSpelling(String signedIn) {
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, signedIn, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ALLOW", "CHALLENGE", "PENDING_ANALYSIS", "BLOCK", "UNBLOCK", ""})
    @DisplayName("whatever it would end as")
    void everyResolution(String action) {
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, action, "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @ParameterizedTest
    @EnumSource(BlockedUserStatus.class)
    @DisplayName("it does not delete its own record either: without it a block no longer reads as in force")
    void itsOwnRecordIsNotDeleted(BlockedUserStatus status) {
        BlockedUser row = row(OWN_KEY, status);

        assertRefused(() -> service.deleteBlockRecord(7L, ADMIN), row, status);
    }

    @Test
    @DisplayName("the way by the user's id takes the same rule")
    void theWayByTheUsersId() {
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);
        when(rows.findFirstByUserIdAndStatusOrderByBlockedAtDesc(OWN_KEY, BlockedUserStatus.BLOCKED))
                .thenReturn(Optional.of(row));

        assertRefused(() -> service.resolveBlock(OWN_KEY, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"console::rcboss", "console::RCBOSS", "CONSOLE::RCBOSS", " console::rcboss ",
            "console::\uFF52\uFF43\uFF42\uFF4F\uFF53\uFF53", "console\uFF1A\uFF1Arcboss"})
    @DisplayName("the free text of the CHALLENGE release is no way around it")
    void itsOwnChallengeInEverySpelling(String typed) {
        actions.saveAction(OWN_KEY, ZeroTrustAction.CHALLENGE, Map.of());

        assertThatThrownBy(() -> service.releaseChallenge(typed, ADMIN, "it was me"))
                .isInstanceOf(AccessDeniedException.class);

        assertThat(actions.getActionFromHash(OWN_KEY)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("session reuse: the verification of another session opens nothing here")
    void theVerificationOfAnotherSession() {
        MockHttpServletRequest other = aRequest("another-session", true);
        verifications.setVerified(OWN_KEY, contextOf(other));
        aRequest(SESSION, true);
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("session reuse: a verification kept for no session opens nothing")
    void aVerificationOfNoSession() {
        verifications.setVerified(OWN_KEY);
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("session reuse: the verification of a BLOCK lifted earlier answers no later one")
    void theVerificationOfAnEarlierBlock() {
        verifications.setVerified(OWN_KEY, here());
        actions.approveOverrideAtomically(OWN_KEY, ZeroTrustAction.ALLOW);
        actions.saveAction(OWN_KEY, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(OWN_KEY);
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("the application user's verification is not the console's")
    void theApplicationUsersVerification() {
        verifications.setVerified(ADMIN, here());
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    /**
     * The application's user is free to be called console::rcboss, shares the browser's session with the console, and
     * passes a factor of their own: that is written under the console's key, from the application's chain.
     */
    @Test
    @DisplayName("an application user named like the console's key, in the same session, verifies nothing for the console")
    void anApplicationUserNamedLikeTheKey() {
        MockHttpServletRequest application = aRequest(SESSION, false);
        verifications.setVerified(OWN_KEY, contextOf(application));
        aRequest(SESSION, true);
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("without a store of verifications nobody releases themselves")
    void noStore() {
        verifications.setVerified(OWN_KEY, here());
        service.setBlockMfaStateStore(null);
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("without a request nothing tells a verification: it stays refused")
    void noRequest() {
        verifications.setVerified(OWN_KEY, here());
        RequestContextHolder.resetRequestAttributes();
        BlockedUser row = row(ADMIN, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("the attempt stays in the audit, with who tried and on what")
    void aRefusalIsAudited() {
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);

        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getPrincipalName()).isEqualTo(ADMIN);
        assertThat(record.getValue().getResourceIdentifier()).isEqualTo(OWN_KEY);
        assertThat(record.getValue().getOutcome()).isEqualTo("REFUSED");
    }

    @Test
    @DisplayName("an audit that fails does not turn the refusal into a release")
    void anAuditThatFails() {
        doThrow(new IllegalStateException("audit down")).when(audit).recordAsync(any());
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);
    }

    @Test
    @DisplayName("another administrator lifts it")
    void anotherAdministrator() {
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        service.resolveBlockById(7L, "second-admin", "ALLOW", "checked with rcboss");

        assertResolved(row, "second-admin");
    }

    @Test
    @DisplayName("the session that passed the verification lifts it, and the record says who")
    void aVerifiedSession() {
        verifications.setVerified(OWN_KEY, here());
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.BLOCKED);

        service.resolveBlockById(7L, ADMIN, "ALLOW", "verified");

        assertResolved(row, ADMIN);
    }

    @Test
    @DisplayName("a verified session may also clear its own record")
    void aVerifiedSessionDeletesItsRecord() {
        verifications.setVerified(OWN_KEY, here());
        BlockedUser row = row(OWN_KEY, BlockedUserStatus.RESOLVED);

        service.deleteBlockRecord(7L, ADMIN);

        verify(rows).delete(row);
    }

    @Test
    @DisplayName("a session under a BLOCK does not lift the BLOCK of someone else either")
    void someoneElse() {
        actions.saveAction(OWN_KEY, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(OWN_KEY);
        BlockedUser row = row("alice", BlockedUserStatus.BLOCKED);

        assertThatThrownBy(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "checked"))
                .isInstanceOf(AccessDeniedException.class);

        assertThat(row.getStatus()).isEqualTo(BlockedUserStatus.BLOCKED);
        assertThat(row.getResolvedBy()).isNull();
    }

    @Test
    @DisplayName("the application's user of that name is someone else")
    void theApplicationsUserOfThatName() {
        BlockedUser row = row(ADMIN, BlockedUserStatus.BLOCKED);

        service.resolveBlockById(7L, ADMIN, "ALLOW", "checked");

        assertResolved(row, ADMIN);
    }

    @Test
    @DisplayName("an application that tells names apart by case has two administrators in them")
    void namesToldApartByCase() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setNormalizeUserKeys(false);
        ZeroTrustUserKey.bind(properties);
        try {
            BlockedUser other = row("console::RCBOSS", BlockedUserStatus.BLOCKED);

            service.resolveBlockById(7L, ADMIN, "ALLOW", "checked");

            assertResolved(other, ADMIN);
        } finally {
            ZeroTrustUserKey.unbind(properties);
        }
    }

    @Test
    @DisplayName("where console and application share an account the same rule reads the plain name")
    void oneAccountForBoth() {
        aRequest(SESSION, false);
        BlockedUser row = row(ADMIN, BlockedUserStatus.BLOCKED);

        assertRefused(() -> service.resolveBlockById(7L, ADMIN, "ALLOW", "it was me"), row, BlockedUserStatus.BLOCKED);

        verifications.setVerified(ADMIN, here());
        service.resolveBlockById(7L, ADMIN, "ALLOW", "verified");

        assertResolved(row, ADMIN);
    }

    @Test
    @DisplayName("the block list asks for a verification only from a console session that stands under its own BLOCK")
    void whoIsAskedToVerify() {
        assertThat(service.ownBlockAwaitsVerification(ADMIN)).as("no BLOCK").isFalse();

        actions.saveAction(OWN_KEY, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(OWN_KEY);
        assertThat(service.ownBlockAwaitsVerification(ADMIN)).isTrue();

        verifications.setVerified(OWN_KEY, here());
        assertThat(service.ownBlockAwaitsVerification(ADMIN)).as("verified here").isFalse();

        actions.removeBlockedFlag(OWN_KEY);
        actions.saveAction(ADMIN, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(ADMIN);
        aRequest(SESSION, false);
        assertThat(service.ownBlockAwaitsVerification(ADMIN)).as("no console session").isFalse();
    }
}
