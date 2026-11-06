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

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.MfaPendingSession;
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Before any sign-in, the current password is all that stands in front of the account: nothing here may tell a stranger
 * more than "wrong", and every wrong guess has to count. The password alone changes nothing either: a sign-in meets a
 * second factor, so only an account that cannot sign in and the signed-in owner change a password here.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PasswordChangeServiceTest {

    private static final String IP = "203.0.113.7";
    private static final String WRONG = "msg.password.change.current.incorrect";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private ObjectProvider<LoginPolicyHandler> loginPolicy;

    @Mock
    private LoginPolicyHandler policy;

    @Mock
    private ObjectProvider<ZeroTrustActionRepository> decisions;

    @Mock
    private ApplicationEventPublisher events;

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/password-change");

    private boolean enforced = true;
    private PasswordChangeService service;
    private Users user;

    @BeforeEach
    void setUp() {
        user = new Users();
        user.setUsername("admin");
        user.setPassword("{hash}old");
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct", "{hash}old")).thenReturn(true);
        when(passwordEncoder.encode(anyString())).thenReturn("{hash}new");
        when(passwordPolicyService.validatePassword(anyString())).thenReturn(List.of());
        when(loginPolicy.getIfAvailable()).thenReturn(policy);
        when(decisions.getIfAvailable()).thenReturn(actions);
        service = new PasswordChangeService(userRepository, passwordEncoder, passwordPolicyService, loginPolicy,
                decisions, () -> enforced, events);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    private void change() {
        service.changePassword("admin", "correct", "New-Pass-1", "New-Pass-1", IP);
    }

    private void assertChanged() {
        change();

        assertThat(user.getPassword()).isEqualTo("{hash}new");
        verify(userRepository).save(user);
        verify(policy, never()).onLoginFailure(anyString(), any(), anyString(), anyString());
    }

    private void assertRefusedAsWrong(String username, String currentPassword) {
        assertThatThrownBy(() -> service.changePassword(username, currentPassword, "New-Pass-1", "New-Pass-1", IP))
                .isInstanceOfSatisfying(PasswordChangeService.PasswordChangeException.class,
                        e -> assertThat(e.getMessageKey()).isEqualTo(WRONG));
        verify(userRepository, never()).save(any());
    }

    /** The right password is refused, and the refusal is held against nobody. */
    private void assertRightPasswordRefused() {
        assertRefusedAsWrong("admin", "correct");

        assertThat(user.getPassword()).isEqualTo("{hash}old");
        verify(policy, never()).onLoginFailure(anyString(), any(), anyString(), anyString());
    }

    private void expired() {
        user.setCredentialsExpired(true);
    }

    private void signedInAs(String name) {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(name, null, AuthorityUtils.NO_AUTHORITIES));
    }

    private void decided(String key, ZeroTrustAction action) {
        actions.saveAction(key, action, Map.of());
    }

    @Test
    @DisplayName("a wrong current password counts as a failed sign-in")
    void wrongPasswordCounts() {
        assertRefusedAsWrong("admin", "guess");

        verify(policy).onLoginFailure(eq("admin"), eq(IP), anyString(), anyString());
    }

    @Test
    @DisplayName("an unknown name answers as a wrong password, after comparing as long, and still throttles the address")
    void unknownNameTellsNothing() {
        assertRefusedAsWrong("nobody", "guess");

        verify(passwordEncoder).matches("guess", "{hash}new");
        verify(policy).onLoginFailure(eq("nobody"), eq(IP), anyString(), anyString());
    }

    @Test
    @DisplayName("a locked account is refused even with the right password, and its lock is not extended")
    void lockedAccount() {
        user.setAccountLocked(true);
        expired();

        assertRightPasswordRefused();
    }

    @Test
    @DisplayName("a lock that ran out is cleared before the account is read")
    void expiredLockIsClearedFirst() {
        expired();

        change();

        InOrder order = inOrder(policy, userRepository);
        order.verify(policy).checkAndUnlockIfExpired("admin");
        order.verify(userRepository).findByUsername("admin");
    }

    @Test
    @DisplayName("a blocked address is refused even with the right password, and its attempt counts against nobody")
    void blockedAddress() {
        expired();
        when(policy.isIpBlocked(IP)).thenReturn(true);

        assertRefusedAsWrong("admin", "correct");
        assertRefusedAsWrong("admin", "guess");

        verify(policy, never()).onLoginFailure(anyString(), any(), anyString(), anyString());
    }

    @Test
    @DisplayName("an account without a password is refused, not an error")
    void accountWithoutPassword() {
        user.setPassword(null);

        assertRefusedAsWrong("admin", "guess");
    }

    @Test
    @DisplayName("without a login policy the current password and the expired mark still decide")
    void withoutPolicy() {
        when(loginPolicy.getIfAvailable()).thenReturn(null);
        expired();

        assertRefusedAsWrong("admin", "guess");
        change();

        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("without a login policy an account not marked expired stays refused")
    void withoutPolicyNotExpired() {
        when(loginPolicy.getIfAvailable()).thenReturn(null);

        assertRefusedAsWrong("admin", "correct");
    }

    /** The count is written in the transaction of the method whose exception reports the failure. */
    @Test
    @DisplayName("the failure count outlives the exception that reports it")
    void theCountIsNotRolledBack() throws NoSuchMethodException {
        Transactional transactional = PasswordChangeService.class
                .getMethod("changePassword", String.class, String.class, String.class, String.class, String.class)
                .getAnnotation(Transactional.class);

        assertThat(transactional.noRollbackFor()).contains(PasswordChangeService.PasswordChangeException.class);
    }

    @Nested
    @DisplayName("before any sign-in")
    class BeforeSignIn {

        @Test
        @DisplayName("a stolen password does not change the password of an account that can still sign in")
        void aPasswordAloneChangesNothing() {
            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("an anonymous visitor is nobody signed in")
        void anAnonymousVisitor() {
            SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "admin",
                    AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("an account marked expired changes its password")
        void markedExpired() {
            expired();

            assertChanged();
        }

        @Test
        @DisplayName("an account past the age of the policy changes its password")
        void pastThePolicyAge() {
            when(policy.isCredentialsExpired("admin")).thenReturn(true);

            assertChanged();
        }

        @ParameterizedTest
        @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "ESCALATE"})
        @DisplayName("a stored BLOCK or ESCALATE stops the expired account")
        void aDecisionStopsTheExpiredAccount(ZeroTrustAction action) {
            expired();
            decided("admin", action);

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("a CHALLENGE leaves the expired account alone: it could only be answered after a sign-in")
        void aChallengeLeavesTheExpiredAccountAlone() {
            expired();
            decided("admin", ZeroTrustAction.CHALLENGE);

            assertChanged();
        }

        @Test
        @DisplayName("a BLOCK is read for the expired account whatever request asks")
        void aBlockIsReadWithoutAContext() {
            expired();
            actions.setBlockedFlag("admin");

            assertRightPasswordRefused();
        }
    }

    @Nested
    @DisplayName("a signed-in user")
    class SignedIn {

        @Test
        @DisplayName("changes the password of the account it signed in with, expired or not")
        void theOwnerChangesIt() {
            signedInAs("admin");

            assertChanged();
        }

        @Test
        @DisplayName("does not change the password of another account")
        void anotherAccount() {
            signedInAs("someone-else");

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("does not change the password of another account that expired either")
        void anotherAccountThatExpired() {
            signedInAs("someone-else");
            expired();

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("a wrong current password counts as for anybody else")
        void aWrongPasswordCounts() {
            signedInAs("admin");

            assertRefusedAsWrong("admin", "guess");

            verify(policy).onLoginFailure(eq("admin"), eq(IP), anyString(), anyString());
        }

        @Test
        @DisplayName("a session that waits for its MFA holds an authentication that proves the password alone")
        void mfaPending() {
            signedInAs("admin");
            request.getSession().setAttribute(MfaPendingSession.ATTRIBUTE, "mfa");

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("a session that waits for its MFA is as anybody else for an account that expired")
        void mfaPendingExpired() {
            signedInAs("admin");
            request.getSession().setAttribute(MfaPendingSession.ATTRIBUTE, "mfa");
            expired();

            assertChanged();
        }

        @ParameterizedTest
        @EnumSource(value = ZeroTrustAction.class, names = {"CHALLENGE", "BLOCK", "ESCALATE"})
        @DisplayName("a stored restriction stops the session")
        void aRestrictionStopsTheSession(ZeroTrustAction action) {
            signedInAs("admin");
            decided("admin", action);

            assertRightPasswordRefused();
        }

        @ParameterizedTest
        @EnumSource(value = ZeroTrustAction.class, names = {"CHALLENGE", "BLOCK", "ESCALATE"})
        @DisplayName("a restriction stops the session of an account that expired as well")
        void aRestrictionStopsTheSessionOfAnExpiredAccount(ZeroTrustAction action) {
            signedInAs("admin");
            decided("admin", action);
            expired();

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("the session that answered the CHALLENGE changes the password, and every other session stays stopped")
        void theSessionThatAnsweredGoesOn() {
            signedInAs("admin");
            request.addHeader("User-Agent", "the-owner");
            String owner = SessionFingerprintUtil.generateContextBindingHash(request);
            decided("admin", ZeroTrustAction.CHALLENGE);
            actions.holdChallengeForOtherSessions("admin", owner);
            actions.saveActionWithPrevious("admin", ZeroTrustAction.ALLOW, owner);

            MockHttpServletRequest thief = new MockHttpServletRequest("POST", "/contexa/password-change");
            thief.addHeader("User-Agent", "the-thief");
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(thief));
            assertRightPasswordRefused();

            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
            assertChanged();
        }

        @Test
        @DisplayName("an ALLOW and an analysis not finished leave the session alone")
        void nothingStoredAgainstTheSession() {
            signedInAs("admin");
            decided("admin", ZeroTrustAction.PENDING_ANALYSIS);

            assertChanged();
        }

        @Test
        @DisplayName("an agent acting for the user is not the user")
        void anAgentIsNotTheUser() {
            signedInAs("admin");
            request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("admin", "report-agent",
                    true, null, null, null, null, null, null, null, null));

            assertRightPasswordRefused();
        }
    }

    @Nested
    @DisplayName("what is enforced")
    class Enforcement {

        @Test
        @DisplayName("a decision that is only observed stops nobody, as everywhere else")
        void aDecisionNotEnforced() {
            enforced = false;
            signedInAs("admin");
            decided("admin", ZeroTrustAction.BLOCK);

            assertChanged();
        }

        @Test
        @DisplayName("without decisions the two ways in still decide")
        void withoutDecisions() {
            when(decisions.getIfAvailable()).thenReturn(null);

            assertRightPasswordRefused();
            signedInAs("admin");
            assertChanged();
        }

        @Test
        @DisplayName("a decision that cannot be read refuses, as a wrong password does, and is no error")
        void aFailingRead() {
            ZeroTrustActionRepository failing = mock(ZeroTrustActionRepository.class);
            when(failing.currentActionOf(any(ZeroTrustSubject.class), any()))
                    .thenThrow(new IllegalStateException("store down"));
            when(decisions.getIfAvailable()).thenReturn(failing);
            signedInAs("admin");

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("a console session reads the decisions of the console, not those of the application's user of its name")
        void aConsoleSessionReadsItsOwnKey() {
            ConsoleSession.mark(request);
            signedInAs("admin");
            decided("admin", ZeroTrustAction.BLOCK);

            assertChanged();
        }

        @Test
        @DisplayName("a restriction of the console stops the console session")
        void aRestrictionOfTheConsole() {
            ConsoleSession.mark(request);
            signedInAs("admin");
            decided(ZeroTrustSubject.CONSOLE_KEY + "admin", ZeroTrustAction.CHALLENGE);

            assertRightPasswordRefused();
        }
    }

    @Nested
    @DisplayName("what a new password ends")
    class WhatItEnds {

        @Test
        @DisplayName("a saved password tells what is open, for the sessions and tokens of its owner")
        void aSavedPasswordTells() {
            expired();

            change();

            InOrder order = inOrder(userRepository, events);
            order.verify(userRepository).save(user);
            order.verify(events).publishEvent(new UserPasswordChangedEvent("admin"));
        }

        @Test
        @DisplayName("a refused password tells nobody: the owner's sessions stay")
        void aRefusedPasswordTellsNobody() {
            assertRightPasswordRefused();

            verify(events, never()).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("a password the policy refuses tells nobody")
        void aPasswordThePolicyRefuses() {
            expired();
            when(passwordPolicyService.validatePassword("New-Pass-1")).thenReturn(List.of("Too short"));

            assertThatThrownBy(PasswordChangeServiceTest.this::change)
                    .isInstanceOf(PasswordChangeService.PasswordChangeException.class);

            verify(events, never()).publishEvent(any(Object.class));
        }
    }

    @Nested
    @DisplayName("an account that may not sign in")
    class AccountState {

        @Test
        @DisplayName("a disabled account does not change its password when it expired")
        void disabledAndExpired() {
            user.setEnabled(false);
            expired();

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("a disabled account does not change its password from a session that outlived it")
        void disabledAndSignedIn() {
            user.setEnabled(false);
            signedInAs("admin");

            assertRightPasswordRefused();
        }

        @Test
        @DisplayName("a wrong password on a disabled account counts as before")
        void aWrongPasswordOnADisabledAccount() {
            user.setEnabled(false);

            assertRefusedAsWrong("admin", "guess");

            verify(policy).onLoginFailure(eq("admin"), eq(IP), anyString(), anyString());
        }

        @Test
        @DisplayName("an account of an outside identity has no password of its own to change")
        void anOutsideIdentity() {
            user.setExternalAuthOnly(true);
            expired();

            assertRightPasswordRefused();
        }
    }
}
