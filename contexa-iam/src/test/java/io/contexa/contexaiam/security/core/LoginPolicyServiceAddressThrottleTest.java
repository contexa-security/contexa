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
package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.entity.LoginAttemptIp;
import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginAddressBlockedException;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** PR-69: the address throttle was written and never read at sign-in. */
class LoginPolicyServiceAddressThrottleTest {

    private static final String ADDRESS = "203.0.113.7";

    private final UserRepository users = mock(UserRepository.class);
    private final LoginAttemptIpRepository addresses = mock(LoginAttemptIpRepository.class);
    private final PasswordPolicyService policies = mock(PasswordPolicyService.class);
    private final LoginAttemptIpUpserter upserter = mock(LoginAttemptIpUpserter.class);
    private LoginPolicyService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        PasswordPolicy policy = new PasswordPolicy();
        policy.setMaxFailedAttempts(5);
        policy.setIpMaxFailedAttempts(30);
        policy.setIpWindowMinutes(15);
        when(policies.getCurrentPolicy()).thenReturn(policy);
        service = new LoginPolicyService(users, addresses, policies, upserter, mock(ObjectProvider.class));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr(ADDRESS);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void clear() {
        LoginPolicyService.clearRequestState();
        RequestContextHolder.resetRequestAttributes();
    }

    private static LoginAttemptIp row(int failures, LocalDateTime blockedUntil) {
        return LoginAttemptIp.builder()
                .ipAddress(ADDRESS)
                .failedAttempts(failures)
                .windowStartAt(LocalDateTime.now().minusMinutes(1))
                .blockedUntil(blockedUntil)
                .build();
    }

    @Test
    @DisplayName("a sign-in from an address under a block is refused")
    void aBlockedAddressIsRefused() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().plusMinutes(10))));

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
    }

    @Test
    @DisplayName("a block that has run out refuses nothing, and neither does an address without a record")
    void anExpiredBlockIsNoBlock() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().minusSeconds(1))));
        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();

        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.empty());
        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a refused attempt is counted against neither the account nor the address")
    void aRefusedAttemptIsNotCounted() {
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, LocalDateTime.now().plusMinutes(10))));

        assertThatThrownBy(() -> service.checkSignInAddress("admin")).isInstanceOf(LoginAddressBlockedException.class);
        // what the failure event and the failure handler report for the same request
        service.onLoginFailure("admin", ADDRESS, "LoginAddressBlockedException", "EVENT");
        service.onLoginFailure("admin");

        verify(users, never()).incrementFailedAttempts(anyString());
        verify(addresses, never()).incrementFailedAttempts(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("whoever keeps trying from a blocked address does not extend its block")
    void attemptsUnderABlockDoNotExtendIt() {
        LocalDateTime until = LocalDateTime.now().plusMinutes(10);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, until)));
        when(users.incrementFailedAttempts("admin")).thenReturn(0);

        service.onLoginFailure("admin", ADDRESS, "PasswordChange", "PASSWORD_CHANGE");

        verify(addresses, never()).blockIp(anyString(), any());
        verify(addresses, never()).incrementFailedAttempts(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("the attempt that reaches the limit blocks the address")
    void theLimitBlocks() {
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), anyString())).thenReturn(1);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(30, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        service.onLoginFailure("nobody", ADDRESS, "BadCredentialsException", "EVENT");

        verify(addresses, times(1)).blockIp(eq(ADDRESS), any());
    }

    @Test
    @DisplayName("the attempt before the limit does not")
    void beforeTheLimit() {
        when(addresses.incrementFailedAttempts(eq(ADDRESS), any(), anyString())).thenReturn(1);
        when(addresses.findByIpAddress(ADDRESS)).thenReturn(Optional.of(row(29, null)));
        when(users.incrementFailedAttempts("nobody")).thenReturn(0);

        service.onLoginFailure("nobody", ADDRESS, "BadCredentialsException", "EVENT");

        verify(addresses, never()).blockIp(anyString(), any());
    }

    @Test
    @DisplayName("the throttle failing never turns into a failed sign-in")
    void theDatabaseFailingDoesNotRefuse() {
        when(addresses.findByIpAddress(ADDRESS)).thenThrow(new DataAccessResourceFailureException("database down"));

        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("outside a request there is no address to refuse")
    void outsideARequest() {
        RequestContextHolder.resetRequestAttributes();

        assertThatCode(() -> service.checkSignInAddress("admin")).doesNotThrowAnyException();
        verify(addresses, never()).findByIpAddress(any());
    }

    /** The follow-up increment counts the attempt: a first row of one would count the first failure twice. */
    @Test
    @DisplayName("the first failure of an address counts once")
    void theFirstFailureCountsOnce() {
        LoginAttemptIpRepository repository = mock(LoginAttemptIpRepository.class);

        new LoginAttemptIpUpserter(repository).insertIfAbsent(ADDRESS, LocalDateTime.now(), "nobody");

        ArgumentCaptor<LoginAttemptIp> saved = ArgumentCaptor.forClass(LoginAttemptIp.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getFailedAttempts()).isZero();
    }
}
