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
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Before any sign-in, the current password is all that stands in front of the account: nothing here may tell a stranger
 * more than "wrong", and every wrong guess has to count.
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
        service = new PasswordChangeService(userRepository, passwordEncoder, passwordPolicyService, loginPolicy);
    }

    private void assertRefusedAsWrong(String username, String currentPassword) {
        assertThatThrownBy(() -> service.changePassword(username, currentPassword, "New-Pass-1", "New-Pass-1", IP))
                .isInstanceOfSatisfying(PasswordChangeService.PasswordChangeException.class,
                        e -> assertThat(e.getMessageKey()).isEqualTo(WRONG));
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("the right current password changes the password and counts nothing against the account")
    void rightPassword() {
        service.changePassword("admin", "correct", "New-Pass-1", "New-Pass-1", IP);

        assertThat(user.getPassword()).isEqualTo("{hash}new");
        verify(userRepository).save(user);
        verify(policy, never()).onLoginFailure(anyString(), any(), anyString(), anyString());
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

        assertRefusedAsWrong("admin", "correct");

        verify(policy, never()).onLoginFailure(anyString(), any(), anyString(), anyString());
    }

    @Test
    @DisplayName("a lock that ran out is cleared before the account is read")
    void expiredLockIsClearedFirst() {
        service.changePassword("admin", "correct", "New-Pass-1", "New-Pass-1", IP);

        InOrder order = inOrder(policy, userRepository);
        order.verify(policy).checkAndUnlockIfExpired("admin");
        order.verify(userRepository).findByUsername("admin");
    }

    @Test
    @DisplayName("a blocked address is refused even with the right password")
    void blockedAddress() {
        when(policy.isIpBlocked(IP)).thenReturn(true);

        assertRefusedAsWrong("admin", "correct");
    }

    @Test
    @DisplayName("an account without a password is refused, not an error")
    void accountWithoutPassword() {
        user.setPassword(null);

        assertRefusedAsWrong("admin", "guess");
    }

    @Test
    @DisplayName("without a login policy the current password still decides")
    void withoutPolicy() {
        when(loginPolicy.getIfAvailable()).thenReturn(null);

        assertRefusedAsWrong("admin", "guess");
        service.changePassword("admin", "correct", "New-Pass-1", "New-Pass-1", IP);

        verify(userRepository).save(user);
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
}
