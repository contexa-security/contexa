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

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** K76: the account's column says whether its password is past the policy's days, as a sign-in reads it. */
class LoginPolicyCredentialsExpiryTest {

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordPolicyService policies = mock(PasswordPolicyService.class);
    @SuppressWarnings("unchecked")
    private final LoginPolicyService service = new LoginPolicyService(users, mock(LoginAttemptIpRepository.class),
            policies, mock(LoginAttemptIpUpserter.class), mock(ObjectProvider.class));

    @Test
    void aPasswordPastThePolicysDaysIsExpiredAndTheAccountSaysSo() {
        policy(30);
        account("carol", LocalDateTime.now().minusDays(40), false);

        assertThat(service.isCredentialsExpired("carol")).isTrue();

        verify(users).markCredentialsExpired("carol", true);
    }

    @Test
    void anAccountThatSaidExpiredWithinThePolicysDaysSaysOtherwise() {
        policy(30);
        account("dave", LocalDateTime.now().minusDays(5), true);

        assertThat(service.isCredentialsExpired("dave")).isFalse();

        verify(users).markCredentialsExpired("dave", false);
    }

    @Test
    void anAccountAlreadySayingWhatThePolicyReadsIsNotWritten() {
        policy(30);
        account("erin", LocalDateTime.now().minusDays(40), true);
        account("frank", null, false);

        assertThat(service.isCredentialsExpired("erin")).isTrue();
        assertThat(service.isCredentialsExpired("frank")).as("a password never changed is not read").isFalse();

        verify(users, never()).markCredentialsExpired(anyString(), anyBoolean());
    }

    @Test
    void passwordsThatLiveForEverReadNoAccount() {
        policy(0);

        assertThat(service.isCredentialsExpired("carol")).isFalse();

        verify(users, never()).findByUsername(anyString());
    }

    private void policy(int expiryDays) {
        PasswordPolicy policy = PasswordPolicy.builder().build();
        policy.setPasswordExpiryDays(expiryDays);
        when(policies.getCurrentPolicy()).thenReturn(policy);
    }

    private void account(String username, LocalDateTime passwordChangedAt, boolean credentialsExpired) {
        Users user = new Users();
        user.setUsername(username);
        user.setPasswordChangedAt(passwordChangedAt);
        user.setCredentialsExpired(credentialsExpired);
        when(users.findByUsername(username)).thenReturn(Optional.of(user));
    }
}
