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
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** PR-69: what the cleanup leaves behind stops the next failure of the same name on that worker thread from counting. */
class LoginAttemptCleanupFilterTest {

    private final LoginAttemptCleanupFilter filter = new LoginAttemptCleanupFilter();

    @AfterEach
    void clear() {
        LoginPolicyService.clearRequestState();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/login", "/app/assets/login", "/static/sign-in", "/webjars-login", "/images/mfa/login"})
    @DisplayName("every request ends with the marker of its failures gone, whatever its path looks like")
    @SuppressWarnings("unchecked")
    void everyRequestLeavesNothingBehind(String path) throws Exception {
        UserRepository users = mock(UserRepository.class);
        PasswordPolicyService policies = mock(PasswordPolicyService.class);
        when(policies.getCurrentPolicy()).thenReturn(new PasswordPolicy());
        LoginPolicyService service = new LoginPolicyService(users, mock(LoginAttemptIpRepository.class), policies,
                mock(LoginAttemptIpUpserter.class), mock(ObjectProvider.class));

        for (int request = 0; request < 2; request++) {
            filter.doFilter(new MockHttpServletRequest("POST", path), new MockHttpServletResponse(),
                    (servletRequest, servletResponse) -> service.onLoginFailure("nobody", null, "BadCredentialsException", "EVENT"));
        }

        verify(users, times(2)).incrementFailedAttempts("nobody");
    }
}
