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
package io.contexa.autoconfigure.iam.admin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.ControllerAdvice;

import static org.assertj.core.api.Assertions.assertThat;

class HostOwnedConsoleModelAdviceTest {

    /**
     * Ownership browser check 2026-11-03: the console header posted its sign-out to /logout, the application's own
     * sign-out under HOST_OWNED, so an administrator signing out of the console signed the application user out (or got
     * the application's CSRF refusal). The header takes the console's sign-out from this advice.
     */
    @Test
    @DisplayName("the console header signs out of the console, not of the application")
    void signsOutOfTheConsole() {
        HostOwnedConsoleModelAdvice advice = new HostOwnedConsoleModelAdvice();

        assertThat(advice.adminLogoutUrl()).isEqualTo(HostOwnedAdminConsoleAutoConfiguration.LOGOUT_URL)
                .isEqualTo("/contexa/admin/logout");
        assertThat(HostOwnedConsoleModelAdvice.class.getAnnotation(ControllerAdvice.class).basePackages())
                .containsExactly("io.contexa");
    }
}
