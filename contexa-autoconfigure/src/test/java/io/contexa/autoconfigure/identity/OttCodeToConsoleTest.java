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

import static org.assertj.core.api.Assertions.assertThat;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** Where one-time codes go to the log as well: development and tests, a start without a mail server, or as configured. */
class OttCodeToConsoleTest {

    private static MockEnvironment profiles(String... active) {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(active);
        return environment;
    }

    @Test
    @DisplayName("development and test profiles, and a start without a mail server, write the codes to the log")
    void developmentAndNoMailServer() {
        AuthContextProperties unset = new AuthContextProperties();

        assertThat(IdentityServiceAutoConfiguration.codeToConsole(unset, profiles("local"), true)).isTrue();
        assertThat(IdentityServiceAutoConfiguration.codeToConsole(unset, profiles("test"), true)).isTrue();
        assertThat(IdentityServiceAutoConfiguration.codeToConsole(unset, profiles(), false)).isTrue();
        assertThat(IdentityServiceAutoConfiguration.codeToConsole(unset, profiles("prod"), true)).isFalse();
        assertThat(IdentityServiceAutoConfiguration.codeToConsole(unset, profiles(), true)).isFalse();
    }

    @Test
    @DisplayName("the setting decides when it is given")
    void theSettingDecides() {
        AuthContextProperties off = new AuthContextProperties();
        off.getOtt().setCodeToConsole(false);
        AuthContextProperties on = new AuthContextProperties();
        on.getOtt().setCodeToConsole(true);

        assertThat(IdentityServiceAutoConfiguration.codeToConsole(off, profiles("local"), false)).isFalse();
        assertThat(IdentityServiceAutoConfiguration.codeToConsole(on, profiles("prod"), true)).isTrue();
    }
}
