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
package io.contexa.contexacore.security.async;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (4.3, F7): a refresh keeps every record of the user's session another day in either mode, and leaves the
 * session's own record as it was written, as the Redis provider extends its keys without rewriting them.
 */
abstract class AbstractAsyncSecurityContextProviderContractTest {

    protected final String user = "z16-async-user-" + UUID.randomUUID();
    protected final String session = "z16-async-session-" + UUID.randomUUID();

    protected abstract AsyncSecurityContextProvider provider();

    /** Time passes for the records of the provider. */
    protected abstract void elapse(Duration elapsed);

    @Test
    void aRefreshKeepsEveryRecordOfTheSessionAnotherDay() {
        provider().saveAuthenticationForAsync(authentication(), session);
        elapse(Duration.ofHours(20));

        provider().refreshExpiration(user, session);
        elapse(Duration.ofHours(20));

        assertThat(provider().getAuthenticationBySessionId(session)).get()
                .extracting(AsyncAuthenticationData::getUserId).isEqualTo(user);
        assertThat(provider().getAuthenticationByUserId(user)).isPresent();
    }

    @Test
    void aRefreshLeavesTheSessionsRecordAsItWasWritten() throws InterruptedException {
        provider().saveAuthenticationForAsync(authentication(), session);
        Instant written = provider().getAuthenticationBySessionId(session).orElseThrow().getExpiresAt();
        Thread.sleep(20);

        provider().refreshExpiration(user, session);

        assertThat(provider().getAuthenticationBySessionId(session).orElseThrow().getExpiresAt()).isEqualTo(written);
        assertThat(provider().getAuthenticationByUserId(user).orElseThrow().getExpiresAt()).isAfter(written);
    }

    private UsernamePasswordAuthenticationToken authentication() {
        return UsernamePasswordAuthenticationToken.authenticated(user, null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
    }
}
