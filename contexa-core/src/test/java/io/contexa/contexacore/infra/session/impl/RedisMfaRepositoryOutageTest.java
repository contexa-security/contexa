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
package io.contexa.contexacore.infra.session.impl;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * D-19: the in-memory and session repositories never fail a read, so a screen of the MFA flow reads a session it cannot
 * find as one it does not have. On Redis the same read ended the screen in a server error while Redis was away.
 */
class RedisMfaRepositoryOutageTest {

    private static final String SESSION = "mfa-session";

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final SessionIdGenerator generator = mock(SessionIdGenerator.class);
    private final RedisMfaRepository repository = new RedisMfaRepository(redis, generator, new AuthContextProperties());

    private void redisStopsAnswering() {
        when(redis.hasKey(anyString())).thenThrow(new QueryTimeoutException("Redis command timed out"));
    }

    @Test
    @DisplayName("a flow that cannot be read is a flow this request does not have")
    void aFlowThatCannotBeReadIsAbsent() {
        redisStopsAnswering();

        assertThat(repository.existsSession(SESSION)).isFalse();
    }

    @Test
    @DisplayName("the session of a cookie that cannot be read is no session")
    void theSessionOfACookieIsNoSession() {
        when(generator.isValidFormat(SESSION)).thenReturn(true);
        redisStopsAnswering();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("MFA_SID", SESSION));

        assertThat(repository.getSessionId(request)).isNull();
    }

    @Test
    @DisplayName("a new session id is not taken for unique when Redis cannot say so")
    void aNewIdIsNotTakenForUnique() {
        redisStopsAnswering();

        assertThatThrownBy(() -> repository.isSessionIdUnique(SESSION)).isInstanceOf(QueryTimeoutException.class);
    }
}
