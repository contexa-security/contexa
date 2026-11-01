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

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (4.3, F5): an MFA session lasts its timeout from the last MFA event in either mode, and storing it leaves the
 * idle limit of the user's HTTP session alone. Where each mode keeps the MFA session (the HTTP session, a Redis key and
 * its cookie) stays as designed; every request here carries both.
 */
abstract class AbstractMfaSessionRepositoryContractTest {

    private static final int HTTP_SESSION_IDLE_SECONDS = 3600;

    protected final List<String> storedIds = new ArrayList<>();
    private final MockHttpSession httpSession = new MockHttpSession();

    protected abstract MfaSessionRepository createRepository(Duration timeout);

    @BeforeEach
    void startHttpSession() {
        httpSession.setMaxInactiveInterval(HTTP_SESSION_IDLE_SECONDS);
    }

    @Test
    void storingAnMfaSessionLeavesTheHttpSessionsIdleLimitAlone() {
        MfaSessionRepository repository = createRepository(Duration.ofMinutes(10));

        String id = store(repository);

        assertThat(repository.existsSession(id)).isTrue();
        assertThat(httpSession.getMaxInactiveInterval()).isEqualTo(HTTP_SESSION_IDLE_SECONDS);
    }

    @Test
    void anMfaSessionLastsItsTimeoutFromTheLastMfaEvent() throws InterruptedException {
        MfaSessionRepository repository = createRepository(Duration.ofMillis(1_000));
        String id = store(repository);

        Thread.sleep(600);
        repository.refreshSession(id);
        Thread.sleep(600);
        assertThat(repository.existsSession(id)).as("within the timeout of the MFA event").isTrue();
        assertThat(repository.getSessionId(nextRequest(id))).isEqualTo(id);

        Thread.sleep(600);
        assertThat(repository.existsSession(id)).as("requests without an MFA event do not keep it").isFalse();
        assertThat(repository.getSessionId(nextRequest(id))).isNull();
        assertThat(repository.isSessionIdUnique(id)).isTrue();
    }

    @Test
    void aRemovedMfaSessionIsGone() {
        MfaSessionRepository repository = createRepository(Duration.ofMinutes(10));
        String id = store(repository);

        repository.removeSession(id, nextRequest(id), null);

        assertThat(repository.existsSession(id)).isFalse();
        assertThat(repository.getSessionId(nextRequest(id))).isNull();
    }

    private String store(MfaSessionRepository repository) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(httpSession);
        String id = repository.generateUniqueSessionId(null, request);
        repository.storeSession(id, request, new MockHttpServletResponse());
        storedIds.add(id);
        return id;
    }

    /** A later request of the user: its HTTP session and the MFA cookie. */
    private MockHttpServletRequest nextRequest(String id) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(httpSession);
        request.setCookies(new Cookie("MFA_SID", id));
        return request;
    }
}
