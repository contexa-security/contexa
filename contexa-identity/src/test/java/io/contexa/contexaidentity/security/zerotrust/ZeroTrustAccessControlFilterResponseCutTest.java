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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockableResponseWrapper;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The access filter's part in cutting a response (docs/showcase/응답차단-수정계획.md RT-5, R-1): the response start is
 * read before the decision in force, a cut leaves the block signal in place for the user's other responses in flight,
 * and a failure that is not a cut is not taken for one.
 */
class ZeroTrustAccessControlFilterResponseCutTest {

    private static final String USER = "cut-user";
    private static final String MARKER = "\n__CONTEXA_RESPONSE_BLOCKED__:BLOCK\n";

    private final ZeroTrustActionRepository decisions = mock(ZeroTrustActionRepository.class);
    private final AtomicLong decisionReadAt = new AtomicLong();
    private InMemoryBlockingSignalBroadcaster signals;
    private ZeroTrustAccessControlFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        signals = new InMemoryBlockingSignalBroadcaster();
        when(decisions.getCurrentAction(eq(USER), any())).thenAnswer(invocation -> {
            decisionReadAt.set(System.nanoTime());
            return ZeroTrustAction.PENDING_ANALYSIS;
        });
        filter = new ZeroTrustAccessControlFilter(decisions, mock(AuthResponseWriter.class), null, null, null, signals,
                2);
        request = new MockHttpServletRequest("GET", "/api/exports/stream");
        response = new MockHttpServletResponse();
        SecurityContextHolder.setContext(new SecurityContextImpl(
                UsernamePasswordAuthenticationToken.authenticated(USER, null, List.of())));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private static byte[] row(int n) {
        return ("{\"row\":" + n + "}\n").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("the response start is read before the decision in force, so a BLOCK written in between cuts it")
    void theResponseStartIsReadBeforeTheDecision() throws Exception {
        AtomicReference<BlockableResponseWrapper> wrapped = new AtomicReference<>();

        filter.doFilter(request, response, (req, res) -> wrapped.set((BlockableResponseWrapper) res));

        assertThat(wrapped.get()).isNotNull();
        assertThat(wrapped.get().responseStartNanos() - decisionReadAt.get()).isNegative();
    }

    @Test
    @DisplayName("a cut byte response leaves the signal, so the user's other responses in flight are cut too")
    void aCutLeavesTheSignalInPlace() throws Exception {
        assertThatThrownBy(() -> filter.doFilter(request, response, (req, res) -> {
            res.getOutputStream().write(row(1));
            res.getOutputStream().flush();
            signals.registerBlock(USER);
            res.getOutputStream().write(row(2));
        })).isInstanceOf(IOException.class);

        assertThat(signals.isBlocked(USER)).isTrue();
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo("{\"row\":1}\n" + MARKER);
    }

    @Test
    @DisplayName("a cut character response leaves the signal too, and ends as an I/O failure")
    void aCutWriterLeavesTheSignalInPlace() throws Exception {
        assertThatThrownBy(() -> filter.doFilter(request, response, (req, res) -> {
            res.getWriter().println("<p>row 1</p>");
            res.getWriter().flush();
            signals.registerBlock(USER);
            res.getWriter().println("<p>row 2</p>");
        })).isInstanceOf(IOException.class);

        assertThat(signals.isBlocked(USER)).isTrue();
        assertThat(response.getContentAsString(StandardCharsets.UTF_8)).endsWith(MARKER);
    }

    @Test
    @DisplayName("an I/O failure that is not a cut propagates as it is, even while an older signal stays")
    void anotherFailureIsNotTakenForACut() {
        signals.registerBlock(USER);
        IOException gone = new IOException("Broken pipe");

        assertThatThrownBy(() -> filter.doFilter(request, response, (req, res) -> {
            throw gone;
        })).isSameAs(gone);

        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(signals.isBlocked(USER)).isTrue();
    }
}
