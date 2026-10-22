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
package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * How a response is cut once a BLOCK applies to it (docs/showcase/응답차단-수정계획.md RT-3, R-2, R-3): every way of
 * writing it ends the same. Before the response is committed nothing written before the decision goes out: 403 and the
 * marker only. After it is committed the marker follows what already went, and nothing is written after the cut, even
 * when the application catches the failure and writes again.
 */
class BlockableResponseCutTest {

    private static final String MARKER = "\n__CONTEXA_RESPONSE_BLOCKED__:BLOCK\n";
    private static final String USER = "cut-user";

    private InMemoryBlockingSignalBroadcaster signals;
    private MockHttpServletResponse response;
    private BlockableResponseWrapper wrapper;

    @BeforeEach
    void setUp() {
        signals = new InMemoryBlockingSignalBroadcaster();
        response = new MockHttpServletResponse();
        response.setBufferSize(8192);
        wrapper = new BlockableResponseWrapper(response, signals, USER, "/contexa/zero-trust/blocked",
                System.nanoTime());
    }

    private void block() {
        signals.registerBlock(USER);
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * R-12: the engine's own deny response of a BLOCK decided before the response (a synchronous decision) carries no
     * protected data and is not cut; it is found through any wrapper laid over the cut's own.
     */
    @Test
    @DisplayName("the engine's own deny response of a BLOCK is written whole, also through another wrapper")
    void theEnginesOwnDenyResponseIsWrittenWhole() throws IOException {
        block();
        HttpServletResponseWrapper outer = new HttpServletResponseWrapper(wrapper);

        assertThat(BlockableResponseWrapper.permitOwnDenyResponse(outer)).isTrue();
        outer.setStatus(HttpServletResponse.SC_FORBIDDEN);
        outer.getOutputStream().write(bytes("{\"action\":\"BLOCK\"}"));
        outer.flushBuffer();

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo("{\"action\":\"BLOCK\"}");
        assertThat(wrapper.isCut()).isFalse();
        assertThat(BlockableResponseWrapper.permitOwnDenyResponse(new MockHttpServletResponse()))
                .as("a response the access filter did not wrap has nothing to permit").isFalse();
    }

    @Test
    @DisplayName("bytes cut before the commit: the rows written before are dropped, 403 and the marker only")
    void bytesCutBeforeTheCommit() throws IOException {
        ServletOutputStream out = wrapper.getOutputStream();
        out.write(bytes("{\"row\":1}\n"));
        assertThat(response.isCommitted()).isFalse();

        block();

        assertThatThrownBy(() -> out.write(bytes("{\"row\":2}\n"))).isInstanceOf(IOException.class);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo(MARKER);
        assertThat(wrapper.isCut()).isTrue();
    }

    @Test
    @DisplayName("bytes cut after the commit: the marker follows what went, and nothing after the cut")
    void bytesCutAfterTheCommit() throws IOException {
        ServletOutputStream out = wrapper.getOutputStream();
        out.write(bytes("{\"row\":1}\n"));
        out.flush();
        assertThat(response.isCommitted()).isTrue();

        block();

        assertThatThrownBy(() -> out.write(bytes("{\"row\":2}\n"))).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> out.write(bytes("{\"row\":3}\n"))).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> out.write('x')).isInstanceOf(IOException.class);
        out.flush();
        out.close();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentAsString()).isEqualTo("{\"row\":1}\n" + MARKER);
        assertThat(out.isReady()).isFalse();
    }

    @Test
    @DisplayName("characters cut before the commit: 403 and the marker only, as for bytes")
    void charactersCutBeforeTheCommit() throws IOException {
        PrintWriter writer = wrapper.getWriter();
        writer.print("<p>row 1</p>");
        assertThat(response.isCommitted()).isFalse();

        block();

        assertThatThrownBy(() -> writer.print("<p>row 2</p>")).isInstanceOf(ResponseBlockedException.class);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo(MARKER);
        assertThat(wrapper.isCut()).isTrue();
    }

    @Test
    @DisplayName("characters cut after the commit: the marker follows what went, and nothing after the cut")
    void charactersCutAfterTheCommit() throws IOException {
        PrintWriter writer = wrapper.getWriter();
        writer.println("<p>row 1</p>");
        writer.flush();
        assertThat(response.isCommitted()).isTrue();

        block();

        assertThatThrownBy(() -> writer.print("<p>row 2</p>")).isInstanceOf(ResponseBlockedException.class);
        assertThatThrownBy(() -> writer.println("<p>row 3</p>")).isInstanceOf(ResponseBlockedException.class);
        writer.close();
        assertThat(response.getContentAsString()).isEqualTo("<p>row 1</p>" + System.lineSeparator() + MARKER);
    }

    @Test
    @DisplayName("an application that catches the cut and writes an error body sends nothing more")
    void anApplicationCatchingTheCutSendsNothingMore() throws IOException {
        ServletOutputStream out = wrapper.getOutputStream();
        out.write(bytes("{\"row\":1}\n"));
        out.flush();
        block();
        try {
            out.write(bytes("{\"row\":2}\n"));
        } catch (IOException expected) {
            // An exception handler of the application tries to answer with an error body.
            assertThatThrownBy(() -> wrapper.sendError(500)).isInstanceOf(IOException.class);
            assertThatThrownBy(() -> out.write(bytes("{\"error\":\"internal\"}"))).isInstanceOf(IOException.class);
        }

        assertThat(response.getContentAsString()).isEqualTo("{\"row\":1}\n" + MARKER);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    @DisplayName("sendError after the BLOCK: 403 and the marker, not the application's error")
    void sendErrorAfterTheBlock() throws Exception {
        block();

        assertThatThrownBy(() -> wrapper.sendError(500, "boom")).isInstanceOf(IOException.class);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo(MARKER);
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    @DisplayName("sendRedirect after the BLOCK: 403 and the marker, no redirect")
    void sendRedirectAfterTheBlock() throws Exception {
        block();

        assertThatThrownBy(() -> wrapper.sendRedirect("/elsewhere")).isInstanceOf(IOException.class);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(response.getContentAsString()).isEqualTo(MARKER);
    }

    @Test
    @DisplayName("flushBuffer after the BLOCK: the uncommitted rows are dropped, 403 and the marker only")
    void flushBufferAfterTheBlock() throws IOException {
        wrapper.getOutputStream().write(bytes("{\"row\":1}\n"));
        block();

        assertThatThrownBy(() -> wrapper.flushBuffer()).isInstanceOf(IOException.class);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo(MARKER);
    }

    @Test
    @DisplayName("a BLOCK signal received before the response started does not cut it")
    void aSignalFromBeforeTheResponseDoesNotCut() throws IOException {
        block();
        MockHttpServletResponse next = new MockHttpServletResponse();
        BlockableResponseWrapper later = new BlockableResponseWrapper(next, signals, USER,
                "/contexa/zero-trust/blocked", System.nanoTime());

        later.getOutputStream().write(bytes("{\"row\":1}\n"));
        later.getOutputStream().flush();

        assertThat(next.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(next.getContentAsString()).isEqualTo("{\"row\":1}\n");
        assertThat(later.isCut()).isFalse();
    }

    @Test
    @DisplayName("the response start is the one the filter read, so the wrapper reports it")
    void theWrapperKeepsTheResponseStart() {
        long started = System.nanoTime() - 5_000_000L;

        BlockableResponseWrapper read = new BlockableResponseWrapper(response, signals, USER, null, started);

        assertThat(read.responseStartNanos()).isEqualTo(started);
    }
}
