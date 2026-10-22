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
import jakarta.servlet.ServletResponse;
import jakarta.servlet.ServletResponseWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * HttpServletResponseWrapper that returns a BlockableServletOutputStream
 * (and a PrintWriter backed by it) so every response write is subject
 * to real-time BLOCK checks via BlockingSignalBroadcaster.
 *
 * The response start is the moment the access filter read before the decision in force: a BLOCK received after it cuts
 * the response, whichever way it is written (bytes, characters, sendError, sendRedirect, flushBuffer).
 */
public class BlockableResponseWrapper extends HttpServletResponseWrapper {

    private final String blockedRedirectUrl;
    private final ResponseCut cut;
    private BlockableServletOutputStream blockableStream;
    private PrintWriter writer;
    private boolean monitoredHeaderSet = false;

    public BlockableResponseWrapper(HttpServletResponse response,
                                    BlockingSignalBroadcaster registry,
                                    String userId) {
        this(response, registry, userId, null);
    }

    public BlockableResponseWrapper(HttpServletResponse response,
                                    BlockingSignalBroadcaster registry,
                                    String userId,
                                    String blockedRedirectUrl) {
        this(response, registry, userId, blockedRedirectUrl, System.nanoTime());
    }

    public BlockableResponseWrapper(HttpServletResponse response,
                                    BlockingSignalBroadcaster registry,
                                    String userId,
                                    String blockedRedirectUrl,
                                    long responseStartNanos) {
        super(response);
        this.blockedRedirectUrl = blockedRedirectUrl;
        this.cut = new ResponseCut(response, registry, userId, responseStartNanos);
    }

    /** The {@link System#nanoTime()} the response started at, read before the decision in force. */
    public long responseStartNanos() {
        return cut.responseStartNanos();
    }

    /** Whether this response was cut by a BLOCK. */
    /**
     * Marks the engine's own deny response of a decision made before the response (a synchronous BLOCK answered by
     * ZeroTrustExceptionHandler): it carries no protected data, so it is written whole and not cut (R-12). The access
     * filter's wrapper is found through any wrapper laid over it; false when the response has none.
     */
    public static boolean permitOwnDenyResponse(ServletResponse response) {
        ServletResponse current = response;
        while (current instanceof ServletResponseWrapper wrapped) {
            if (wrapped instanceof BlockableResponseWrapper blockable) {
                blockable.cut.permitOwnDenyResponse();
                return true;
            }
            current = wrapped.getResponse();
        }
        return false;
    }

    public boolean isCut() {
        return cut.isCut();
    }

    private void ensureMonitoredHeader() {
        if (!monitoredHeaderSet) {
            monitoredHeaderSet = true;
            setHeader("X-Contexa-Monitored", "true");
            if (blockedRedirectUrl != null && !blockedRedirectUrl.isBlank()) {
                setHeader("X-Contexa-Blocked-Redirect", blockedRedirectUrl);
            }
        }
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (blockableStream == null) {
            ensureMonitoredHeader();
            ServletOutputStream delegate = super.getOutputStream();
            cut.useStream(delegate);
            blockableStream = new BlockableServletOutputStream(delegate, cut);
        }
        return blockableStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer == null) {
            ensureMonitoredHeader();
            PrintWriter delegate = super.getWriter();
            cut.useWriter(delegate);
            writer = new BlockablePrintWriter(delegate, cut);
        }
        return writer;
    }

    @Override
    public void sendError(int sc) throws IOException {
        ensureNotBlocked();
        super.sendError(sc);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        ensureNotBlocked();
        super.sendError(sc, msg);
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        ensureNotBlocked();
        super.sendRedirect(location);
    }

    @Override
    public void flushBuffer() throws IOException {
        ensureNotBlocked();
        if (blockableStream != null) {
            blockableStream.flush();
        }
        ensureNotBlocked();
        super.flushBuffer();
    }

    private void ensureNotBlocked() throws IOException {
        if (cut.cutIfBlocked()) {
            throw new IOException("Response aborted: user " + cut.userId() + " blocked by security decision");
        }
    }
}
