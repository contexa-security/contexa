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

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * The cut of one response, shared by its byte stream, its writer and its wrapper so that every way of writing it ends
 * the same: before the commit the buffered output is dropped and the status is 403; the in-band marker is written on the
 * channel the response opened (detected by the client fetch/XHR interceptors) and flushed; nothing is written after.
 * After the commit, output the application wrote before the decision may still be in the container's buffer and goes
 * out with the marker: it was written before the BLOCK, which a cut cannot take back.
 */
final class ResponseCut {

    static final String SIGNAL_PREFIX = "\n__CONTEXA_RESPONSE_BLOCKED__:";

    private final HttpServletResponse response;
    private final BlockingSignalBroadcaster registry;
    private final String userId;
    private final long responseStartNanos;
    private volatile boolean cut;
    /** R-12: the engine's own deny response of a decision made before the response; it carries no protected data. */
    private volatile boolean ownDenyResponse;
    private volatile ServletOutputStream stream;
    private volatile PrintWriter writer;

    ResponseCut(HttpServletResponse response, BlockingSignalBroadcaster registry, String userId,
                long responseStartNanos) {
        this.response = response;
        this.registry = registry;
        this.userId = userId;
        this.responseStartNanos = responseStartNanos;
    }

    long responseStartNanos() {
        return responseStartNanos;
    }

    boolean isCut() {
        return cut;
    }

    String userId() {
        return userId;
    }

    void useStream(ServletOutputStream stream) {
        this.stream = stream;
    }

    void useWriter(PrintWriter writer) {
        this.writer = writer;
    }

    /** Marks the response as the engine's own deny response, which is not cut (R-12). */
    void permitOwnDenyResponse() {
        ownDenyResponse = true;
    }

    /** Cuts the response when a BLOCK applies to it; whether it is cut, now or before. */
    boolean cutIfBlocked() {
        if (cut) {
            return true;
        }
        if (ownDenyResponse || registry == null || !registry.shouldCut(userId, responseStartNanos)) {
            return false;
        }
        synchronized (this) {
            if (!cut) {
                cut = true;
                terminate();
            }
        }
        return true;
    }

    private void terminate() {
        String action = registry.getBlockAction(userId);
        String signal = SIGNAL_PREFIX + (action != null ? action : "BLOCK") + "\n";
        if (response != null) {
            try {
                if (!response.isCommitted()) {
                    // Nothing written before the decision has left yet: it is dropped, so only the cut goes out.
                    response.resetBuffer();
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                }
            } catch (IllegalStateException committedMeanwhile) {
                // The container committed the response between the check and the reset; the marker still follows.
            }
        }
        try {
            PrintWriter openWriter = writer;
            if (openWriter != null) {
                openWriter.write(signal);
                openWriter.flush();
                return;
            }
            ServletOutputStream out = stream != null ? stream : (response != null ? response.getOutputStream() : null);
            if (out != null) {
                out.write(signal.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (IOException | IllegalStateException clientGone) {
            // The client left or the channel cannot take the marker: the response is cut all the same.
        }
    }
}
