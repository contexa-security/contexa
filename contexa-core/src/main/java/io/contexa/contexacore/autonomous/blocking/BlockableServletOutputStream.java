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
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * ServletOutputStream wrapper that checks BlockingSignalBroadcaster on every
 * write() and flush(). When a BLOCK decision is detected mid-stream:
 *
 * 1. Writes an in-band block signal marker to the stream (detected by client fetch/XHR interceptors);
 *    before the commit the buffered output is dropped first and the status is 403 (ResponseCut)
 * 2. Throws IOException to stop the server-side streaming loop
 *
 * Client-side detection uses the in-band signal: the fetch/XHR interceptors act on the marker only, and a broken
 * stream without it reaches the application as the error it is.
 */
public class BlockableServletOutputStream extends ServletOutputStream {

    private final ServletOutputStream delegate;
    private final ResponseCut cut;

    public BlockableServletOutputStream(ServletOutputStream delegate,
                                        BlockingSignalBroadcaster registry,
                                        String userId,
                                        HttpServletResponse response) {
        this(delegate, new ResponseCut(response, registry, userId, System.nanoTime()));
        cut.useStream(delegate);
    }

    BlockableServletOutputStream(ServletOutputStream delegate, ResponseCut cut) {
        this.delegate = delegate;
        this.cut = cut;
    }

    @Override
    public void write(int b) throws IOException {
        checkBlocked();
        delegate.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        if (b == null || b.length == 0) {
            return;
        }
        checkBlocked();
        delegate.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (b == null || len == 0) {
            return;
        }
        checkBlocked();
        delegate.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        if (cut.isCut()) {
            return;
        }
        checkBlocked();
        delegate.flush();
    }

    @Override
    public void close() throws IOException {
        if (cut.isCut()) {
            return;
        }
        checkBlocked();
        delegate.close();
    }

    @Override
    public boolean isReady() {
        return !cut.isCut() && delegate.isReady();
    }

    @Override
    public void setWriteListener(WriteListener listener) {
        if (listener != null) {
            delegate.setWriteListener(listener);
        }
    }

    private void checkBlocked() throws IOException {
        if (cut.cutIfBlocked()) {
            throw new IOException("Response aborted: user " + cut.userId() + " blocked by security decision");
        }
    }
}
