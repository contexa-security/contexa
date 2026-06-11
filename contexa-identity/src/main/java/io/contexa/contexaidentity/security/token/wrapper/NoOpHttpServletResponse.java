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
package io.contexa.contexaidentity.security.token.wrapper;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Response wrapper that discards all output to prevent the delegate filter
 * from committing the original response. Used when invoking
 * OAuth2TokenEndpointFilter internally - the token result is extracted
 * from SecurityContextHolder, not from the response body.
 */
public class NoOpHttpServletResponse extends HttpServletResponseWrapper {

    private static final ServletOutputStream NO_OP_OUTPUT_STREAM = new ServletOutputStream() {
        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(WriteListener listener) {
        }

        @Override
        public void write(int b) {
        }
    };

    private final PrintWriter noOpWriter = new PrintWriter(new StringWriter());

    public NoOpHttpServletResponse(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return NO_OP_OUTPUT_STREAM;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return noOpWriter;
    }

    @Override
    public void sendRedirect(String location) throws IOException {
    }

    @Override
    public void flushBuffer() throws IOException {
    }

    @Override
    public void setStatus(int sc) {
    }
}
