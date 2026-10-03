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

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * Keeps the body and status written by the in-process token endpoint away from the client response,
 * so that the caller can read the endpoint's error response when no token was issued.
 */
public class CapturedTokenEndpointResponse extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private final ServletOutputStream outputStream = new ServletOutputStream() {
        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(WriteListener listener) {
        }

        @Override
        public void write(int b) {
            body.write(b);
        }
    };
    private final PrintWriter writer = new PrintWriter(new OutputStreamWriter(body, StandardCharsets.UTF_8), true);
    private int status = HttpServletResponse.SC_OK;

    public CapturedTokenEndpointResponse(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public PrintWriter getWriter() {
        return writer;
    }

    @Override
    public void setStatus(int sc) {
        this.status = sc;
    }

    @Override
    public void sendError(int sc) {
        this.status = sc;
    }

    @Override
    public void sendError(int sc, String msg) {
        this.status = sc;
    }

    @Override
    public void sendRedirect(String location) {
    }

    @Override
    public void flushBuffer() {
        writer.flush();
    }

    @Override
    public int getStatus() {
        return status;
    }

    @Override
    public boolean isCommitted() {
        return false;
    }

    public byte[] getCapturedBody() {
        writer.flush();
        return body.toByteArray();
    }
}
