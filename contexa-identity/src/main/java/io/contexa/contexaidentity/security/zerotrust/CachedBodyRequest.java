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

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.SequenceInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * An agent's request whose body was read once to bind its confirmation to it (docs/agent A5-9); the application
 * reads the same body afterwards. A body larger than the bound size is not bound, and still reaches the application
 * whole: the bytes read to find that out come first, then the rest of the stream.
 */
final class CachedBodyRequest extends HttpServletRequestWrapper {

    /** The body read, or null when nothing was read (the declared length is over the bound size). */
    private final byte[] body;
    /** The rest of a body larger than the bound size, after {@link #body}; null when the whole body was read. */
    private final InputStream rest;

    private CachedBodyRequest(HttpServletRequest request, byte[] body, InputStream rest) {
        super(request);
        this.body = body;
        this.rest = rest;
    }

    /**
     * Reads the request's body, at most {@code maxBytes}, without losing any of it.
     *
     * @return the request with its body; {@link #bound()} tells whether the whole body was read
     */
    static CachedBodyRequest of(HttpServletRequest request, int maxBytes) throws IOException {
        long declared = request.getContentLengthLong();
        if (declared > maxBytes) {
            return new CachedBodyRequest(request, null, null);
        }
        InputStream input = request.getInputStream();
        byte[] read = input != null ? input.readNBytes(maxBytes + 1) : new byte[0];
        if (read.length > maxBytes) {
            return new CachedBodyRequest(request, read, input);
        }
        return new CachedBodyRequest(request, read, null);
    }

    /** Whether the whole body was read, so a confirmation can be bound to it. */
    boolean bound() {
        return body != null && rest == null;
    }

    byte[] body() {
        if (!bound()) {
            throw new IllegalStateException("The body is larger than the bound size");
        }
        return body.clone();
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (body == null) {
            return super.getInputStream();
        }
        ByteArrayInputStream read = new ByteArrayInputStream(body);
        InputStream input = rest != null ? new SequenceInputStream(read, rest) : read;
        boolean whole = rest == null;
        return new ServletInputStream() {
            private boolean finished;

            @Override
            public boolean isFinished() {
                return whole ? read.available() == 0 : finished;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                if (!whole) {
                    throw new UnsupportedOperationException("A body larger than the bound size is read blocking");
                }
                // The body is in memory: all of it is available now.
                try {
                    listener.onDataAvailable();
                    listener.onAllDataRead();
                } catch (IOException e) {
                    listener.onError(e);
                }
            }

            @Override
            public int read() throws IOException {
                int value = input.read();
                finished = value < 0;
                return value;
            }

            @Override
            public int read(byte[] buffer, int offset, int length) throws IOException {
                int count = input.read(buffer, offset, length);
                finished = count < 0;
                return count;
            }
        };
    }

    @Override
    public BufferedReader getReader() throws IOException {
        if (body == null) {
            return super.getReader();
        }
        String encoding = getCharacterEncoding();
        Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
        return new BufferedReader(new InputStreamReader(getInputStream(), charset));
    }

    @Override
    public int getContentLength() {
        return bound() ? body.length : super.getContentLength();
    }

    @Override
    public long getContentLengthLong() {
        return bound() ? body.length : super.getContentLengthLong();
    }
}
