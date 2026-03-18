package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * ServletOutputStream wrapper that checks BlockingSignalBroadcaster on every
 * write() and flush(). When a BLOCK decision is detected mid-stream:
 *
 * 1. Writes an in-band block signal marker to the stream (detected by client fetch/XHR interceptors)
 * 2. Throws IOException to stop the server-side streaming loop
 *
 * Client-side detection uses two paths:
 * - In-band signal: fetch/XHR interceptors detect the BLOCK_SIGNAL marker in response data
 * - Stream error: pump() catch handles network errors when the connection is disrupted
 */
public class BlockableServletOutputStream extends ServletOutputStream {

    private static final String BLOCK_SIGNAL_PREFIX = "\n__CONTEXA_RESPONSE_BLOCKED__:";

    private final ServletOutputStream delegate;
    private final BlockingSignalBroadcaster registry;
    private final String userId;
    private final HttpServletResponse response;
    private volatile boolean aborted = false;

    public BlockableServletOutputStream(ServletOutputStream delegate,
                                        BlockingSignalBroadcaster registry,
                                        String userId,
                                        HttpServletResponse response) {
        this.delegate = delegate;
        this.registry = registry;
        this.userId = userId;
        this.response = response;
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
        if (aborted) {
            return;
        }
        checkBlocked();
        delegate.flush();
    }

    @Override
    public void close() throws IOException {
        if (aborted) {
            return;
        }
        checkBlocked();
        delegate.close();
    }

    @Override
    public boolean isReady() {
        return !aborted && delegate.isReady();
    }

    @Override
    public void setWriteListener(WriteListener listener) {
        if (listener != null) {
            delegate.setWriteListener(listener);
        }
    }

    private void checkBlocked() throws IOException {
        if (aborted) {
            throw new IOException("Response aborted: user blocked");
        }
        if (registry != null && registry.isBlocked(userId)) {
            aborted = true;
            try {
                if (response != null && !response.isCommitted()) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                }
            } catch (Exception ignored) {
            }
            // Write in-band block signal with action type so client can redirect appropriately
            try {
                String action = registry.getBlockAction(userId);
                byte[] signal = (BLOCK_SIGNAL_PREFIX + (action != null ? action : "BLOCK") + "\n")
                        .getBytes(StandardCharsets.UTF_8);
                delegate.write(signal);
                delegate.flush();
            } catch (Exception ignored) {
            }
            throw new IOException("Response aborted: user " + userId + " blocked by security decision");
        }
    }
}
