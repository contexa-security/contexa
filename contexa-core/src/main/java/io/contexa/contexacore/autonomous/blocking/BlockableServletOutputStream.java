package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * ServletOutputStream wrapper that checks BlockingDecisionRegistry on every
 * bulk write() and flush(). When a BLOCK decision is detected mid-stream,
 * the stream is aborted with an IOException.
 */
public class BlockableServletOutputStream extends ServletOutputStream {

    private final ServletOutputStream delegate;
    private final BlockingDecisionRegistry registry;
    private final String userId;
    private final HttpServletResponse response;
    private volatile boolean aborted = false;

    public BlockableServletOutputStream(ServletOutputStream delegate,
                                        BlockingDecisionRegistry registry,
                                        String userId,
                                        HttpServletResponse response) {
        this.delegate = delegate;
        this.registry = registry;
        this.userId = userId;
        this.response = response;
    }

    @Override
    public void write(int b) throws IOException {
        // Single-byte write is typically buffered; skip the check for performance.
        delegate.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        checkBlocked();
        delegate.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        checkBlocked();
        delegate.write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
        checkBlocked();
        delegate.flush();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public boolean isReady() {
        return delegate.isReady();
    }

    @Override
    public void setWriteListener(WriteListener listener) {
        delegate.setWriteListener(listener);
    }

    private void checkBlocked() throws IOException {
        if (aborted) {
            throw new IOException("Response aborted: user blocked");
        }
        if (registry.isBlocked(userId)) {
            aborted = true;
            if (!response.isCommitted()) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
            throw new IOException("Response aborted: user " + userId + " blocked by security decision");
        }
    }
}
