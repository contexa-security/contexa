package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * HttpServletResponseWrapper that returns a BlockableServletOutputStream
 * (and a PrintWriter backed by it) so every response write is subject
 * to real-time BLOCK checks via BlockingSignalBroadcaster.
 */
public class BlockableResponseWrapper extends HttpServletResponseWrapper {

    private final BlockingSignalBroadcaster registry;
    private final String userId;
    private BlockableServletOutputStream blockableStream;
    private PrintWriter writer;
    private boolean monitoredHeaderSet = false;

    public BlockableResponseWrapper(HttpServletResponse response,
                                    BlockingSignalBroadcaster registry,
                                    String userId) {
        super(response);
        this.registry = registry;
        this.userId = userId;
    }

    private void ensureMonitoredHeader() {
        if (!monitoredHeaderSet) {
            monitoredHeaderSet = true;
            setHeader("X-Contexa-Monitored", "true");
        }
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (blockableStream == null) {
            ensureMonitoredHeader();
            blockableStream = new BlockableServletOutputStream(
                    super.getOutputStream(), registry, userId,
                    (HttpServletResponse) getResponse());
        }
        return blockableStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer == null) {
            ensureMonitoredHeader();
            writer = new BlockablePrintWriter(
                    super.getWriter(), registry, userId);
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
        if (registry != null && registry.isBlocked(userId)) {
            try {
                if (!isCommitted()) {
                    setStatus(HttpServletResponse.SC_FORBIDDEN);
                }
            } catch (Exception ignored) {
                // Response may already be in an invalid state — setStatus failure is non-critical
            }
            throw new IOException("Response aborted: user " + userId + " blocked by security decision");
        }
    }
}