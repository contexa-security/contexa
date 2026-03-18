package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.lang.reflect.Field;

/**
 * ServletOutputStream wrapper that checks BlockingSignalBroadcaster on every
 * write() and flush(). When a BLOCK decision is detected mid-stream,
 * the stream is aborted by forcefully closing the underlying Tomcat connection
 * so the client receives a network error instead of a clean EOF.
 */
public class BlockableServletOutputStream extends ServletOutputStream {

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
            abortTomcatConnection();
            throw new IOException("Response aborted: user " + userId + " blocked by security decision");
        }
    }

    /**
     * Force-abort the underlying Tomcat connection so the client receives
     * a network error (ERR_INCOMPLETE_CHUNKED_ENCODING) instead of a clean EOF.
     *
     * Without this, Tomcat sends the final 0-length chunk on IOException,
     * causing the client's ReadableStream to end with {done: true} (success).
     */
    private void abortTomcatConnection() {
        try {
            HttpServletResponse unwrapped = unwrapResponse(response);
            if (unwrapped != null) {
                Field responseField = unwrapped.getClass().getDeclaredField("response");
                responseField.setAccessible(true);
                Object catalinaResponse = responseField.get(unwrapped);

                var getCoyoteMethod = catalinaResponse.getClass().getMethod("getCoyoteResponse");
                Object coyoteResponse = getCoyoteMethod.invoke(catalinaResponse);

                Class<?> actionCodeClass = Class.forName("org.apache.coyote.ActionCode");
                Object closeNow = Enum.valueOf((Class<Enum>) actionCodeClass, "CLOSE_NOW");

                var actionMethod = coyoteResponse.getClass().getMethod("action", actionCodeClass, Object.class);
                actionMethod.invoke(coyoteResponse, closeNow, null);
            }
        } catch (Exception ignored) {
            // Fallback: if Tomcat internals are unavailable, the IOException alone
            // will still stop the server-side loop, but the client may see a clean EOF.
        }
    }

    private static HttpServletResponse unwrapResponse(HttpServletResponse response) {
        HttpServletResponse current = response;
        while (current instanceof HttpServletResponseWrapper wrapper) {
            current = (HttpServletResponse) wrapper.getResponse();
        }
        return current;
    }
}
