package io.contexa.contexacore.autonomous.blocking;

import java.io.PrintWriter;

/**
 * PrintWriter wrapper that checks BlockingSignalBroadcaster before every write.
 * Throws ResponseBlockedException (RuntimeException) on block detection,
 * bypassing PrintWriter's internal IOException suppression.
 */
public class BlockablePrintWriter extends PrintWriter {

    private final BlockingSignalBroadcaster registry;
    private final String userId;

    public BlockablePrintWriter(PrintWriter delegate,
                                BlockingSignalBroadcaster registry,
                                String userId) {
        super(delegate, true);
        this.registry = registry;
        this.userId = userId;
    }

    @Override
    public void write(int c) {
        checkBlocked();
        super.write(c);
    }

    @Override
    public void write(char[] buf, int off, int len) {
        checkBlocked();
        super.write(buf, off, len);
    }

    @Override
    public void write(String s, int off, int len) {
        checkBlocked();
        super.write(s, off, len);
    }

    @Override
    public void flush() {
        checkBlocked();
        super.flush();
    }

    private void checkBlocked() {
        if (registry.isBlocked(userId)) {
            throw new ResponseBlockedException(
                    "Response aborted: user " + userId + " blocked by security decision");
        }
    }
}
