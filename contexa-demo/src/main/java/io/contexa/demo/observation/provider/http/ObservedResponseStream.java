package io.contexa.demo.observation.provider.http;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.function.Consumer;

public final class ObservedResponseStream extends FilterInputStream {

    private final BoundedBodyCapture capture;
    private final Consumer<Exception> failures;
    private long position;
    private long highWater;
    private long markedPosition = -1;

    public ObservedResponseStream(InputStream source, BoundedBodyCapture capture, Consumer<Exception> failures) {
        super(source);
        this.capture = capture;
        this.failures = failures;
    }

    @Override
    public int read() throws IOException {
        try {
            int value = in.read();
            if (value < 0) {
                capture.complete();
            } else {
                byte[] one = {(byte) value};
                observe(one, 0, 1);
            }
            return value;
        } catch (IOException failure) {
            failures.accept(failure);
            throw failure;
        }
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        try {
            int count = in.read(bytes, offset, length);
            if (count < 0) {
                capture.complete();
            } else if (count > 0) {
                observe(bytes, offset, count);
            }
            return count;
        } catch (IOException failure) {
            failures.accept(failure);
            throw failure;
        }
    }

    private void observe(byte[] bytes, int offset, int count) {
        int alreadyRead = (int) Math.min(count, Math.max(0, highWater - position));
        if (alreadyRead < count) {
            capture.accept(bytes, offset + alreadyRead, count - alreadyRead);
        }
        position += count;
        highWater = Math.max(highWater, position);
    }

    @Override
    public long skip(long count) throws IOException {
        long skipped = in.skip(count);
        if (skipped > 0) {
            capture.skipped();
            position += skipped;
        }
        return skipped;
    }

    @Override
    public synchronized void mark(int readLimit) {
        in.mark(readLimit);
        markedPosition = position;
    }

    @Override
    public synchronized void reset() throws IOException {
        in.reset();
        if (markedPosition >= 0) {
            position = markedPosition;
        } else {
            capture.skipped();
        }
    }
}
