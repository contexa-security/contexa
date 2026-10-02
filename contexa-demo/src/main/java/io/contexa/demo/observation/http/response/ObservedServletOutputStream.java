package io.contexa.demo.observation.http.response;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;

import java.io.IOException;

public class ObservedServletOutputStream extends ServletOutputStream {

    private final ServletOutputStream delegate;
    private long writtenBytes;
    private boolean failed;

    public ObservedServletOutputStream(ServletOutputStream delegate) {
        this.delegate = delegate;
    }

    @Override
    public void write(int value) throws IOException {
        try {
            delegate.write(value);
            writtenBytes++;
        } catch (IOException failure) {
            failed = true;
            throw failure;
        }
    }

    @Override
    public void write(byte[] value, int offset, int length) throws IOException {
        try {
            delegate.write(value, offset, length);
            writtenBytes += length;
        } catch (IOException failure) {
            failed = true;
            throw failure;
        }
    }

    @Override
    public void flush() throws IOException {
        try {
            delegate.flush();
        } catch (IOException failure) {
            failed = true;
            throw failure;
        }
    }

    @Override
    public void close() throws IOException {
        try {
            delegate.close();
        } catch (IOException failure) {
            failed = true;
            throw failure;
        }
    }

    @Override
    public boolean isReady() {
        return delegate.isReady();
    }

    @Override
    public void setWriteListener(WriteListener listener) {
        delegate.setWriteListener(listener);
    }

    public long writtenBytes() {
        return writtenBytes;
    }

    public boolean failed() {
        return failed;
    }
}
