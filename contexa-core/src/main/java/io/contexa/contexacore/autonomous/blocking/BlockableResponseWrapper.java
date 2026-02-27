package io.contexa.contexacore.autonomous.blocking;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

/**
 * HttpServletResponseWrapper that returns a BlockableServletOutputStream
 * (and a PrintWriter backed by it) so every response write is subject
 * to real-time BLOCK checks via BlockingDecisionRegistry.
 */
public class BlockableResponseWrapper extends HttpServletResponseWrapper {

    private final BlockingDecisionRegistry registry;
    private final String userId;
    private BlockableServletOutputStream blockableStream;
    private PrintWriter writer;

    public BlockableResponseWrapper(HttpServletResponse response,
                                    BlockingDecisionRegistry registry,
                                    String userId) {
        super(response);
        this.registry = registry;
        this.userId = userId;
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (blockableStream == null) {
            blockableStream = new BlockableServletOutputStream(
                    super.getOutputStream(), registry, userId,
                    (HttpServletResponse) getResponse());
        }
        return blockableStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer == null) {
            String encoding = getCharacterEncoding();
            if (encoding == null) {
                encoding = "UTF-8";
            }
            writer = new PrintWriter(
                    new OutputStreamWriter(getOutputStream(), encoding), true);
        }
        return writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        if (writer != null) {
            writer.flush();
        } else if (blockableStream != null) {
            blockableStream.flush();
        }
        super.flushBuffer();
    }
}
