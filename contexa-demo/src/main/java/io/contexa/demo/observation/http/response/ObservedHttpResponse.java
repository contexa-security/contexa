package io.contexa.demo.observation.http.response;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.PrintWriter;

public class ObservedHttpResponse extends HttpServletResponseWrapper {

    private ObservedServletOutputStream output;
    private boolean writerUsed;
    private boolean resetObserved;

    public ObservedHttpResponse(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (output == null) {
            output = new ObservedServletOutputStream(super.getOutputStream());
        }
        return output;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        writerUsed = true;
        return super.getWriter();
    }

    @Override
    public void resetBuffer() {
        super.resetBuffer();
        resetObserved = true;
    }

    @Override
    public void reset() {
        super.reset();
        resetObserved = true;
        output = null;
        writerUsed = false;
    }

    public Long writtenBytes(boolean asynchronous) {
        return resetObserved || writerUsed || asynchronous || output == null || output.failed() ? null : output.writtenBytes();
    }

    public String captureState(boolean asynchronous) {
        if (asynchronous) {
            return "ASYNC_UNOBSERVED";
        }
        if (resetObserved) {
            return "RESPONSE_RESET_UNOBSERVED";
        }
        if (writerUsed) {
            return "CHARACTER_WRITER_UNOBSERVED";
        }
        if (output == null) {
            return "OUTPUT_NOT_OBSERVED";
        }
        return output.failed() ? "WRITE_FAILED_INCOMPLETE" : "SERVLET_OUTPUT_STREAM";
    }
}
