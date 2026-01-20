package io.contexa.contexaidentity.security.token.wrapper;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;


public class CapturingResponseWrapper extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream capturedOutputStream = new ByteArrayOutputStream();
    private final PrintWriter writer;
    private final ServletOutputStream outputStream;
    private int statusCode = HttpServletResponse.SC_OK;

    
    public CapturingResponseWrapper(HttpServletResponse response) {
        super(response);

        this.outputStream = new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                capturedOutputStream.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                capturedOutputStream.write(b, off, len);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
                
            }
        };

        this.writer = new PrintWriter(
            new OutputStreamWriter(capturedOutputStream, StandardCharsets.UTF_8),
            true 
        );
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return outputStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return writer;
    }

    @Override
    public void setStatus(int sc) {
        this.statusCode = sc;
        
    }

    @Deprecated
    public void setStatus(int sc, String sm) {
        this.statusCode = sc;
        
    }

    @Override
    public void sendError(int sc) throws IOException {
        this.statusCode = sc;
        
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        this.statusCode = sc;
        
    }

    @Override
    public int getStatus() {
        return statusCode;
    }

    @Override
    public void setContentType(String type) {
        
        
    }

    @Override
    public void setContentLength(int len) {
        
    }

    @Override
    public void setContentLengthLong(long len) {
        
    }

    @Override
    public void setCharacterEncoding(String charset) {
        
    }

    
    public String getCapturedContent() {
        writer.flush();
        return capturedOutputStream.toString(StandardCharsets.UTF_8);
    }

    
    public byte[] getCapturedBytes() {
        writer.flush();
        return capturedOutputStream.toByteArray();
    }
}
