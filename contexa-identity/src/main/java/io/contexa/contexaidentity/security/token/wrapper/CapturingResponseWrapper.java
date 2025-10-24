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

/**
 * OAuth2 토큰 응답을 캡처하는 HttpServletResponse 래퍼
 *
 * <p>OAuth2TokenEndpointFilter의 응답을 메모리에 캡처하면서 원본 response는 변경하지 않습니다.
 * 이를 통해 나중에 원본 response에 최종 응답을 작성할 수 있습니다.
 *
 * <h3>캡처되는 내용</h3>
 * <ul>
 *   <li>응답 본문 (JSON 토큰 응답)</li>
 *   <li>HTTP 상태 코드</li>
 * </ul>
 *
 * <h3>보존되는 내용</h3>
 * <ul>
 *   <li>원본 response는 변경되지 않음</li>
 *   <li>나중에 원본 response에 다른 내용 작성 가능</li>
 * </ul>
 *
 * @since 2025.01
 */
public class CapturingResponseWrapper extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream capturedOutputStream = new ByteArrayOutputStream();
    private final PrintWriter writer;
    private final ServletOutputStream outputStream;
    private int statusCode = HttpServletResponse.SC_OK;

    /**
     * CapturingResponseWrapper 생성자
     *
     * @param response 원본 HttpServletResponse
     */
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
                // No-op for capturing
            }
        };

        this.writer = new PrintWriter(
            new OutputStreamWriter(capturedOutputStream, StandardCharsets.UTF_8),
            true // autoFlush
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
        // 원본 response의 status는 변경하지 않음
    }

    @Deprecated
    public void setStatus(int sc, String sm) {
        this.statusCode = sc;
        // 원본 response의 status는 변경하지 않음
    }

    @Override
    public void sendError(int sc) throws IOException {
        this.statusCode = sc;
        // 원본 response의 status는 변경하지 않음
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        this.statusCode = sc;
        // 원본 response의 status는 변경하지 않음
    }

    @Override
    public int getStatus() {
        return statusCode;
    }

    @Override
    public void setContentType(String type) {
        // 원본 response의 content type은 변경하지 않음
        // 캡처만 수행
    }

    @Override
    public void setContentLength(int len) {
        // 원본 response의 content length는 변경하지 않음
    }

    @Override
    public void setContentLengthLong(long len) {
        // 원본 response의 content length는 변경하지 않음
    }

    @Override
    public void setCharacterEncoding(String charset) {
        // 원본 response의 character encoding은 변경하지 않음
    }

    /**
     * 캡처된 응답 본문을 문자열로 반환
     *
     * @return 캡처된 응답 본문 (UTF-8)
     */
    public String getCapturedContent() {
        writer.flush();
        return capturedOutputStream.toString(StandardCharsets.UTF_8);
    }

    /**
     * 캡처된 응답 본문을 바이트 배열로 반환
     *
     * @return 캡처된 응답 본문 (바이트 배열)
     */
    public byte[] getCapturedBytes() {
        writer.flush();
        return capturedOutputStream.toByteArray();
    }
}
