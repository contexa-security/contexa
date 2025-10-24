package io.contexa.contexaidentity.security.utils.writer;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

public interface AuthResponseWriter {
    /**
     * 성공 응답을 JSON 형태로 작성합니다.
     * @param response HttpServletResponse 객체
     * @param data 응답 본문에 포함될 데이터 객체 (Map 또는 DTO)
     * @param status 설정할 HTTP 상태 코드
     * @throws IOException
     */
    void writeSuccessResponse(HttpServletResponse response, Object data, int status) throws IOException;

    /**
     * 오류 응답을 JSON 형태로 작성합니다.
     * @param response HttpServletResponse 객체
     * @param status 설정할 HTTP 상태 코드
     * @param errorCode 애플리케이션 정의 오류 코드
     * @param errorMessage 사용자에게 보여줄 오류 메시지
     * @param path 오류가 발생한 요청 경로 (선택적)
     * @throws IOException
     */
    void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException;

    void writeErrorResponse(HttpServletResponse response, int scUnauthorized, String errorCode, String errorMessage, String requestURI, Map<String, Object> errorDetails) throws IOException;

}
