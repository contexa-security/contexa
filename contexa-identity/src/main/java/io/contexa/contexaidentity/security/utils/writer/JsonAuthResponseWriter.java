package io.contexa.contexaidentity.security.utils.writer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class JsonAuthResponseWriter implements AuthResponseWriter {
    private final ObjectMapper objectMapper;

    public JsonAuthResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "ObjectMapper cannot be null");
    }

    @Override
    public void writeSuccessResponse(HttpServletResponse response, Object data, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), data);
    }

    @Override
    public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException {

        writeError(response, status, errorCode, errorMessage, path, new HashMap<>());
    }

    @Override
    public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path, Map<String, Object> errorDetails) throws IOException{
        writeError(response, status, errorCode, errorMessage, path, errorDetails);
    }

    public void writeError(HttpServletResponse response, int status, String error,
                           String message, String path, Map<String, Object> additionalData)
            throws IOException {

        // additionalData가 불변 Map인 경우를 대비
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", status);
        errorResponse.put("error", error);
        errorResponse.put("message", message);
        errorResponse.put("path", path);

        // 안전하게 추가 데이터 병합
        if (additionalData != null) {
            errorResponse.putAll(additionalData);
        }

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), errorResponse);
    }
}
