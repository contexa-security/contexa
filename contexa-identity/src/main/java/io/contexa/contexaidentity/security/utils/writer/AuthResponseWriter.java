package io.contexa.contexaidentity.security.utils.writer;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

public interface AuthResponseWriter {
    
    void writeSuccessResponse(HttpServletResponse response, Object data, int status) throws IOException;

    void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException;

    void writeErrorResponse(HttpServletResponse response, int scUnauthorized, String errorCode, String errorMessage, String requestURI, Map<String, Object> errorDetails) throws IOException;

}
