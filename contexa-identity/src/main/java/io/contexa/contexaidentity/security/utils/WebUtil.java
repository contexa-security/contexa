package io.contexa.contexaidentity.security.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

public class WebUtil {

    public static boolean isApiOrAjaxRequest(HttpServletRequest request) {
        String accept     = request.getHeader("Accept");
        String xRequested = request.getHeader("X-Requested-With");
        String uri        = request.getRequestURI();

        return (accept != null && accept.contains("application/json"))
                || "XMLHttpRequest".equalsIgnoreCase(xRequested)
                || uri.startsWith("/api/");
    }

    /**
     * JSON 오류 응답 헬퍼
     */
    public static void writeError(HttpServletResponse res, int status, String code, String message) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        new ObjectMapper().writeValue(res.getWriter(), Map.of(
                "error", code,
                "message", message
        ));
    }
}
