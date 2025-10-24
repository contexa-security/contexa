package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OAuth2 Resource Server 에서 권한 부족으로 접근이 거부되었을 때 처리하는 Handler입니다.
 *
 * <p>인증은 성공했지만 해당 리소스에 접근할 권한이 없을 때 호출됩니다.
 * HTTP 403 Forbidden 응답을 JSON 형식으로 반환합니다.
 */
@Slf4j
public class OAuth2AccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        log.debug("OAuth2 Access denied for request [{}]: {}",
                request.getRequestURI(), accessDeniedException.getMessage());

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("status", 403);
        errorResponse.put("error", "Forbidden");
        errorResponse.put("message", "Insufficient permissions");
        errorResponse.put("path", request.getRequestURI());
        errorResponse.put("details", accessDeniedException.getMessage());

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
