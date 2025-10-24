package io.contexa.contexaidentity.security.handler.logout;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.util.Map;

/**
 * OAuth2 기반 LogoutSuccessHandler
 * - 로그아웃 성공 시 JSON 응답 반환
 * - JwtLogoutSuccessHandler와 동일한 로직
 */
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

    private final ObjectMapper objectMapper;

    public OAuth2LogoutSuccessHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        objectMapper.writeValue(response.getWriter(), Map.of("message", "로그아웃 되었습니다"));
    }
}
