package io.contexa.contexaidentity.security.handler.logout;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

    private final ObjectMapper objectMapper;

    public OAuth2LogoutSuccessHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        if (response.isCommitted()) {
            return;
        }
    }
}
