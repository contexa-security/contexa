package io.contexa.contexaidentity.security.handler.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Slf4j
public class SessionLogoutStrategy implements LogoutStrategy {

    private final CsrfTokenRepository csrfTokenRepository;

    public SessionLogoutStrategy(CsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    @Override
    public boolean supports(HttpServletRequest request, Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken) {
            return false;
        }
        return request.getSession(false) != null;
    }

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        if (csrfTokenRepository != null) {
            csrfTokenRepository.saveToken(null, request, response);
        }

        SecurityContextHolder.clearContext();
    }
}
