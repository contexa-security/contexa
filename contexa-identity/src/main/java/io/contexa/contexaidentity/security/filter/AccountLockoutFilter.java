package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Checks account lockout status BEFORE authentication.
 * Works regardless of which AuthenticationProvider is used.
 * Placed before UsernamePasswordAuthenticationFilter in the filter chain.
 */
@Slf4j
@RequiredArgsConstructor
public class AccountLockoutFilter extends OncePerRequestFilter {

    private final LoginPolicyHandler loginPolicyHandler;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {

        String username = obtainUsername(request);
        if (username == null || username.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Auto-unlock if lock duration expired
        loginPolicyHandler.checkAndUnlockIfExpired(username);

        // Check if still locked
        boolean locked = userRepository.findByUsername(username)
                .map(Users::isAccountLocked)
                .orElse(false);

        if (locked) {
            log.error("Login blocked - account is locked: {}", username);
            String loginUrl = determineLoginUrl(request);
            response.sendRedirect(loginUrl + "?error=account_locked");
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equalsIgnoreCase(request.getMethod());
    }

    private String obtainUsername(HttpServletRequest request) {
        String username = request.getParameter("username");
        if (username == null) {
            username = request.getParameter("loginId");
        }
        return username;
    }

    private String determineLoginUrl(HttpServletRequest request) {
        String uri = request.getRequestURI();
        // Use the same path for redirect (e.g., /admin/login, /admin/mfa/login)
        return uri.contains("/mfa/") ? uri.replace("/mfa/login", "/mfa/login")
                : request.getContextPath() + "/login";
    }
}
