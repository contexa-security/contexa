package io.contexa.contexacore.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Zero Trust filter for OAuth2 Resource Server requests.
 * Registered after BearerTokenAuthenticationFilter in the OAuth2 filter chain
 * to apply Zero Trust verification to JWT-authenticated requests.
 *
 * <p>Execution flow:
 * <pre>
 * SecurityContextHolderFilter
 *   -> BearerTokenAuthenticationFilter (JWT verification -> SecurityContextHolder)
 *     -> AIOAuth2ZeroTrustFilter (Zero Trust -> authority adjustment)
 *       -> AuthorizationFilter (authorization with Zero Trust result)
 * </pre>
 *
 * @see AIOAuth2SecurityContextRepository
 */
public class AIOAuth2ZeroTrustFilter extends OncePerRequestFilter {

    private final AIOAuth2SecurityContextRepository oAuth2SecurityContextRepository;

    public AIOAuth2ZeroTrustFilter(AIOAuth2SecurityContextRepository oAuth2SecurityContextRepository) {
        this.oAuth2SecurityContextRepository = oAuth2SecurityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        oAuth2SecurityContextRepository.applyZeroTrustToCurrentContext(request);
        filterChain.doFilter(request, response);
    }
}
