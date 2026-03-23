package io.contexa.contexacommon.security.bridge.old;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Bridges legacy authentication into Spring Security's SecurityContext.
 * <p>
 * On every request, this filter:
 * <ol>
 *   <li>Delegates to {@link AuthBridge} to extract user identity from the legacy system</li>
 *   <li>If a user is found: creates an {@link Authentication} and sets it in SecurityContext</li>
 *   <li>If no user found: clears SecurityContext (user is unauthenticated in legacy)</li>
 * </ol>
 * <p>
 * This filter executes on <b>every request</b> to ensure synchronization with the legacy
 * authentication state. If the legacy session expires or the user logs out,
 * the next request will immediately reflect that change.
 * <p>
 * The created Authentication is also persisted by {@code AISessionSecurityContextRepository}
 * into the HttpSession, but this filter always re-checks the legacy source to guarantee
 * consistency.
 */
@Slf4j
public class AuthBridgeFilter extends OncePerRequestFilter {

    private final AuthBridge authBridge;

    public AuthBridgeFilter(AuthBridge authBridge) {
        this.authBridge = authBridge;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        BridgedUser bridgedUser = null;
        try {
            bridgedUser = authBridge.extractUser(request);
        } catch (Exception e) {
            log.error("[AuthBridge] Failed to extract user from legacy system", e);
        }

        if (bridgedUser != null && bridgedUser.username() != null && !bridgedUser.username().isBlank()) {
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

            // Only update if user changed or no authentication exists
            if (currentAuth == null || !bridgedUser.username().equals(currentAuth.getName())) {
                List<SimpleGrantedAuthority> authorities = bridgedUser.roles().stream()
                        .map(role -> {
                            String normalized = role.toUpperCase();
                            return new SimpleGrantedAuthority(
                                    normalized.startsWith("ROLE_") ? normalized : "ROLE_" + normalized);
                        })
                        .toList();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                bridgedUser.username(), null, authorities);
                authentication.setDetails(bridgedUser.attributes());

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } else {
            // Legacy user not found - clear any previously bridged authentication
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
            if (currentAuth != null && !(currentAuth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}
