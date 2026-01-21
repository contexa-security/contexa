package io.contexa.contexaidentity.security.token.validator;

import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class OAuth2TokenValidator implements TokenValidator {

    private final JwtDecoder jwtDecoder;
    private final RefreshTokenStore refreshTokenStore;
    private final OAuth2AuthorizationService authorizationService;
    private final long rotationThresholdMillis;

    public OAuth2TokenValidator(JwtDecoder jwtDecoder,
                                 RefreshTokenStore refreshTokenStore,
                                 OAuth2AuthorizationService authorizationService,
                                 long rotateThresholdMillis) {
        this.jwtDecoder = jwtDecoder;
        this.refreshTokenStore = refreshTokenStore;
        this.authorizationService = authorizationService;
        this.rotationThresholdMillis = rotateThresholdMillis;

            }

    @Override
    public boolean validateAccessToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException ex) {
                        return false;
        }
    }

    @Override
    public boolean validateRefreshToken(String token) {
        try {
            
            if (refreshTokenStore.isBlacklisted(token)) {
                log.warn("Refresh token is blacklisted");
                return false;
            }

            String username = refreshTokenStore.getUsername(token);
            if (username == null) {
                log.warn("Refresh token not found in RefreshTokenStore or expired");
                return false;
            }

            OAuth2Authorization authorization = authorizationService.findByToken(
                    token, OAuth2TokenType.REFRESH_TOKEN);

            if (authorization == null) {
                log.warn("Refresh token not found in OAuth2AuthorizationService");
                return false;
            }

            OAuth2Authorization.Token<OAuth2RefreshToken> tokenMetadata = authorization.getRefreshToken();
            if (tokenMetadata != null && tokenMetadata.isExpired()) {
                log.warn("Refresh token is expired");
                return false;
            }

                        return true;

        } catch (Exception ex) {
            log.error("Error validating refresh token", ex);
            return false;
        }
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        try {
            
            String username = refreshTokenStore.getUsername(refreshToken);
            if (username != null) {
                refreshTokenStore.remove(refreshToken);
                            } else {
                            }

            OAuth2Authorization authorization = authorizationService.findByToken(
                    refreshToken, OAuth2TokenType.REFRESH_TOKEN);

            if (authorization != null) {
                authorizationService.remove(authorization);
                            } else {
                            }

        } catch (Exception ex) {
            log.error("Error invalidating refresh token", ex);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalidation_failed",
                            "Failed to invalidate refresh token: " + ex.getMessage(), null));
        }
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        try {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    refreshToken, OAuth2TokenType.REFRESH_TOKEN);

            if (authorization == null) {
                log.warn("Cannot determine rotation: refresh token not found");
                return false;
            }

            OAuth2Authorization.Token<OAuth2RefreshToken> tokenMetadata = authorization.getRefreshToken();
            if (tokenMetadata == null || tokenMetadata.getToken().getExpiresAt() == null) {
                log.warn("Cannot determine rotation: token metadata or expiration not available");
                return false;
            }

            long expirationMillis = tokenMetadata.getToken().getExpiresAt().toEpochMilli();
            long remainingMillis = expirationMillis - System.currentTimeMillis();

            boolean shouldRotate = remainingMillis <= rotationThresholdMillis;
            
            return shouldRotate;

        } catch (Exception ex) {
            log.error("Error checking refresh token rotation", ex);
            return false;
        }
    }

    @Override
    public Authentication getAuthentication(String token) {
        try {
            
            Jwt jwt = jwtDecoder.decode(token);

            Collection<GrantedAuthority> authorities = extractAuthorities(jwt);

            JwtAuthenticationToken authentication =
                    new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());

                        return authentication;

        } catch (JwtException ex) {
            log.error("Failed to extract authentication from token: {}", ex.getMessage());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Invalid JWT token", null), ex);
        }
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        
        List<String> scopes = jwt.getClaimAsStringList("scope");
        Collection<GrantedAuthority> scopeAuthorities = scopes != null ?
                scopes.stream()
                        .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                        .collect(Collectors.toList()) :
                List.of();

        List<String> roles = jwt.getClaimAsStringList("roles");
        Collection<GrantedAuthority> roleAuthorities = roles != null ?
                roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList()) :
                List.of();

        List<String> authorities = jwt.getClaimAsStringList("authorities");
        Collection<GrantedAuthority> explicitAuthorities = authorities != null ?
                authorities.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()) :
                List.of();

        return List.of(scopeAuthorities, roleAuthorities, explicitAuthorities).stream()
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }
}
