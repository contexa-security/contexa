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

/**
 * OAuth2 토큰 검증자 (RSA 기반)
 * <p>
 * Spring Security OAuth2 표준을 준수하는 토큰 검증을 수행합니다.
 * - Access Token: JwtDecoder 사용 (RSA 공개키 검증)
 * - Refresh Token: RefreshTokenStore + OAuth2AuthorizationService 이중 검증
 * <p>
 * TokenValidator 인터페이스를 구현하여 OAuth2TokenService와 동일한 방식으로 사용됩니다.
 *
 * @since 2025.01 - OAuth2 마이그레이션, RSA 기반 검증
 */
@Slf4j
public class OAuth2TokenValidator implements TokenValidator {

    private final JwtDecoder jwtDecoder;
    private final RefreshTokenStore refreshTokenStore;
    private final OAuth2AuthorizationService authorizationService;
    private final long rotationThresholdMillis;

    /**
     * OAuth2TokenValidator 생성자
     *
     * @param jwtDecoder             Access Token 검증용 JwtDecoder (RSA 공개키 사용)
     * @param refreshTokenStore      Refresh Token 저장소 (블랙리스트 포함)
     * @param authorizationService   OAuth2 Authorization 서비스
     * @param rotateThresholdMillis  Refresh Token 회전 임계값 (밀리초)
     */
    public OAuth2TokenValidator(JwtDecoder jwtDecoder,
                                 RefreshTokenStore refreshTokenStore,
                                 OAuth2AuthorizationService authorizationService,
                                 long rotateThresholdMillis) {
        this.jwtDecoder = jwtDecoder;
        this.refreshTokenStore = refreshTokenStore;
        this.authorizationService = authorizationService;
        this.rotationThresholdMillis = rotateThresholdMillis;

        log.info("OAuth2TokenValidator initialized (RSA-based) with rotation threshold: {} ms", rotateThresholdMillis);
    }

    /**
     * Access Token 검증 (JwtDecoder 사용)
     * <p>
     * Spring Security OAuth2 표준 RSA 검증
     */
    @Override
    public boolean validateAccessToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException ex) {
            log.debug("Invalid access token: {}", ex.getMessage());
            return false;
        }
    }

    /**
     * Refresh Token 검증 (4단계 검증)
     * <p>
     * 1. 블랙리스트 확인
     * 2. RefreshTokenStore 존재 여부
     * 3. OAuth2AuthorizationService 존재 여부
     * 4. 만료 여부
     */
    @Override
    public boolean validateRefreshToken(String token) {
        try {
            // 1. 블랙리스트 검증
            if (refreshTokenStore.isBlacklisted(token)) {
                log.warn("Refresh token is blacklisted");
                return false;
            }

            // 2. RefreshTokenStore 에서 조회
            String username = refreshTokenStore.getUsername(token);
            if (username == null) {
                log.warn("Refresh token not found in RefreshTokenStore or expired");
                return false;
            }

            // 3. OAuth2AuthorizationService 에서 조회
            OAuth2Authorization authorization = authorizationService.findByToken(
                    token, OAuth2TokenType.REFRESH_TOKEN);

            if (authorization == null) {
                log.warn("Refresh token not found in OAuth2AuthorizationService");
                return false;
            }

            // 4. Refresh Token 만료 검증
            OAuth2Authorization.Token<OAuth2RefreshToken> tokenMetadata = authorization.getRefreshToken();
            if (tokenMetadata != null && tokenMetadata.isExpired()) {
                log.warn("Refresh token is expired");
                return false;
            }

            log.debug("Refresh token validation successful for user: {}", username);
            return true;

        } catch (Exception ex) {
            log.error("Error validating refresh token", ex);
            return false;
        }
    }

    /**
     * Refresh Token 무효화 (2단계 제거)
     * <p>
     * 1. RefreshTokenStore에서 제거
     * 2. OAuth2AuthorizationService에서 제거
     */
    @Override
    public void invalidateRefreshToken(String refreshToken) {
        try {
            // 1. RefreshTokenStore에서 사용자 정보 조회 및 제거
            String username = refreshTokenStore.getUsername(refreshToken);
            if (username != null) {
                refreshTokenStore.remove(refreshToken);
                log.debug("Removed refresh token from RefreshTokenStore for user: {}", username);
            } else {
                log.debug("Refresh token not found in RefreshTokenStore");
            }

            // 2. OAuth2AuthorizationService에서 제거
            OAuth2Authorization authorization = authorizationService.findByToken(
                    refreshToken, OAuth2TokenType.REFRESH_TOKEN);

            if (authorization != null) {
                authorizationService.remove(authorization);
                log.debug("Removed OAuth2Authorization for refresh token");
            } else {
                log.debug("OAuth2Authorization not found for refresh token");
            }

            log.info("Successfully invalidated refresh token");

        } catch (Exception ex) {
            log.error("Error invalidating refresh token", ex);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalidation_failed",
                            "Failed to invalidate refresh token: " + ex.getMessage(), null));
        }
    }

    /**
     * Refresh Token 회전 필요 여부 판단
     * <p>
     * 만료 시간까지 남은 시간이 임계값 이하이면 회전
     */
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
            log.debug("Refresh token rotation check: remaining={} ms, threshold={} ms, rotate={}",
                    remainingMillis, rotationThresholdMillis, shouldRotate);

            return shouldRotate;

        } catch (Exception ex) {
            log.error("Error checking refresh token rotation", ex);
            return false;
        }
    }

    /**
     * Authentication 객체 생성 (JWT에서 추출)
     * <p>
     * OAuth2의 JwtAuthenticationToken을 반환
     */
    @Override
    public Authentication getAuthentication(String token) {
        try {
            // JwtDecoder로 토큰 검증 (RSA 공개키 사용)
            Jwt jwt = jwtDecoder.decode(token);

            // JWT에서 권한 추출
            Collection<GrantedAuthority> authorities = extractAuthorities(jwt);

            // JwtAuthenticationToken 생성
            JwtAuthenticationToken authentication =
                    new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());

            log.debug("Successfully extracted authentication from token for user: {}", jwt.getSubject());
            return authentication;

        } catch (JwtException ex) {
            log.error("Failed to extract authentication from token: {}", ex.getMessage());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Invalid JWT token", null), ex);
        }
    }

    /**
     * JWT에서 권한 추출
     * <p>
     * OAuth2의 "scope", "roles", "authorities" 클레임을 모두 확인
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // 1. scope 클레임 (OAuth2 표준)
        List<String> scopes = jwt.getClaimAsStringList("scope");
        Collection<GrantedAuthority> scopeAuthorities = scopes != null ?
                scopes.stream()
                        .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                        .collect(Collectors.toList()) :
                List.of();

        // 2. roles 클레임 (AIDC 프레임워크)
        List<String> roles = jwt.getClaimAsStringList("roles");
        Collection<GrantedAuthority> roleAuthorities = roles != null ?
                roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList()) :
                List.of();

        // 3. authorities 클레임 (명시적 권한)
        List<String> authorities = jwt.getClaimAsStringList("authorities");
        Collection<GrantedAuthority> explicitAuthorities = authorities != null ?
                authorities.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()) :
                List.of();

        // 모든 권한 병합
        return List.of(scopeAuthorities, roleAuthorities, explicitAuthorities).stream()
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }
}
