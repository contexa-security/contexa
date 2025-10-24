package io.contexa.contexaidentity.security.token.validator;

import org.springframework.security.core.Authentication;

/**
 * 토큰 검증자 인터페이스
 * <p>
 * Access Token과 Refresh Token의 검증을 담당합니다.
 * Spring Security OAuth2 표준을 준수하여 RSA 기반 검증을 수행합니다.
 *
 * @since 2025.01 - OAuth2 마이그레이션, RSA 기반 검증
 */
public interface TokenValidator {

    /**
     * Access Token 검증
     * @param token 검증할 Access Token
     * @return 유효하면 true, 그렇지 않으면 false
     */
    boolean validateAccessToken(String token);

    /**
     * Refresh Token 검증
     * @param token 검증할 Refresh Token
     * @return 유효하면 true, 그렇지 않으면 false
     */
    boolean validateRefreshToken(String token);

    /**
     * Refresh Token 무효화
     * @param refreshToken 무효화할 Refresh Token
     */
    void invalidateRefreshToken(String refreshToken);

    /**
     * JWT 토큰에서 Authentication 객체 추출
     * @param token JWT 토큰
     * @return Authentication 객체
     */
    Authentication getAuthentication(String token);

    /**
     * Refresh Token을 갱신(회전)해야 하는지 여부를 결정합니다.
     * 기본적으로는 회전하지 않도록 false를 반환합니다.
     * @param refreshToken 검사할 Refresh Token
     * @return 토큰을 회전해야 하면 true, 그렇지 않으면 false
     */
    default boolean shouldRotateRefreshToken(String refreshToken) {
        return false;
    }
}
