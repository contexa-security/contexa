package io.contexa.contexaidentity.security.token.dto;

import lombok.Builder;
import lombok.Getter;
import org.springframework.lang.Nullable;

import java.time.Instant;

/**
 * Access Token과 Refresh Token 쌍을 표현하는 DTO
 *
 * <p>OAuth2 Authorization Server로부터 한 번의 요청으로 획득한 토큰 쌍을 담습니다.
 * 중복 서버 호출을 방지하기 위해 두 토큰을 함께 반환합니다.
 *
 * <h3>사용 예시</h3>
 * <pre>
 * TokenPair tokenPair = tokenService.createTokenPair(authentication, deviceId);
 * String accessToken = tokenPair.getAccessToken();
 * String refreshToken = tokenPair.getRefreshToken(); // nullable
 * </pre>
 *
 * @since 2025.01
 */
@Getter
@Builder
public class TokenPair {

    /**
     * Access Token (Bearer Token)
     */
    private final String accessToken;

    /**
     * Refresh Token (nullable)
     *
     * <p>Refresh Token이 발급되지 않은 경우 null일 수 있습니다.
     */
    @Nullable
    private final String refreshToken;

    /**
     * Access Token 만료 시간
     */
    private final Instant accessTokenExpiresAt;

    /**
     * Refresh Token 만료 시간 (nullable)
     */
    @Nullable
    private final Instant refreshTokenExpiresAt;

    /**
     * OAuth2 스코프 (공백으로 구분)
     */
    @Nullable
    private final String scope;

    /**
     * Refresh Token 존재 여부
     *
     * @return Refresh Token이 null이 아니면 true
     */
    public boolean hasRefreshToken() {
        return refreshToken != null;
    }

    /**
     * Access Token 만료 여부 확인
     *
     * @return 현재 시각 기준 만료 여부
     */
    public boolean isAccessTokenExpired() {
        return accessTokenExpiresAt != null && Instant.now().isAfter(accessTokenExpiresAt);
    }

    /**
     * Refresh Token 만료 여부 확인
     *
     * @return 현재 시각 기준 만료 여부, Refresh Token이 없으면 true
     */
    public boolean isRefreshTokenExpired() {
        if (refreshTokenExpiresAt == null) {
            return true;
        }
        return Instant.now().isAfter(refreshTokenExpiresAt);
    }
}
