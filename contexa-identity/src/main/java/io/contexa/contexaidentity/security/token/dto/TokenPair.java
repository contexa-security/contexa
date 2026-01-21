package io.contexa.contexaidentity.security.token.dto;

import lombok.Builder;
import lombok.Getter;
import org.springframework.lang.Nullable;

import java.time.Instant;

@Getter
@Builder
public class TokenPair {

    private final String accessToken;

    @Nullable
    private final String refreshToken;

    private final Instant accessTokenExpiresAt;

    @Nullable
    private final Instant refreshTokenExpiresAt;

    @Nullable
    private final String scope;

    public boolean hasRefreshToken() {
        return refreshToken != null;
    }

    public boolean isAccessTokenExpired() {
        return accessTokenExpiresAt != null && Instant.now().isAfter(accessTokenExpiresAt);
    }

    public boolean isRefreshTokenExpired() {
        if (refreshTokenExpiresAt == null) {
            return true;
        }
        return Instant.now().isAfter(refreshTokenExpiresAt);
    }
}
