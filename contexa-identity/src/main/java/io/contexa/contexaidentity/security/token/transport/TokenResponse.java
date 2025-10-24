package io.contexa.contexaidentity.security.token.transport;

public record TokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken) {
}

