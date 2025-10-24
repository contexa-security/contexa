package io.contexa.contexaidentity.security.core.mfa;

/**
 * Adaptive 정책 도메인 객체
 */
public record AdaptiveConfig(boolean geolocation, boolean devicePosture) {
}
