package io.contexa.contexaidentity.security.core.config.oauth2;

/**
 * OAuth2 Resource Server 설정을 담는 설정 객체입니다.
 *
 * @param jwkSetUri JWT 검증을 위한 JWK Set 엔드포인트 URI (예: https://auth.example.com/oauth2/jwks)
 * @param issuerUri 토큰 발급자 URI (예: https://auth.example.com) - JWT의 'iss' 클레임 검증에 사용
 * @param tokenType OAuth2 토큰 타입 (JWT 또는 OPAQUE)
 * @param introspectionUri Opaque Token 검증을 위한 Introspection 엔드포인트 URI (tokenType이 OPAQUE일 때 사용)
 * @param introspectionClientId Introspection 요청 시 사용할 클라이언트 ID
 * @param introspectionClientSecret Introspection 요청 시 사용할 클라이언트 Secret
 */
public record ResourceServerConfig(
        String jwkSetUri,
        String issuerUri,
        OAuth2TokenType tokenType,
        String introspectionUri,
        String introspectionClientId,
        String introspectionClientSecret
) {
    /**
     * 기본 생성자: JWT 타입으로 초기화
     */
    public ResourceServerConfig() {
        this(null, null, OAuth2TokenType.JWT, null, null, null);
    }

    /**
     * JWT 기반 Resource Server 설정 생성
     */
    public static ResourceServerConfig jwt(String jwkSetUri, String issuerUri) {
        return new ResourceServerConfig(jwkSetUri, issuerUri, OAuth2TokenType.JWT, null, null, null);
    }

    /**
     * Opaque Token 기반 Resource Server 설정 생성
     */
    public static ResourceServerConfig opaque(String introspectionUri, String clientId, String clientSecret) {
        return new ResourceServerConfig(null, null, OAuth2TokenType.OPAQUE, introspectionUri, clientId, clientSecret);
    }

    /**
     * OAuth2 토큰 타입
     */
    public enum OAuth2TokenType {
        /**
         * JWT (JSON Web Token): 자가 검증 가능한 토큰
         */
        JWT,

        /**
         * Opaque Token: 불투명 토큰, Introspection 엔드포인트를 통해 검증 필요
         */
        OPAQUE
    }
}
