package io.contexa.contexaidentity.security.core.config.oauth2;

/**
 * OAuth2 Authorization Server 설정을 담는 설정 객체입니다.
 *
 * @param issuerUri Authorization Server의 Issuer URI (예: https://localhost:8080)
 * @param authorizationEndpoint Authorization Endpoint 경로 (기본값: /oauth2/authorize)
 * @param tokenEndpoint Token Endpoint 경로 (기본값: /oauth2/token)
 * @param jwkSetEndpoint JWK Set Endpoint 경로 (기본값: /oauth2/jwks)
 * @param introspectionEndpoint Token Introspection Endpoint 경로 (기본값: /oauth2/introspect)
 * @param revocationEndpoint Token Revocation Endpoint 경로 (기본값: /oauth2/revoke)
 * @param enableOidc OpenID Connect (OIDC) 지원 여부
 * @param userInfoEndpoint OIDC UserInfo Endpoint 경로 (기본값: /oauth2/userinfo)
 * @param accessTokenValidity Access Token 유효 기간 (초 단위, 기본값: 3600초 = 1시간)
 * @param refreshTokenValidity Refresh Token 유효 기간 (초 단위, 기본값: 86400초 = 24시간)
 */
public record AuthorizationServerConfig(
        String issuerUri,
        String authorizationEndpoint,
        String tokenEndpoint,
        String jwkSetEndpoint,
        String introspectionEndpoint,
        String revocationEndpoint,
        boolean enableOidc,
        String userInfoEndpoint,
        long accessTokenValidity,
        long refreshTokenValidity
) {
    /**
     * 기본 생성자: 표준 OAuth2 엔드포인트 경로로 초기화
     */
    public AuthorizationServerConfig() {
        this(
                null,
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/jwks",
                "/oauth2/introspect",
                "/oauth2/revoke",
                false,
                "/oauth2/userinfo",
                3600L,
                86400L
        );
    }

    /**
     * 기본 설정으로 Authorization Server 설정 생성
     */
    public static AuthorizationServerConfig defaults(String issuerUri) {
        return new AuthorizationServerConfig(
                issuerUri,
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/jwks",
                "/oauth2/introspect",
                "/oauth2/revoke",
                false,
                "/oauth2/userinfo",
                3600L,
                86400L
        );
    }

    /**
     * OIDC 지원이 활성화된 Authorization Server 설정 생성
     */
    public static AuthorizationServerConfig withOidc(String issuerUri) {
        return new AuthorizationServerConfig(
                issuerUri,
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/jwks",
                "/oauth2/introspect",
                "/oauth2/revoke",
                true,
                "/oauth2/userinfo",
                3600L,
                86400L
        );
    }
}
