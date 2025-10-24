package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/**
 * 사용자 인증 기반 OAuth2 Grant Type을 위한 Authentication Token
 *
 * <p>Form/MFA로 이미 인증된 사용자의 정보를 기반으로
 * OAuth2 Access Token을 발급받기 위한 커스텀 Grant Type입니다.
 *
 * <p>Grant Type: "urn:ietf:params:oauth:grant-type:authenticated-user"
 *
 * @since 2024.12
 */
public class AuthenticatedUserGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /**
     * Custom Grant Type: authenticated-user
     */
    public static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private final String username;
    private final String deviceId;

    /**
     * AuthenticatedUserGrantAuthenticationToken 생성자
     *
     * @param clientPrincipal 클라이언트 인증 정보
     * @param username 사용자 이름
     * @param deviceId 디바이스 ID (선택적)
     * @param additionalParameters 추가 파라미터
     */
    public AuthenticatedUserGrantAuthenticationToken(
            Authentication clientPrincipal,
            String username,
            @Nullable String deviceId,
            @Nullable Map<String, Object> additionalParameters) {

        super(AUTHENTICATED_USER, clientPrincipal, additionalParameters);
        this.username = username;
        this.deviceId = deviceId;
    }

    /**
     * 사용자 이름 반환
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * 디바이스 ID 반환
     */
    @Nullable
    public String getDeviceId() {
        return this.deviceId;
    }
}
