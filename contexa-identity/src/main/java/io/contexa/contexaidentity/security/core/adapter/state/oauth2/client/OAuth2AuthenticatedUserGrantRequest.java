package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * Authenticated User Grant Type을 위한 OAuth2 Grant Request
 *
 * <p>OAuth2 Client가 Authorization Server에 토큰을 요청할 때 사용하는 요청 객체입니다.
 *
 * @since 2024.12
 */
public class OAuth2AuthenticatedUserGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

    private static final AuthorizationGrantType AUTHENTICATED_USER =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:authenticated-user");

    private final String username;
    private final String deviceId;

    /**
     * OAuth2AuthenticatedUserGrantRequest 생성자
     *
     * @param clientRegistration 클라이언트 등록 정보
     * @param username 인증된 사용자 이름
     * @param deviceId 디바이스 ID (선택적)
     */
    public OAuth2AuthenticatedUserGrantRequest(
            ClientRegistration clientRegistration,
            String username,
            @Nullable String deviceId) {

        super(AUTHENTICATED_USER, clientRegistration);
        Assert.hasText(username, "username cannot be empty");
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
