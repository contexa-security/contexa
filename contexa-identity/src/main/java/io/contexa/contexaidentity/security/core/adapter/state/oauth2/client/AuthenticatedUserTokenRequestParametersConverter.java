package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Authenticated User Grant Type을 위한 토큰 요청 파라미터 Converter
 *
 * <p>Spring Security의 {@code DefaultOAuth2TokenRequestParametersConverter} 패턴을 따라
 * OAuth2 토큰 요청 시 필요한 파라미터를 생성합니다.
 *
 * <h3>생성되는 파라미터</h3>
 * <ul>
 *   <li>grant_type: "urn:ietf:params:oauth:grant-type:authenticated-user"</li>
 *   <li>username: 인증된 사용자 이름</li>
 *   <li>device_id: 디바이스 ID (선택적)</li>
 *   <li>client_id: OAuth2 클라이언트 ID</li>
 *   <li>client_secret: OAuth2 클라이언트 시크릿</li>
 * </ul>
 *
 * @since 2025.01
 * @see org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequestEntityConverter
 */
public final class AuthenticatedUserTokenRequestParametersConverter
        implements Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> {

    /**
     * Authenticated User Grant Type 상수
     */
    private static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:authenticated-user";

    @Override
    public MultiValueMap<String, String> convert(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

        // grant_type
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, GRANT_TYPE_VALUE);

        // username
        parameters.add("username", grantRequest.getUsername());

        // device_id (선택적)
        if (grantRequest.getDeviceId() != null) {
            parameters.add("device_id", grantRequest.getDeviceId());
        }

        // client_id & client_secret
        parameters.add(OAuth2ParameterNames.CLIENT_ID,
                grantRequest.getClientRegistration().getClientId());
        parameters.add(OAuth2ParameterNames.CLIENT_SECRET,
                grantRequest.getClientRegistration().getClientSecret());

        return parameters;
    }
}
