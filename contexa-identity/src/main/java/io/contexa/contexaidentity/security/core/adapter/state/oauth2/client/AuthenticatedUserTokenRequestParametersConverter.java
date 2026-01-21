package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public final class AuthenticatedUserTokenRequestParametersConverter
        implements Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> {

    private static final String GRANT_TYPE_VALUE = "urn:ietf:params:oauth:grant-type:authenticated-user";

    @Override
    public MultiValueMap<String, String> convert(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

        parameters.add(OAuth2ParameterNames.GRANT_TYPE, GRANT_TYPE_VALUE);

        parameters.add("username", grantRequest.getUsername());

        if (grantRequest.getDeviceId() != null) {
            parameters.add("device_id", grantRequest.getDeviceId());
        }

        parameters.add(OAuth2ParameterNames.CLIENT_ID,
                grantRequest.getClientRegistration().getClientId());
        parameters.add(OAuth2ParameterNames.CLIENT_SECRET,
                grantRequest.getClientRegistration().getClientSecret());

        return parameters;
    }
}
