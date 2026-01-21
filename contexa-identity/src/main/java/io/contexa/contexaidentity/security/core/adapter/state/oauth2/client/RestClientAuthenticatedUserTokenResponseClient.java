package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public final class RestClientAuthenticatedUserTokenResponseClient
        implements OAuth2AccessTokenResponseClient<OAuth2AuthenticatedUserGrantRequest> {

    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

    @Nullable
    private ObjectProvider<FilterChainProxy> filterChainProxyProvider;

    @Nullable
    private org.springframework.security.web.authentication.AuthenticationConverter clientSecretBasicConverter;

    @Nullable
    private org.springframework.security.authentication.AuthenticationProvider clientSecretAuthenticationProvider;

    @Nullable
    private Filter oauth2TokenEndpointFilter; 

    @Nullable
    private HttpServletRequest request;

    @Nullable
    private HttpServletResponse response;

    private RestClient restClient;

    private Converter<OAuth2AuthenticatedUserGrantRequest, HttpHeaders> headersConverter = (grantRequest) -> new HttpHeaders();

    private Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> parametersConverter;

    private Consumer<MultiValueMap<String, String>> parametersCustomizer = (parameters) -> {};

    public RestClientAuthenticatedUserTokenResponseClient() {
        this.restClient = RestClient.builder()
                .messageConverters((messageConverters) -> {
                    messageConverters.clear();
                    messageConverters.add(new FormHttpMessageConverter());
                    messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
                })
                .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
                .build();
        this.parametersConverter = new AuthenticatedUserTokenRequestParametersConverter();
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        Assert.notNull(grantRequest, "grantRequest cannot be null");

        try {
            
            validateClientAuthenticationMethod(grantRequest);

            if (oauth2TokenEndpointFilter == null && filterChainProxyProvider != null) {
                oauth2TokenEndpointFilter = extractOAuth2TokenEndpointFilter(filterChainProxyProvider.getObject());
            }

            if (oauth2TokenEndpointFilter != null && request != null && response != null) {
                return getTokenResponseViaFilter(grantRequest);
            }

            return getTokenResponseViaRestClient(grantRequest);

        } catch (Exception ex) {
            OAuth2Error error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: " + ex.getMessage(),
                    null);
            throw new OAuth2AuthorizationException(error, ex);
        }
    }

    private OAuth2AccessTokenResponse getTokenResponseViaFilter(OAuth2AuthenticatedUserGrantRequest grantRequest) throws Exception {
        
        SecurityContext originalContext = SecurityContextHolder.getContext();

        try {
            
            SecurityContextHolder.clearContext();

            OAuth2TokenRequestWrapper wrappedRequest = new OAuth2TokenRequestWrapper(
                    request,
                    grantRequest.getUsername(),
                    grantRequest.getDeviceId());

            assert clientSecretBasicConverter != null;
            Authentication clientAuthRequest = clientSecretBasicConverter.convert(wrappedRequest);

            if (clientAuthRequest == null) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_client",
                                "Client authentication failed - no credentials found", null));
            }

            assert clientSecretAuthenticationProvider != null;
            Authentication clientAuthResult = clientSecretAuthenticationProvider.authenticate(clientAuthRequest);

            if (clientAuthResult == null || !clientAuthResult.isAuthenticated()) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_client",
                                "Client authentication failed", null));
            }

            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(clientAuthResult);
            SecurityContextHolder.setContext(securityContext);

            assert oauth2TokenEndpointFilter != null;
            oauth2TokenEndpointFilter.doFilter(wrappedRequest, response, (req, res) -> {});

            Authentication resultAuth = SecurityContextHolder.getContext().getAuthentication();

            if (!(resultAuth instanceof OAuth2AccessTokenAuthenticationToken tokenAuth)) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error("token_endpoint_error",
                                "Expected OAuth2AccessTokenAuthenticationToken but got: "
                                        + (resultAuth != null ? resultAuth.getClass().getName() : "null"), null));
            }

            return buildTokenResponse(tokenAuth);

        } finally {
            
            SecurityContextHolder.setContext(originalContext);
        }
    }

    private OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessTokenAuthenticationToken authentication) {
        OAuth2AccessToken accessToken = authentication.getAccessToken();
        OAuth2RefreshToken refreshToken = authentication.getRefreshToken();
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());

        if (accessToken.getExpiresAt() != null && accessToken.getIssuedAt() != null) {
            long expiresIn = ChronoUnit.SECONDS.between(
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt());
            builder.expiresIn(expiresIn);
        }

        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }

        return builder.build();
    }

    private OAuth2AccessTokenResponse getTokenResponseViaRestClient(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        
        MultiValueMap<String, String> parameters = this.parametersConverter.convert(grantRequest);
        if (parameters == null) {
            parameters = new LinkedMultiValueMap<>();
        }
        this.parametersCustomizer.accept(parameters);

        String tokenUri = grantRequest.getClientRegistration().getProviderDetails().getTokenUri();

        OAuth2AccessTokenResponse accessTokenResponse = this.restClient
                .post()
                .uri(tokenUri)
                .headers((headers) -> {
                    HttpHeaders headersToAdd = this.headersConverter.convert(grantRequest);
                    if (headersToAdd != null) {
                        headers.addAll(headersToAdd);
                    }
                })
                .body(parameters)
                .retrieve()
                .body(OAuth2AccessTokenResponse.class);

        if (accessTokenResponse == null) {
            OAuth2Error error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "Empty OAuth 2.0 Access Token Response", null);
            throw new OAuth2AuthorizationException(error);
        }

        return accessTokenResponse;
    }

    private void validateClientAuthenticationMethod(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        ClientRegistration clientRegistration = grantRequest.getClientRegistration();
        ClientAuthenticationMethod clientAuthenticationMethod = clientRegistration.getClientAuthenticationMethod();

        boolean supportedClientAuthenticationMethod = clientAuthenticationMethod.equals(ClientAuthenticationMethod.NONE)
                || clientAuthenticationMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                || clientAuthenticationMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST);

        if (!supportedClientAuthenticationMethod) {
            throw new IllegalArgumentException(String.format(
                    "This class supports `client_secret_basic`, `client_secret_post`, and `none` by default. " +
                            "Client [%s] is using [%s] instead. Please use a supported client authentication method, " +
                            "or use `setParametersConverter` or `setHeadersConverter` to supply an instance that supports [%s].",
                    clientRegistration.getRegistrationId(), clientAuthenticationMethod, clientAuthenticationMethod));
        }
    }

    public void setRestClient(RestClient restClient) {
        Assert.notNull(restClient, "restClient cannot be null");
        this.restClient = restClient;
    }

    public void setHeadersConverter(Converter<OAuth2AuthenticatedUserGrantRequest, HttpHeaders> headersConverter) {
        Assert.notNull(headersConverter, "headersConverter cannot be null");
        this.headersConverter = headersConverter;
    }

    public void addHeadersConverter(Converter<OAuth2AuthenticatedUserGrantRequest, HttpHeaders> headersConverter) {
        Assert.notNull(headersConverter, "headersConverter cannot be null");
        Converter<OAuth2AuthenticatedUserGrantRequest, HttpHeaders> currentHeadersConverter = this.headersConverter;
        this.headersConverter = (authorizationGrantRequest) -> {
            HttpHeaders headers = currentHeadersConverter.convert(authorizationGrantRequest);
            if (headers == null) {
                headers = new HttpHeaders();
            }
            HttpHeaders headersToAdd = headersConverter.convert(authorizationGrantRequest);
            if (headersToAdd != null) {
                headers.addAll(headersToAdd);
            }
            return headers;
        };
    }

    public void setParametersConverter(
            Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> parametersConverter) {
        Assert.notNull(parametersConverter, "parametersConverter cannot be null");
        this.parametersConverter = parametersConverter;
    }

    public void addParametersConverter(
            Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> parametersConverter) {
        Assert.notNull(parametersConverter, "parametersConverter cannot be null");
        Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> currentParametersConverter = this.parametersConverter;
        this.parametersConverter = (authorizationGrantRequest) -> {
            MultiValueMap<String, String> parameters = currentParametersConverter.convert(authorizationGrantRequest);
            if (parameters == null) {
                parameters = new LinkedMultiValueMap<>();
            }
            MultiValueMap<String, String> parametersToAdd = parametersConverter.convert(authorizationGrantRequest);
            if (parametersToAdd != null) {
                parameters.addAll(parametersToAdd);
            }
            return parameters;
        };
    }

    public void setParametersCustomizer(Consumer<MultiValueMap<String, String>> parametersCustomizer) {
        Assert.notNull(parametersCustomizer, "parametersCustomizer cannot be null");
        this.parametersCustomizer = parametersCustomizer;
    }

    public void setFilterChainProxyProvider(ObjectProvider<FilterChainProxy> filterChainProxyProvider) {
        this.filterChainProxyProvider = filterChainProxyProvider;
    }

    public void setClientSecretBasicConverter(org.springframework.security.web.authentication.AuthenticationConverter clientSecretBasicConverter) {
        this.clientSecretBasicConverter = clientSecretBasicConverter;
    }

    public void setClientSecretAuthenticationProvider(org.springframework.security.authentication.AuthenticationProvider clientSecretAuthenticationProvider) {
        this.clientSecretAuthenticationProvider = clientSecretAuthenticationProvider;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    public void setResponse(HttpServletResponse response) {
        this.response = response;
    }

    private Filter extractOAuth2TokenEndpointFilter(FilterChainProxy filterChainProxy) {
        List<SecurityFilterChain> chains = filterChainProxy.getFilterChains();

        for (SecurityFilterChain chain : chains) {
            List<Filter> filters = chain.getFilters();
            for (Filter filter : filters) {
                String filterClassName = filter.getClass().getName();
                if (filterClassName.contains("OAuth2TokenEndpointFilter")) {
                    return filter;
                }
            }
        }

        throw new IllegalStateException(
                "OAuth2TokenEndpointFilter not found in FilterChainProxy. " +
                        "Ensure Spring Authorization Server is properly configured.");
    }
}
