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

/**
 * Authenticated User Grant Type을 위한 RestClient 기반 TokenResponseClient
 *
 * <p>Spring Security의 {@code AbstractRestClientOAuth2AccessTokenResponseClient} 패턴을 따라
 * 표준 OAuth2 토큰 요청/응답 처리를 제공합니다.
 *
 * <p>Authorization Server의 /oauth2/token 엔드포인트를 HTTP POST로 호출하여
 * OAuth2 Access Token과 Refresh Token을 획득합니다.
 *
 * <h3>요청 파라미터</h3>
 * <ul>
 *   <li>grant_type: "urn:ietf:params:oauth:grant-type:authenticated-user"</li>
 *   <li>username: 인증된 사용자 이름</li>
 *   <li>device_id: 디바이스 ID (선택적)</li>
 *   <li>client_id: OAuth2 클라이언트 ID</li>
 *   <li>client_secret: OAuth2 클라이언트 시크릿</li>
 * </ul>
 *
 * <h3>자동 제공되는 기능</h3>
 * <ul>
 *   <li>Client Authentication 지원 (CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, NONE)</li>
 *   <li>표준 OAuth2 에러 핸들링 (OAuth2ErrorResponseErrorHandler)</li>
 *   <li>자동 요청/응답 변환 (OAuth2AccessTokenResponseHttpMessageConverter)</li>
 *   <li>확장 가능한 Converter 패턴 (헤더, 파라미터 커스터마이징)</li>
 * </ul>
 *
 * @since 2024.12
 * @since 2025.01 - Spring Security 표준 패턴으로 리팩토링
 * @see org.springframework.security.oauth2.client.endpoint.AbstractRestClientOAuth2AccessTokenResponseClient
 * @see AuthenticatedUserTokenRequestParametersConverter
 */
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
    private Filter oauth2TokenEndpointFilter; // 첫 사용 시 lazy 초기화

    @Nullable
    private HttpServletRequest request;

    @Nullable
    private HttpServletResponse response;

    private RestClient restClient;

    private Converter<OAuth2AuthenticatedUserGrantRequest, HttpHeaders> headersConverter = (grantRequest) -> new HttpHeaders();

    private Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> parametersConverter;

    private Consumer<MultiValueMap<String, String>> parametersCustomizer = (parameters) -> {};

    /**
     * 기본 생성자
     *
     * <p>Spring Security 표준 구성을 사용합니다:
     * <ul>
     *   <li>FormHttpMessageConverter: 요청 본문 변환</li>
     *   <li>OAuth2AccessTokenResponseHttpMessageConverter: 응답 본문 변환</li>
     *   <li>OAuth2ErrorResponseErrorHandler: OAuth2 에러 처리</li>
     *   <li>AuthenticatedUserTokenRequestParametersConverter: 파라미터 생성</li>
     * </ul>
     */
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
            // Client Authentication Method 검증
            validateClientAuthenticationMethod(grantRequest);

            // Lazy initialization: 첫 사용 시 필터 추출
            if (oauth2TokenEndpointFilter == null && filterChainProxyProvider != null) {
                oauth2TokenEndpointFilter = extractOAuth2TokenEndpointFilter(filterChainProxyProvider.getObject());
            }

            // OAuth2TokenEndpointFilter 직접 호출 (HTTP 통신 없음!)
            if (oauth2TokenEndpointFilter != null && request != null && response != null) {
                return getTokenResponseViaFilter(grantRequest);
            }

            // Fallback: RestClient HTTP 통신 (외부 인가서버용)
            return getTokenResponseViaRestClient(grantRequest);

        } catch (Exception ex) {
            OAuth2Error error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: " + ex.getMessage(),
                    null);
            throw new OAuth2AuthorizationException(error, ex);
        }
    }

    /**
     * ClientSecretAuthenticationProvider + OAuth2TokenEndpointFilter 직접 호출하여 토큰 응답 획득 (내부 인가서버용)
     *
     * <p>HTTP 통신 없이 필터를 직접 실행하여 circular request deadlock 방지
     * <ol>
     *   <li>ClientSecretBasicAuthenticationConverter: Authorization 헤더 파싱</li>
     *   <li>ClientSecretAuthenticationProvider: 클라이언트 인증 수행, OAuth2ClientAuthenticationToken 반환</li>
     *   <li>SecurityContext에 OAuth2ClientAuthenticationToken 설정</li>
     *   <li>OAuth2TokenEndpointFilter: 사용자 토큰 발급, authenticationSuccessHandler가 ThreadLocal에 응답 저장</li>
     * </ol>
     *
     * <p>ThreadLocal 기반 OAuth2TokenSuccessHandler와 연동하여 응답 획득
     *
     * @see io.contexa.contexaidentity.security.handler.oauth2.OAuth2TokenSuccessHandler
     */
    private OAuth2AccessTokenResponse getTokenResponseViaFilter(OAuth2AuthenticatedUserGrantRequest grantRequest) throws Exception {
        // 기존 SecurityContext 백업
        SecurityContext originalContext = SecurityContextHolder.getContext();

        try {
            // 1. SecurityContext 비우기
            SecurityContextHolder.clearContext();

            // 2. Request 래핑 (OAuth2 토큰 요청으로 변환, HTTP Basic Authorization 헤더 포함)
            OAuth2TokenRequestWrapper wrappedRequest = new OAuth2TokenRequestWrapper(
                    request,
                    grantRequest.getUsername(),
                    grantRequest.getDeviceId());

            // 3. ClientSecretBasicAuthenticationConverter로 클라이언트 인증 요청 생성
            assert clientSecretBasicConverter != null;
            Authentication clientAuthRequest = clientSecretBasicConverter.convert(wrappedRequest);

            if (clientAuthRequest == null) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_client",
                                "Client authentication failed - no credentials found", null));
            }

            // 4. ClientSecretAuthenticationProvider로 클라이언트 인증 수행
            assert clientSecretAuthenticationProvider != null;
            Authentication clientAuthResult = clientSecretAuthenticationProvider.authenticate(clientAuthRequest);

            if (clientAuthResult == null || !clientAuthResult.isAuthenticated()) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error("invalid_client",
                                "Client authentication failed", null));
            }

            // 5. SecurityContext에 OAuth2ClientAuthenticationToken 설정
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(clientAuthResult);
            SecurityContextHolder.setContext(securityContext);

            // 6. OAuth2TokenEndpointFilter 직접 호출 (사용자 토큰 발급)
            //    Filter 내부에서 OAuth2TokenSuccessHandler가 호출되어
            //    SecurityContext에 OAuth2AccessTokenAuthenticationToken 저장됨
            assert oauth2TokenEndpointFilter != null;
            oauth2TokenEndpointFilter.doFilter(wrappedRequest, response, (req, res) -> {});

            // 7. SecurityContext 에서 OAuth2AccessTokenAuthenticationToken 추출
            Authentication resultAuth = SecurityContextHolder.getContext().getAuthentication();

            if (!(resultAuth instanceof OAuth2AccessTokenAuthenticationToken tokenAuth)) {
                throw new OAuth2AuthorizationException(
                        new OAuth2Error("token_endpoint_error",
                                "Expected OAuth2AccessTokenAuthenticationToken but got: "
                                        + (resultAuth != null ? resultAuth.getClass().getName() : "null"), null));
            }

            // 8. OAuth2AccessTokenAuthenticationToken → OAuth2AccessTokenResponse 변환
            return buildTokenResponse(tokenAuth);

        } finally {
            // 9. SecurityContext 복원
            SecurityContextHolder.setContext(originalContext);
        }
    }

    /**
     * OAuth2AccessTokenAuthenticationToken → OAuth2AccessTokenResponse 변환
     *
     * @param authentication OAuth2AccessTokenAuthenticationToken
     * @return OAuth2AccessTokenResponse
     */
    private OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessTokenAuthenticationToken authentication) {
        OAuth2AccessToken accessToken = authentication.getAccessToken();
        OAuth2RefreshToken refreshToken = authentication.getRefreshToken();
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());

        // expiresIn 계산
        if (accessToken.getExpiresAt() != null && accessToken.getIssuedAt() != null) {
            long expiresIn = ChronoUnit.SECONDS.between(
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt());
            builder.expiresIn(expiresIn);
        }

        // Refresh Token 추가
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        // Additional Parameters 추가
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }

        return builder.build();
    }

    /**
     * RestClient HTTP 통신으로 토큰 응답 획득 (외부 인가서버용)
     */
    private OAuth2AccessTokenResponse getTokenResponseViaRestClient(OAuth2AuthenticatedUserGrantRequest grantRequest) {
        // 요청 파라미터 생성
        MultiValueMap<String, String> parameters = this.parametersConverter.convert(grantRequest);
        if (parameters == null) {
            parameters = new LinkedMultiValueMap<>();
        }
        this.parametersCustomizer.accept(parameters);

        // Token URI
        String tokenUri = grantRequest.getClientRegistration().getProviderDetails().getTokenUri();

        // RestClient로 /oauth2/token 엔드포인트 호출
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

    /**
     * Client Authentication Method 검증
     *
     * <p>지원되는 인증 방식: CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, NONE
     */
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

    /**
     * Sets the {@link RestClient} used when requesting the OAuth 2.0 Access Token Response.
     *
     * @param restClient the {@link RestClient} used when requesting the Access Token Response
     */
    public void setRestClient(RestClient restClient) {
        Assert.notNull(restClient, "restClient cannot be null");
        this.restClient = restClient;
    }

    /**
     * Sets the {@link Converter} used for converting the {@link OAuth2AuthenticatedUserGrantRequest}
     * to {@link HttpHeaders} used in the OAuth 2.0 Access Token Request headers.
     *
     * @param headersConverter the {@link Converter} used for converting to {@link HttpHeaders}
     */
    public void setHeadersConverter(Converter<OAuth2AuthenticatedUserGrantRequest, HttpHeaders> headersConverter) {
        Assert.notNull(headersConverter, "headersConverter cannot be null");
        this.headersConverter = headersConverter;
    }

    /**
     * Add (compose) the provided {@code headersConverter} to the current {@link Converter}.
     *
     * @param headersConverter the {@link Converter} to add (compose)
     */
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

    /**
     * Sets the {@link Converter} used for converting the {@link OAuth2AuthenticatedUserGrantRequest}
     * to {@link MultiValueMap} used in the OAuth 2.0 Access Token Request body.
     *
     * @param parametersConverter the {@link Converter} used for converting to {@link MultiValueMap}
     */
    public void setParametersConverter(
            Converter<OAuth2AuthenticatedUserGrantRequest, MultiValueMap<String, String>> parametersConverter) {
        Assert.notNull(parametersConverter, "parametersConverter cannot be null");
        this.parametersConverter = parametersConverter;
    }

    /**
     * Add (compose) the provided {@code parametersConverter} to the current {@link Converter}.
     *
     * @param parametersConverter the {@link Converter} to add (compose)
     */
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

    /**
     * Sets the {@link Consumer} used for customizing the OAuth 2.0 Access Token parameters,
     * which allows for parameters to be added, overwritten or removed.
     *
     * @param parametersCustomizer the {@link Consumer} to customize the parameters
     */
    public void setParametersCustomizer(Consumer<MultiValueMap<String, String>> parametersCustomizer) {
        Assert.notNull(parametersCustomizer, "parametersCustomizer cannot be null");
        this.parametersCustomizer = parametersCustomizer;
    }

    /**
     * Sets the FilterChainProxyProvider for lazy OAuth2TokenEndpointFilter extraction
     *
     * <p>ObjectProvider를 사용하여 순환 의존성 방지:
     * <ul>
     *   <li>빈 생성 시점에는 FilterChainProxy 접근하지 않음</li>
     *   <li>첫 토큰 요청 시 getObject() 호출하여 Filter 추출</li>
     * </ul>
     *
     * @param filterChainProxyProvider the ObjectProvider for FilterChainProxy
     */
    public void setFilterChainProxyProvider(ObjectProvider<FilterChainProxy> filterChainProxyProvider) {
        this.filterChainProxyProvider = filterChainProxyProvider;
    }

    /**
     * Sets the ClientSecretBasicAuthenticationConverter for client authentication
     *
     * @param clientSecretBasicConverter the converter to use
     */
    public void setClientSecretBasicConverter(org.springframework.security.web.authentication.AuthenticationConverter clientSecretBasicConverter) {
        this.clientSecretBasicConverter = clientSecretBasicConverter;
    }

    /**
     * Sets the ClientSecretAuthenticationProvider for client authentication
     *
     * @param clientSecretAuthenticationProvider the provider to use
     */
    public void setClientSecretAuthenticationProvider(org.springframework.security.authentication.AuthenticationProvider clientSecretAuthenticationProvider) {
        this.clientSecretAuthenticationProvider = clientSecretAuthenticationProvider;
    }

    /**
     * Sets the HttpServletRequest context for filter invocation
     *
     * @param request the HTTP request
     */
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    /**
     * Sets the HttpServletResponse context for filter invocation
     *
     * @param response the HTTP response
     */
    public void setResponse(HttpServletResponse response) {
        this.response = response;
    }


    /**
     * FilterChainProxy 에서 OAuth2TokenEndpointFilter 추출
     *
     * <p>이 메소드는 첫 토큰 요청 시 한 번만 호출됩니다 (lazy initialization).
     *
     * @param filterChainProxy the FilterChainProxy to extract filter from
     * @return the extracted OAuth2TokenEndpointFilter
     * @throws IllegalStateException if filter not found
     */
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
