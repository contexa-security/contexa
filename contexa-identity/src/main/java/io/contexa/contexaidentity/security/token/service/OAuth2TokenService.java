package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore.ClientInfo;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore.TokenAction;
import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategy;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * OAuth2 Client 프레임워크 기반 토큰 서비스 (완전 재작성)
 *
 * <p><strong>Spring OAuth2 표준 100% 활용</strong></p>
 *
 * <p>이 서비스는 Spring OAuth2 Client 프레임워크를 완전히 활용하여
 * Authorization Server 로부터 OAuth2 토큰을 획득하고 관리합니다.
 *
 * <h3>핵심 컴포넌트</h3>
 * <ul>
 *   <li><strong>OAuth2AuthorizedClientManager</strong>: 토큰 획득 및 갱신 관리</li>
 *   <li><strong>AuthenticatedUserOAuth2AuthorizedClientProvider</strong>: Custom Grant 처리</li>
 *   <li><strong>RefreshTokenOAuth2AuthorizedClientProvider</strong>: Refresh Token 자동 갱신</li>
 *   <li><strong>RestClient</strong>: Authorization Server HTTP 호출</li>
 * </ul>
 *
 * <h3>토큰 획득 흐름</h3>
 * <pre>
 * 1. OAuth2AuthorizeRequest 생성 (principal, device_id 포함)
 * 2. OAuth2AuthorizedClientManager.authorize() 호출
 * 3. AuthenticatedUserOAuth2AuthorizedClientProvider가 처리
 * 4. RestClient로 /oauth2/token 엔드포인트 HTTP POST
 * 5. Authorization Server가 OAuth2 토큰 발급
 * 6. OAuth2AuthorizedClient 반환 및 자동 저장
 * </pre>
 *
 * <h3>Refresh Token 자동 갱신</h3>
 * <p>OAuth2AuthorizedClientManager가 토큰 만료를 자동으로 감지하고
 * RefreshTokenOAuth2AuthorizedClientProvider를 통해 갱신합니다.</p>
 *
 * @since 2024.12 - OAuth2 Client 프레임워크 완전 활용
 */
@Slf4j
public class OAuth2TokenService implements TokenService {

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final RefreshTokenStore refreshTokenStore;
    private final TokenValidator tokenValidator;
    private final JwtDecoder jwtDecoder;
    private final AuthContextProperties properties;
    private final ObjectMapper objectMapper;
    private final TokenTransportStrategy transportStrategy;

    private static final String CLIENT_REGISTRATION_ID = "aidc-internal";

    /**
     * OAuth2TokenService 생성자
     *
     * @param authorizedClientManager OAuth2 토큰 관리자
     * @param clientRegistrationRepository OAuth2 클라이언트 등록 저장소
     * @param authorizationService OAuth2 인가 서비스
     * @param refreshTokenStore RefreshToken 고급 관리 저장소
     * @param tokenValidator 토큰 검증자
     * @param jwtDecoder JWT 디코더 (토큰 검증용 - RSA 공개키 사용)
     * @param properties 인증 컨텍스트 설정
     */
    public OAuth2TokenService(
            OAuth2AuthorizedClientManager authorizedClientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizationService authorizationService,
            RefreshTokenStore refreshTokenStore,
            TokenValidator tokenValidator,
            JwtDecoder jwtDecoder,
            AuthContextProperties properties) {
        this(authorizedClientManager, clientRegistrationRepository, authorizationService,
                refreshTokenStore, tokenValidator, jwtDecoder, properties, new ObjectMapper(), null);
    }

    /**
     * OAuth2TokenService 전체 생성자
     */
    public OAuth2TokenService(
            OAuth2AuthorizedClientManager authorizedClientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizationService authorizationService,
            RefreshTokenStore refreshTokenStore,
            TokenValidator tokenValidator,
            JwtDecoder jwtDecoder,
            AuthContextProperties properties,
            ObjectMapper objectMapper,
            @Nullable TokenTransportStrategy transportStrategy) {

        Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(refreshTokenStore, "refreshTokenStore cannot be null");
        Assert.notNull(tokenValidator, "tokenValidator cannot be null");
        Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
        Assert.notNull(properties, "properties cannot be null");
        Assert.notNull(objectMapper, "objectMapper cannot be null");

        this.authorizedClientManager = authorizedClientManager;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationService = authorizationService;
        this.refreshTokenStore = refreshTokenStore;
        this.tokenValidator = tokenValidator;
        this.jwtDecoder = jwtDecoder;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.transportStrategy = transportStrategy;

        log.info("OAuth2TokenService initialized with OAuth2AuthorizedClientManager");
    }

    /**
     * Access Token과 Refresh Token을 한 번에 생성
     *
     * <p><strong>권장 메소드:</strong> 중복 서버 호출을 방지하기 위해 이 메소드를 사용하세요.
     *
     * @param authentication 인증 정보
     * @param deviceId 디바이스 ID (nullable)
     * @return Access Token과 Refresh Token 쌍
     * @since 2025.01
     */
    public TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId) {
        Assert.notNull(authentication, "authentication cannot be null");

        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth2 token pair for user: {}, deviceId: {}", authentication.getName(), deviceId);
        }

        // OAuth2AuthorizeRequest 생성
        OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication);

        // device_id attribute 추가 (선택적)
        if (deviceId != null) {
            builder.attribute("device_id", deviceId);
        }

        // HttpServletRequest/Response 추가 (Filter 직접 호출용)
        try {
            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

            if (requestAttributes != null) {
                HttpServletRequest req = requestAttributes.getRequest();
                HttpServletResponse res = requestAttributes.getResponse();

                log.debug("Extracted HttpServletRequest/Response from RequestContextHolder: request={}, response={}",
                        req != null ? req.getClass().getSimpleName() : "null",
                        res != null ? res.getClass().getSimpleName() : "null");

                // Spring Security 표준 attribute 키 사용
                builder.attribute("request", req);
                builder.attribute("response", res);
            } else {
                log.warn("RequestContextHolder.getRequestAttributes() returned null - no HTTP context available");
            }
        } catch (Exception ex) {
            log.warn("Failed to extract HttpServletRequest/Response from RequestContextHolder", ex);
        }

        OAuth2AuthorizeRequest authorizeRequest = builder.build();

        // OAuth2AuthorizedClientManager를 통해 토큰 획득
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient == null) {
            log.error("Failed to obtain OAuth2AuthorizedClient for user: {}", authentication.getName());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("token_request_failed", "Failed to authorize client", null));
        }

        // Access Token & Refresh Token 추출
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

        String accessTokenValue = accessToken.getTokenValue();
        String refreshTokenValue = refreshToken != null ? refreshToken.getTokenValue() : null;

        // Refresh Token 저장
        if (refreshToken != null) {
            refreshTokenStore.save(refreshToken.getTokenValue(), authentication.getName());

            if (log.isDebugEnabled()) {
                log.debug("Refresh token saved to RefreshTokenStore for user: {}", authentication.getName());
            }
        }

        // TokenPair 생성
        TokenPair tokenPair = TokenPair.builder()
                .accessToken(accessTokenValue)
                .refreshToken(refreshTokenValue)
                .accessTokenExpiresAt(accessToken.getExpiresAt())
                .refreshTokenExpiresAt(refreshToken != null ? refreshToken.getExpiresAt() : null)
                .scope(accessToken.getScopes() != null ? String.join(" ", accessToken.getScopes()) : null)
                .build();

        if (log.isInfoEnabled()) {
            log.info("Successfully obtained OAuth2 token pair for user: {}, hasRefreshToken: {}",
                    authentication.getName(), tokenPair.hasRefreshToken());
        }

        return tokenPair;
    }

    /**
     * Access Token과 Refresh Token을 한 번에 생성 (HttpServletRequest/Response 포함)
     *
     * <p>OAuth2TokenEndpointFilter를 직접 호출하기 위해 request/response를 전달합니다.
     *
     * @param authentication 인증 정보
     * @param deviceId 디바이스 ID (nullable)
     * @param request HTTP 요청 (Filter 직접 호출용)
     * @param response HTTP 응답 (Filter 직접 호출용)
     * @return Access Token과 Refresh Token 쌍
     * @since 2025.01
     */
    @Override
    public TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId,
                                    HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(authentication, "authentication cannot be null");
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");

        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth2 token pair for user: {}, deviceId: {} (with request/response)",
                    authentication.getName(), deviceId);
        }

        // OAuth2AuthorizeRequest 생성
        OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication);

        // device_id attribute 추가 (선택적)
        if (deviceId != null) {
            builder.attribute("device_id", deviceId);
        }

        // HttpServletRequest/Response 추가 (Filter 직접 호출용)
        // DefaultOAuth2AuthorizedClientManager가 찾는 키: HttpServletRequest.class.getName()
        builder.attribute(HttpServletRequest.class.getName(), request);
        builder.attribute(HttpServletResponse.class.getName(), response);

        log.debug("Added request/response to OAuth2AuthorizeRequest attributes with keys: {}, {}",
                HttpServletRequest.class.getName(), HttpServletResponse.class.getName());

        OAuth2AuthorizeRequest authorizeRequest = builder.build();

        // OAuth2AuthorizedClientManager를 통해 토큰 획득
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient == null) {
            log.error("Failed to obtain OAuth2AuthorizedClient for user: {}", authentication.getName());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("token_request_failed", "Failed to authorize client", null));
        }

        // Access Token & Refresh Token 추출
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

        String accessTokenValue = accessToken.getTokenValue();
        String refreshTokenValue = refreshToken != null ? refreshToken.getTokenValue() : null;

        // Refresh Token 저장
        if (refreshToken != null) {
            refreshTokenStore.save(refreshToken.getTokenValue(), authentication.getName());

            if (log.isDebugEnabled()) {
                log.debug("Refresh token saved to RefreshTokenStore for user: {}", authentication.getName());
            }
        }

        // TokenPair 생성
        TokenPair tokenPair = TokenPair.builder()
                .accessToken(accessTokenValue)
                .refreshToken(refreshTokenValue)
                .accessTokenExpiresAt(accessToken.getExpiresAt())
                .refreshTokenExpiresAt(refreshToken != null ? refreshToken.getExpiresAt() : null)
                .scope(accessToken.getScopes() != null ? String.join(" ", accessToken.getScopes()) : null)
                .build();

        if (log.isInfoEnabled()) {
            log.info("Successfully obtained OAuth2 token pair for user: {}, hasRefreshToken: {}",
                    authentication.getName(), tokenPair.hasRefreshToken());
        }

        return tokenPair;
    }

    /**
     * Access Token 생성 (레거시 호환성)
     *
     * <p><strong>비권장:</strong> {@link #createTokenPair(Authentication, String)}를 사용하세요.
     * 이 메소드는 하위 호환성을 위해 유지됩니다.
     *
     * @deprecated {@link #createTokenPair(Authentication, String)} 사용 권장
     */
    @Override
    @Deprecated(since = "2025.01", forRemoval = false)
    public String createAccessToken(Authentication authentication, String deviceId) {
        return createTokenPair(authentication, deviceId).getAccessToken();
    }

    /**
     * Refresh Token 생성 (레거시 호환성)
     *
     * <p><strong>비권장:</strong> {@link #createTokenPair(Authentication, String)}를 사용하세요.
     * 이 메소드는 하위 호환성을 위해 유지됩니다.
     *
     * @deprecated {@link #createTokenPair(Authentication, String)} 사용 권장
     */
    @Override
    @Deprecated(since = "2025.01", forRemoval = false)
    public String createRefreshToken(Authentication authentication, String deviceId) {
        TokenPair tokenPair = createTokenPair(authentication, deviceId);
        return tokenPair.getRefreshToken();
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        Assert.hasText(refreshToken, "refreshToken cannot be empty");

        log.info("Refreshing OAuth2 access token with refresh token");

        // 1. 블랙리스트 검증
        if (refreshTokenStore.isBlacklisted(refreshToken)) {
            log.error("Attempted to use blacklisted refresh token");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Refresh token is blacklisted", null));
        }

        // 2. RefreshTokenStore 에서 사용자 정보 조회
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) {
            log.error("Refresh token not found or expired in RefreshTokenStore");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Refresh token not found or expired", null));
        }

        // 3. EnhancedRefreshTokenStore - 토큰 재사용 감지
        if (refreshTokenStore instanceof EnhancedRefreshTokenStore enhanced) {
            if (enhanced.isTokenReused(refreshToken)) {
                log.error("Token reuse attack detected! User: {}", username);
                // 보안 침해: 모든 사용자 토큰 무효화
                enhanced.revokeAllUserTokens(username, "Token reuse detected");
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("token_reuse_detected",
                                "Security breach detected - all tokens revoked", null));
            }
        }

        // 4. OAuth2Authorization 조회
        OAuth2Authorization authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            log.error("OAuth2Authorization not found for refresh token");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Authorization not found", null));
        }

        // 5. ClientRegistration 조회
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(CLIENT_REGISTRATION_ID);
        if (clientRegistration == null) {
            log.error("ClientRegistration not found: {}", CLIENT_REGISTRATION_ID);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("server_error", "Client registration not configured", null));
        }

        // 6. Authentication 객체 재구성
        String principalName = authorization.getPrincipalName();
        List<GrantedAuthority> authorities = authorization.getAuthorizedScopes().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                principalName,
                null,
                authorities
        );

        // 7. OAuth2AuthorizedClient 재구성 (기존 토큰으로)
        OAuth2AccessToken existingAccessToken = authorization.getAccessToken().getToken();
        OAuth2RefreshToken existingRefreshToken = Objects.requireNonNull(authorization.getRefreshToken()).getToken();

        OAuth2AuthorizedClient existingClient = new OAuth2AuthorizedClient(
                clientRegistration,
                principalName,
                existingAccessToken,
                existingRefreshToken
        );

        // 8. OAuth2AuthorizedClientManager를 통한 토큰 갱신
        // RefreshTokenOAuth2AuthorizedClientProvider가 실제 HTTP 요청 처리
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication)
                .build();

        log.info("Requesting token refresh from OAuth2AuthorizedClientManager for user: {}", username);

        OAuth2AuthorizedClient refreshedClient = authorizedClientManager.authorize(authorizeRequest);

        if (refreshedClient == null) {
            log.error("OAuth2AuthorizedClientManager failed to refresh token");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("refresh_failed", "Failed to refresh token", null));
        }

        // 9. 새로운 토큰 추출
        String newAccessToken = refreshedClient.getAccessToken().getTokenValue();
        OAuth2RefreshToken newRefreshTokenObj = refreshedClient.getRefreshToken();
        String newRefreshToken = (newRefreshTokenObj != null)
                ? newRefreshTokenObj.getTokenValue()
                : refreshToken; // Refresh Token 재사용 정책인 경우

        log.info("Token refresh successful. New Access Token issued. Refresh Token {} for user: {}",
                newRefreshToken.equals(refreshToken) ? "reused" : "rotated", username);

        // 10. EnhancedRefreshTokenStore - 토큰 회전 (Token Rotation)
        if (refreshTokenStore instanceof EnhancedRefreshTokenStore enhanced) {
            ClientInfo clientInfo = getCurrentClientInfo();
            String deviceId = extractDeviceId(refreshToken);

            // 새로운 Refresh Token이 발급된 경우에만 rotate 호출
            if (!newRefreshToken.equals(refreshToken)) {
                log.debug("Rotating refresh token for user: {}", username);
                enhanced.rotate(refreshToken, newRefreshToken, username, deviceId, clientInfo);
            } else {
                // Refresh Token 재사용 정책 - 사용 이력만 기록
                log.debug("Reusing refresh token for user: {}", username);
                enhanced.recordUsage(refreshToken, TokenAction.REUSED, clientInfo);
            }
        }

        log.info("Refresh operation completed successfully for user: {}", username);

        return new RefreshResult(newAccessToken, newRefreshToken);
    }

    @Override
    public boolean validateAccessToken(String accessToken) {
        return tokenValidator.validateAccessToken(accessToken);
    }

    @Override
    public boolean validateRefreshToken(String refreshToken) {
        return tokenValidator.validateRefreshToken(refreshToken);
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        tokenValidator.invalidateRefreshToken(refreshToken);
    }

    @Override
    public Authentication getAuthentication(String token) {
        return tokenValidator.getAuthentication(token);
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        return tokenValidator.shouldRotateRefreshToken(refreshToken);
    }

    @Override
    public void blacklistRefreshToken(String refreshToken, String username, String reason) {
        Assert.hasText(refreshToken, "refreshToken cannot be empty");
        Assert.hasText(username, "username cannot be empty");

        log.info("Blacklisting refresh token for user: {}, reason: {}", username, reason);

        // 1. OAuth2Authorization 제거 (OAuth2 표준 레이어)
        var authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization != null) {
            authorizationService.remove(authorization);
            log.debug("Removed OAuth2Authorization for token");
        }

        // 2. RefreshTokenStore 블랙리스트 (보안 관리 레이어)
        refreshTokenStore.blacklist(refreshToken, username, reason);
        log.debug("Added token to RefreshTokenStore blacklist");
    }

    @Override
    public ObjectMapper getObjectMapper() {
        return this.objectMapper;
    }

    @Override
    public TokenTransportResult prepareTokensForTransport(String accessToken, @Nullable String refreshToken) {
        if (transportStrategy != null) {
            // TokenServicePropertiesProvider 구현
            TokenService.TokenServicePropertiesProvider propertiesProvider = new TokenService.TokenServicePropertiesProvider() {
                @Override
                public long getAccessTokenValidity() {
                    return properties.getAccessTokenValidity();
                }

                @Override
                public long getRefreshTokenValidity() {
                    return properties.getRefreshTokenValidity();
                }

                @Override
                public String getCookiePath() {
                    return "/";
                }

                @Override
                public boolean isCookieSecure() {
                    return false; // HTTP 개발 환경
                }

                @Override
                public String getRefreshTokenCookieName() {
                    return "refresh_token";
                }

                @Override
                public String getAccessTokenCookieName() {
                    return "access_token";
                }
            };

            return transportStrategy.prepareTokensForWrite(accessToken, refreshToken, propertiesProvider);
        }

        // 기본 구현: Body에 토큰 포함
        return TokenTransportResult.builder()
                .body(java.util.Map.of(
                        "access_token", accessToken,
                        "token_type", "Bearer",
                        "refresh_token", refreshToken != null ? refreshToken : ""
                ))
                .build();
    }

    @Override
    public TokenTransportResult prepareClearTokens() {
        if (transportStrategy != null) {
            TokenService.TokenServicePropertiesProvider propertiesProvider = new TokenService.TokenServicePropertiesProvider() {
                @Override
                public long getAccessTokenValidity() {
                    return properties.getAccessTokenValidity();
                }

                @Override
                public long getRefreshTokenValidity() {
                    return properties.getRefreshTokenValidity();
                }

                @Override
                public String getCookiePath() {
                    return "/";
                }

                @Override
                public boolean isCookieSecure() {
                    return false;
                }

                @Override
                public String getRefreshTokenCookieName() {
                    return "refresh_token";
                }

                @Override
                public String getAccessTokenCookieName() {
                    return "access_token";
                }
            };

            return transportStrategy.prepareTokensForClear(propertiesProvider);
        }

        // 기본 구현: 빈 응답
        return TokenTransportResult.builder().build();
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        // Authorization 헤더에서 Bearer 토큰 추출
        String bearerToken = request.getHeader(ACCESS_TOKEN_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        // X-Refresh-Token 헤더에서 토큰 추출
        return request.getHeader(REFRESH_TOKEN_HEADER);
    }

    @Override
    public TokenTransportStrategy getUnderlyingTokenTransportStrategy() {
        return this.transportStrategy;
    }

    @Override
    public AuthContextProperties properties() {
        return this.properties;
    }

    /**
     * JWT 에서 권한(Authorities) 추출
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // roles 클레임에서 권한 추출
        Object rolesObj = jwt.getClaim("roles");
        if (rolesObj instanceof Collection<?>) {
            return ((Collection<?>) rolesObj).stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (GrantedAuthority) () -> (String) role)
                    .collect(Collectors.toList());
        }

        // scope 클레임에서 권한 추출
        Collection<String> scopes = jwt.getClaimAsStringList("scope");
        if (scopes != null) {
            return scopes.stream()
                    .map(scope -> (GrantedAuthority) () -> "SCOPE_" + scope)
                    .collect(Collectors.toList());
        }

        return java.util.Collections.emptyList();
    }

    /**
     * Refresh Token에서 deviceId 추출
     *
     * Spring Security OAuth2 표준 JwtDecoder를 사용하여 RSA 서명 토큰 파싱
     */
    private String extractDeviceId(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String deviceId = jwt.getClaim("deviceId");
            return deviceId != null ? deviceId : "unknown";
        } catch (Exception e) {
            log.trace("Failed to extract deviceId from token. Error: {}", e.getMessage(), e);
            return "unknown";
        }
    }

    /**
     * 현재 HTTP 요청 정보에서 ClientInfo 추출
     *
     * FIXME: 실제 구현 필요
     * - SecurityContext 또는 HttpServletRequest에서 실제 정보 추출
     * - IP 주소: X-Forwarded-For 헤더 고려
     * - User-Agent: Request 헤더에서 추출
     * - Device Fingerprint: 클라이언트에서 전송된 값 사용
     * - Location: GeoIP 서비스 연동
     *
     * 현재는 더미 데이터를 반환합니다.
     */
    private ClientInfo getCurrentClientInfo() {
        log.trace("Using dummy ClientInfo - actual HTTP request extraction not implemented");
        return new ClientInfo(
                "127.0.0.1",
                "Mozilla/5.0",
                "device-fingerprint",
                "Seoul, KR",
                Instant.now()
        );
    }
}
