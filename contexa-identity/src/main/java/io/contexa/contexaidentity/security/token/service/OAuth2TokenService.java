package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
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

    
    public OAuth2TokenService(
            OAuth2AuthorizedClientManager authorizedClientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizationService authorizationService,
            RefreshTokenStore refreshTokenStore,
            TokenValidator tokenValidator,
            JwtDecoder jwtDecoder,
            AuthContextProperties properties,
            ObjectMapper objectMapper,
            TokenTransportStrategy transportStrategy) {

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

    
    public TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId) {
        Assert.notNull(authentication, "authentication cannot be null");

        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth2 token pair for user: {}, deviceId: {}", authentication.getName(), deviceId);
        }

        
        OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication);

        
        if (deviceId != null) {
            builder.attribute("device_id", deviceId);
        }

        
        try {
            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

            if (requestAttributes != null) {
                HttpServletRequest req = requestAttributes.getRequest();
                HttpServletResponse res = requestAttributes.getResponse();

                log.debug("Extracted HttpServletRequest/Response from RequestContextHolder: request={}, response={}",
                        req != null ? req.getClass().getSimpleName() : "null",
                        res != null ? res.getClass().getSimpleName() : "null");

                
                builder.attribute("request", req);
                builder.attribute("response", res);
            } else {
                log.warn("RequestContextHolder.getRequestAttributes() returned null - no HTTP context available");
            }
        } catch (Exception ex) {
            log.warn("Failed to extract HttpServletRequest/Response from RequestContextHolder", ex);
        }

        OAuth2AuthorizeRequest authorizeRequest = builder.build();

        
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient == null) {
            log.error("Failed to obtain OAuth2AuthorizedClient for user: {}", authentication.getName());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("token_request_failed", "Failed to authorize client", null));
        }

        
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

        String accessTokenValue = accessToken.getTokenValue();
        String refreshTokenValue = refreshToken != null ? refreshToken.getTokenValue() : null;

        
        if (refreshToken != null) {
            refreshTokenStore.save(refreshToken.getTokenValue(), authentication.getName());

            if (log.isDebugEnabled()) {
                log.debug("Refresh token saved to RefreshTokenStore for user: {}", authentication.getName());
            }
        }

        
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

        
        OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication);

        
        if (deviceId != null) {
            builder.attribute("device_id", deviceId);
        }

        
        
        builder.attribute(HttpServletRequest.class.getName(), request);
        builder.attribute(HttpServletResponse.class.getName(), response);

        log.debug("Added request/response to OAuth2AuthorizeRequest attributes with keys: {}, {}",
                HttpServletRequest.class.getName(), HttpServletResponse.class.getName());

        OAuth2AuthorizeRequest authorizeRequest = builder.build();

        
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        if (authorizedClient == null) {
            log.error("Failed to obtain OAuth2AuthorizedClient for user: {}", authentication.getName());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("token_request_failed", "Failed to authorize client", null));
        }

        
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

        String accessTokenValue = accessToken.getTokenValue();
        String refreshTokenValue = refreshToken != null ? refreshToken.getTokenValue() : null;

        
        if (refreshToken != null) {
            refreshTokenStore.save(refreshToken.getTokenValue(), authentication.getName());

            if (log.isDebugEnabled()) {
                log.debug("Refresh token saved to RefreshTokenStore for user: {}", authentication.getName());
            }
        }

        
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

    
    @Override
    @Deprecated(since = "2025.01", forRemoval = false)
    public String createAccessToken(Authentication authentication, String deviceId) {
        return createTokenPair(authentication, deviceId).getAccessToken();
    }

    
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

        
        if (refreshTokenStore.isBlacklisted(refreshToken)) {
            log.error("Attempted to use blacklisted refresh token");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Refresh token is blacklisted", null));
        }

        
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) {
            log.error("Refresh token not found or expired in RefreshTokenStore");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Refresh token not found or expired", null));
        }

        
        if (refreshTokenStore instanceof EnhancedRefreshTokenStore enhanced) {
            if (enhanced.isTokenReused(refreshToken)) {
                log.error("Token reuse attack detected! User: {}", username);
                
                enhanced.revokeAllUserTokens(username, "Token reuse detected");
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("token_reuse_detected",
                                "Security breach detected - all tokens revoked", null));
            }
        }

        
        OAuth2Authorization authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            log.error("OAuth2Authorization not found for refresh token");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Authorization not found", null));
        }

        
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(CLIENT_REGISTRATION_ID);
        if (clientRegistration == null) {
            log.error("ClientRegistration not found: {}", CLIENT_REGISTRATION_ID);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("server_error", "Client registration not configured", null));
        }

        
        String principalName = authorization.getPrincipalName();
        List<GrantedAuthority> authorities = authorization.getAuthorizedScopes().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                principalName,
                null,
                authorities
        );

        
        OAuth2AccessToken existingAccessToken = authorization.getAccessToken().getToken();
        OAuth2RefreshToken existingRefreshToken = Objects.requireNonNull(authorization.getRefreshToken()).getToken();

        OAuth2AuthorizedClient existingClient = new OAuth2AuthorizedClient(
                clientRegistration,
                principalName,
                existingAccessToken,
                existingRefreshToken
        );

        
        
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

        
        String newAccessToken = refreshedClient.getAccessToken().getTokenValue();
        OAuth2RefreshToken newRefreshTokenObj = refreshedClient.getRefreshToken();
        String newRefreshToken = (newRefreshTokenObj != null)
                ? newRefreshTokenObj.getTokenValue()
                : refreshToken; 

        log.info("Token refresh successful. New Access Token issued. Refresh Token {} for user: {}",
                newRefreshToken.equals(refreshToken) ? "reused" : "rotated", username);

        
        if (refreshTokenStore instanceof EnhancedRefreshTokenStore enhanced) {
            ClientInfo clientInfo = getCurrentClientInfo();
            String deviceId = extractDeviceId(refreshToken);

            
            if (!newRefreshToken.equals(refreshToken)) {
                log.debug("Rotating refresh token for user: {}", username);
                enhanced.rotate(refreshToken, newRefreshToken, username, deviceId, clientInfo);
            } else {
                
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

        
        var authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization != null) {
            authorizationService.remove(authorization);
            log.debug("Removed OAuth2Authorization for token");
        }

        
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

            return transportStrategy.prepareTokensForWrite(accessToken, refreshToken, propertiesProvider);
        }

        
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

        
        return TokenTransportResult.builder().build();
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        
        String bearerToken = request.getHeader(ACCESS_TOKEN_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        
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

    
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        
        Object rolesObj = jwt.getClaim("roles");
        if (rolesObj instanceof Collection<?>) {
            return ((Collection<?>) rolesObj).stream()
                    .filter(role -> role instanceof String)
                    .map(role -> (GrantedAuthority) () -> (String) role)
                    .collect(Collectors.toList());
        }

        
        Collection<String> scopes = jwt.getClaimAsStringList("scope");
        if (scopes != null) {
            return scopes.stream()
                    .map(scope -> (GrantedAuthority) () -> "SCOPE_" + scope)
                    .collect(Collectors.toList());
        }

        return java.util.Collections.emptyList();
    }

    
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
