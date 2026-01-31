package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
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

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class OAuth2TokenService implements TokenService {

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final RefreshTokenStore refreshTokenStore;
    private final TokenValidator tokenValidator;
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
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.transportStrategy = transportStrategy;
    }

    public TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId) {
        Assert.notNull(authentication, "authentication cannot be null");

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
        }

        return TokenPair.builder()
                .accessToken(accessTokenValue)
                .refreshToken(refreshTokenValue)
                .accessTokenExpiresAt(accessToken.getExpiresAt())
                .refreshTokenExpiresAt(refreshToken != null ? refreshToken.getExpiresAt() : null)
                .scope(accessToken.getScopes() != null ? String.join(" ", accessToken.getScopes()) : null)
                .build();
    }

    @Override
    public TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId,
                                     HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(authentication, "authentication cannot be null");
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");

        OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication);

        if (deviceId != null) {
            builder.attribute("device_id", deviceId);
        }

        builder.attribute(HttpServletRequest.class.getName(), request);
        builder.attribute(HttpServletResponse.class.getName(), response);

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
        }

        return TokenPair.builder()
                .accessToken(accessTokenValue)
                .refreshToken(refreshTokenValue)
                .accessTokenExpiresAt(accessToken.getExpiresAt())
                .refreshTokenExpiresAt(refreshToken != null ? refreshToken.getExpiresAt() : null)
                .scope(accessToken.getScopes() != null ? String.join(" ", accessToken.getScopes()) : null)
                .build();
    }

    @Override
    public String createAccessToken(Authentication authentication, String deviceId) {
        return createTokenPair(authentication, deviceId).getAccessToken();
    }

    @Override
    public String createRefreshToken(Authentication authentication, String deviceId) {
        TokenPair tokenPair = createTokenPair(authentication, deviceId);
        return tokenPair.getRefreshToken();
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        Assert.hasText(refreshToken, "refreshToken cannot be empty");

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

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                .principal(authentication)
                .build();

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

        var authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization != null) {
            authorizationService.remove(authorization);
        }

        refreshTokenStore.blacklist(refreshToken, username, reason);
    }

    @Override
    public ObjectMapper getObjectMapper() {
        return this.objectMapper;
    }

    @Override
    public TokenTransportResult prepareTokensForTransport(String accessToken, @Nullable String refreshToken) {
        if (transportStrategy != null) {
            return transportStrategy.prepareTokensForWrite(accessToken, refreshToken);
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
            return transportStrategy.prepareTokensForClear();
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
}
