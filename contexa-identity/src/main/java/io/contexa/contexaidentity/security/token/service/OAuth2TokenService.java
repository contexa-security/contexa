package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
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
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class OAuth2TokenService implements TokenService {

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final TokenValidator tokenValidator;
    private final AuthContextProperties properties;
    private final ObjectMapper objectMapper;
    private final TokenTransportStrategy transportStrategy;

    private static final String CLIENT_REGISTRATION_ID = "aidc-internal";

    public OAuth2TokenService(
            OAuth2AuthorizedClientManager authorizedClientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizationService authorizationService,
            TokenValidator tokenValidator,
            AuthContextProperties properties,
            ObjectMapper objectMapper,
            TokenTransportStrategy transportStrategy) {

        Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenValidator, "tokenValidator cannot be null");
        Assert.notNull(properties, "properties cannot be null");
        Assert.notNull(objectMapper, "objectMapper cannot be null");

        this.authorizedClientManager = authorizedClientManager;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationService = authorizationService;
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

                builder.attribute(HttpServletRequest.class.getName(), req);
                builder.attribute(HttpServletResponse.class.getName(), res);
            }
        } catch (Exception ex) {
            log.error("Failed to extract HttpServletRequest/Response from RequestContextHolder", ex);
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

        return TokenPair.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : null)
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

        return TokenPair.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : null)
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
        return createTokenPair(authentication, deviceId).getRefreshToken();
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        Assert.hasText(refreshToken, "refreshToken cannot be empty");

        OAuth2Authorization authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            log.error("OAuth2Authorization not found for refresh token");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Authorization not found", null));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = authorization.getRefreshToken();
        if (refreshTokenMeta == null || refreshTokenMeta.isInvalidated()) {
            log.error("Refresh token is invalidated");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Refresh token is invalidated", null));
        }

        if (refreshTokenMeta.isExpired()) {
            log.error("Refresh token is expired");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "Refresh token is expired", null));
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
                principalName, null, authorities);

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

        OAuth2Authorization authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            return;
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = authorization.getRefreshToken();
        if (refreshTokenMeta != null && !refreshTokenMeta.isInvalidated()) {
            builder.token(refreshTokenMeta.getToken(), metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessTokenMeta = authorization.getAccessToken();
        if (accessTokenMeta != null && !accessTokenMeta.isInvalidated()) {
            builder.token(accessTokenMeta.getToken(), metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        }

        authorizationService.save(builder.build());
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
        return transportStrategy.resolveAccessToken(request);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return transportStrategy.resolveRefreshToken(request);
    }

    @Override
    public AuthContextProperties properties() {
        return this.properties;
    }
}
