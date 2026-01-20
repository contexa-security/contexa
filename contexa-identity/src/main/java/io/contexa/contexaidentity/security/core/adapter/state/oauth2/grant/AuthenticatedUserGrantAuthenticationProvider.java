package io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant;

import io.contexa.contexaidentity.security.filter.MfaGrantedAuthority;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.*;


@Slf4j
public class AuthenticatedUserGrantAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;
    private final UserRepository userRepository;
    private final TransactionTemplate transactionTemplate;

    public AuthenticatedUserGrantAuthenticationProvider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            UserRepository userRepository,
            TransactionTemplate transactionTemplate) {

        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        Assert.notNull(userRepository, "userRepository cannot be null");
        Assert.notNull(transactionTemplate, "transactionTemplate cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userRepository = userRepository;
        this.transactionTemplate = transactionTemplate;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthenticatedUserGrantAuthenticationToken authenticationToken =
                (AuthenticatedUserGrantAuthenticationToken) authentication;

        
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(authenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (log.isTraceEnabled()) {
            log.trace("Retrieved registered client: {}", registeredClient.getId());
        }

        
        assert registeredClient != null;
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        
        String username = authenticationToken.getUsername();
        Users user = loadUserFromDatabase(username);
        Authentication userAuthentication = createAuthenticatedUser(user, registeredClient.getScopes());

        if (log.isDebugEnabled()) {
            log.debug("Created authenticated user with DB authorities for: {}", username);
        }

        
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(registeredClient.getScopes())
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrant(authenticationToken);

        
        if (authenticationToken.getDeviceId() != null) {
            tokenContextBuilder.put("device_id", authenticationToken.getDeviceId());
        }

        
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (log.isTraceEnabled()) {
            log.trace("Generated access token");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes());

        
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            if (log.isTraceEnabled()) {
                log.trace("Generated refresh token");
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
        }

        
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(userAuthentication.getName())
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizedScopes(registeredClient.getScopes())
                .attribute(Principal.class.getName(), userAuthentication);

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        
        transactionTemplate.executeWithoutResult(status -> {
            this.authorizationService.save(authorization);
            if (log.isDebugEnabled()) {
                log.debug("Saved OAuth2Authorization for user: {} in transaction", userAuthentication.getName());
            }
        });

        
        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken, Collections.emptyMap());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AuthenticatedUserGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
            Authentication authentication) {

        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    
    private Users loadUserFromDatabase(String username) {
        return userRepository.findByUsernameWithGroupsRolesAndPermissions(username)
                .orElseThrow(() -> {
                    log.warn("User not found in database: {}", username);
                    return new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                                    "User not found: " + username, ERROR_URI));
                });
    }

    
    private Authentication createAuthenticatedUser(Users user, Set<String> scopes) {

        
        List<GrantedAuthority> allAuthorities = new ArrayList<>();
        user.getRoleNames().stream()
                .map(MfaGrantedAuthority::new)
                .forEach(allAuthorities::add);

        
        if (scopes != null && !scopes.isEmpty()) {
            scopes.forEach(scope ->
                    allAuthorities.add(new MfaGrantedAuthority("SCOPE_" + scope)));
        }

        if (log.isTraceEnabled()) {
            log.trace("Created authentication with DB authorities: {} and scopes: {}",
                    user.getRoleNames(), scopes);
        }

        
        return new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                user.getPassword(),
                allAuthorities);
    }
}
