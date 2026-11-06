/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.bridge.AgentTokenClaims;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import io.contexa.contexaidentity.security.token.validator.OAuth2AuthorizationValidator;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

/**
 * Converts a validated access token into the authentication of the resource server chain. A token whose subject has a
 * user account authenticates as that user, with what the account holds at this request and the token's scopes. Its role
 * claims grant nothing: they say what the user could do when the token was issued, so a right taken away would outlive
 * the change, and a claim of another issuer would add to the account. A disabled account's token is refused, as its
 * session would end; a locked account's goes on as its session does, because anyone can lock an account with wrong
 * passwords.
 *
 * <p>A client's own token (client credentials: the subject is the client) has no user account, whatever account carries
 * the client's name. It authenticates only for a client the {@link AgentClientDirectory} names as an approved agent in
 * service, or a client the settings list as a service client ({@code contexa.auth.oauth2.service-client-ids}), and then
 * carries the token's scopes only (A1-2, AG-12b). The internal client and every other client is refused as before, as
 * is a token naming a user without an account.</p>
 */
public class OAuth2JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final UserDetailsService userDetailsService;
    private final OAuth2AuthorizationValidator authorizationValidator;
    private final AuthContextProperties properties;
    private final ObjectProvider<AgentClientDirectory> agentClientDirectory;
    private final ObjectProvider<BridgeProperties> bridgeProperties;
    private final JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();

    public OAuth2JwtAuthenticationConverter(HttpSecurity httpSecurity) {
        ApplicationContext applicationContext = httpSecurity.getSharedObject(ApplicationContext.class);
        this.userDetailsService = ContexaUserStore.of(applicationContext);
        AuthContextProperties properties = applicationContext.getBeanProvider(AuthContextProperties.class)
                .getIfAvailable();
        this.authorizationValidator = properties != null
                && properties.getOauth2ServerMode().includesAuthorizationServer()
                ? new OAuth2AuthorizationValidator(applicationContext.getBean(OAuth2AuthorizationService.class))
                : null;
        this.properties = properties;
        // Resolved per token: the directory is built after the security chains.
        this.agentClientDirectory = applicationContext.getBeanProvider(AgentClientDirectory.class);
        this.bridgeProperties = applicationContext.getBeanProvider(BridgeProperties.class);
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Assert.notNull(jwt.getSubject(), "Subject cannot be null");
        if (authorizationValidator != null) {
            authorizationValidator.validateAccessToken(jwt);
        }
        refuseSuspendedAgent(jwt);
        // Before any account is read: an account of the client's name is a person's, and would lend the client its rights.
        if (AgentTokenClaims.isClientOwnToken(jwt.getClaims(), tokenSettings())) {
            return clientPrincipal(jwt).orElseThrow(
                    () -> new UsernameNotFoundException("This client does not authenticate without a user account"));
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(jwt.getSubject());
        if (AccountTokenGuard.disabled(userDetails)) {
            throw new InvalidBearerTokenException("The account of this token is disabled");
        }
        Set<GrantedAuthority> authorities = new HashSet<>(scopeConverter.convert(jwt));
        authorities.addAll(userDetails.getAuthorities());

        return new JwtAuthenticationToken(jwt, authorities);
    }

    /** The authentication of a client's own token, when the client may authenticate without a user account. */
    private Optional<AbstractAuthenticationToken> clientPrincipal(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        BridgeProperties.Delegation.Token tokenSettings = tokenSettings();
        String clientId = jwt.getSubject();
        if (properties != null && clientId.equals(properties.getOauth2().getClientId())) {
            return Optional.empty();
        }
        List<String> serviceClients = properties != null ? properties.getOauth2().getServiceClientIds() : List.of();
        boolean serviceClient = serviceClients != null && serviceClients.contains(clientId);
        if (!serviceClient && !isApprovedAgent(AgentTokenClaims.tenant(claims, tokenSettings), clientId)) {
            return Optional.empty();
        }
        // The token's scopes only: a client has no account, and a role claim is not a grant to a client.
        return Optional.of(new JwtAuthenticationToken(jwt, scopeConverter.convert(jwt)));
    }

    /**
     * Whether the directory names the client as an approved agent in service. A directory that cannot say refuses the token
     * as it does when it cannot read a suspension: the client is not taken for no agent by the failure, and the failure is
     * the token's refusal and no error of the application.
     */
    private boolean isApprovedAgent(String tenantId, String clientId) {
        try {
            return directory().activeAgentForClient(tenantId, clientId).isPresent();
        } catch (AgentClientStatusUnavailableException unreadable) {
            throw new InvalidBearerTokenException("The agent this token was issued to cannot be read now");
        }
    }

    /**
     * docs/agent A5-3: a token issued to a suspended agent is refused, its own and one it holds for a person, so the
     * suspension stops the agent whichever token it carries and whichever authorization server issued it. A directory that
     * cannot read the suspension refuses the token as well, for now.
     */
    private void refuseSuspendedAgent(Jwt jwt) {
        BridgeProperties.Delegation.Token tokenSettings = tokenSettings();
        String clientId = AgentTokenClaims.firstText(jwt.getClaims(), tokenSettings.getClientIdClaims());
        // The internal client is the sign-in of a person, never an agent: such a token does not depend on the agent registry.
        if (clientId == null || isInternalClient(clientId)) {
            return;
        }
        boolean suspended;
        try {
            suspended = directory().suspendedAgentClient(AgentTokenClaims.tenant(jwt.getClaims(), tokenSettings), clientId);
        } catch (AgentClientStatusUnavailableException unreadable) {
            // A restriction is not lifted by a failure: the token waits until the status can be read. The cause stays in the
            // log; nothing of it is attached here, since a cause's text becomes the message of the exception.
            throw new InvalidBearerTokenException("The status of the agent this token was issued to cannot be read now");
        }
        if (suspended) {
            throw new InvalidBearerTokenException("The agent this token was issued to is suspended");
        }
    }

    private boolean isInternalClient(String clientId) {
        return properties != null && clientId.equals(properties.getOauth2().getClientId());
    }

    private AgentClientDirectory directory() {
        AgentClientDirectory directory = agentClientDirectory != null ? agentClientDirectory.getIfAvailable() : null;
        return directory != null ? directory : AgentClientDirectory.NONE;
    }

    private BridgeProperties.Delegation.Token tokenSettings() {
        BridgeProperties bridge = bridgeProperties != null ? bridgeProperties.getIfAvailable() : null;
        return (bridge != null ? bridge : new BridgeProperties()).getDelegation().getToken();
    }
}
