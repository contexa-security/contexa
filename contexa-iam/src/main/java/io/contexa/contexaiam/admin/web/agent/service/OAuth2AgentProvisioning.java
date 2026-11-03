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
package io.contexa.contexaiam.admin.web.agent.service;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationSource;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Registers agents with Contexa's authorization server (docs/agent OC-3): the agent's OAuth2 client in the client
 * repository, the agent in the agent registry with its sponsor, and, when asked, the agent's own account through the
 * user management service. Secrets are generated here and returned once; only their hashes are kept. Every change is
 * audited.
 */
public class OAuth2AgentProvisioning implements AgentProvisioning {

    /** The agent kind recorded when the registration names none. */
    public static final String DEFAULT_AGENT_TYPE = "AGENT";
    /** The domain of an agent account's address (RFC 2606 reserved): no mail ever reaches an agent. */
    public static final String ACCOUNT_EMAIL_DOMAIN = "@agents.invalid";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final AgentRegistry registry;
    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final JdbcOperations jdbc;
    private final UserManagementService users;
    private final UserRepository userRepository;
    private final GroupRepository groups;
    private final CentralAuditFacade auditFacade;
    private final Duration defaultTokenLifetime;
    private UserEngineStatePurger engineStatePurger;

    public OAuth2AgentProvisioning(AgentRegistry registry, RegisteredClientRepository clients,
                                   PasswordEncoder passwordEncoder, @Nullable JdbcOperations jdbc,
                                   @Nullable UserManagementService users, @Nullable UserRepository userRepository,
                                   @Nullable GroupRepository groups, @Nullable CentralAuditFacade auditFacade,
                                   @Nullable Duration defaultTokenLifetime) {
        this.registry = Objects.requireNonNull(registry, "An agent registry is required");
        this.clients = Objects.requireNonNull(clients, "A client repository is required");
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder, "A password encoder is required");
        this.jdbc = jdbc;
        this.users = users;
        this.userRepository = userRepository;
        this.groups = groups;
        this.auditFacade = auditFacade;
        this.defaultTokenLifetime = defaultTokenLifetime != null ? defaultTokenLifetime : Duration.ofMinutes(30);
    }

    /**
     * CF-23: removes the engine state of the agent's client with the agent. An agent acting on its own works under its
     * client's identity, so its decisions, mirror user and learning are kept under the client ID; left behind, an
     * agent registered again with the same client would inherit them, as a deleted account's name would.
     */
    public void setEngineStatePurger(@Nullable UserEngineStatePurger engineStatePurger) {
        this.engineStatePurger = engineStatePurger;
    }

    @Override
    public boolean available() {
        return true;
    }

    @Override
    public Credentials register(Registration request, String administrator) {
        if (request == null) {
            throw new IllegalArgumentException("A registration is required");
        }
        String agentId = required(request.agentId(), "An agent identifier is required");
        String sponsor = required(request.sponsorId(), "A sponsor (the person accountable for the agent) is required");
        boolean ownToken = !Boolean.FALSE.equals(request.ownToken());
        boolean actsForPeople = !Boolean.FALSE.equals(request.actsForPeople());
        if (!ownToken && !actsForPeople) {
            throw new IllegalArgumentException("An agent needs its own token, token exchange or both");
        }
        registry.find(request.tenantId(), agentId)
                .filter(current -> current.source() == AgentRegistrationSource.LIFECYCLE
                        && current.status() != AgentStatus.DEREGISTERED)
                .ifPresent(current -> {
                    throw new IllegalArgumentException("Agent " + agentId + " is already registered");
                });
        String clientId = text(request.clientId()) != null ? text(request.clientId()) : agentId + "-client";
        if (clients.findByClientId(clientId) != null) {
            throw new IllegalArgumentException("OAuth2 client " + clientId + " already exists");
        }
        boolean account = Boolean.TRUE.equals(request.account());
        List<Long> groupIds = account ? groupIds(request.accountGroups()) : List.of();
        if (account) {
            requireAccounts();
            if (userRepository.findByUsername(agentId).isPresent()) {
                throw new IllegalArgumentException("An account named " + agentId + " already exists");
            }
        }
        Duration lifetime = request.tokenLifetime() != null && !request.tokenLifetime().isNegative()
                && !request.tokenLifetime().isZero() ? request.tokenLifetime() : defaultTokenLifetime;
        String secret = secret();
        Set<String> scopes = scopes(request.scopes());
        RegisteredClient.Builder client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(text(request.displayName()) != null ? text(request.displayName()) : agentId)
                .clientSecret(passwordEncoder.encode(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .scopes(names -> names.addAll(scopes))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(lifetime).build());
        if (ownToken) {
            client.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        }
        if (actsForPeople) {
            client.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE);
        }
        clients.save(client.build());
        AgentRegistration registration = registry.register(new AgentRegistrationRequest(request.tenantId(), agentId,
                text(request.displayName()), text(request.agentType()) != null ? text(request.agentType())
                : DEFAULT_AGENT_TYPE, clientId, sponsor, true));
        String password = null;
        if (account) {
            password = password();
            UserDto user = new UserDto();
            user.setUsername(agentId);
            user.setPassword(password);
            user.setName(text(request.displayName()) != null ? text(request.displayName()) : agentId);
            // An agent is never sent the people's sign-in factors (A1-13); its address is in a reserved domain.
            user.setEmail(agentId + ACCOUNT_EMAIL_DOMAIN);
            user.setEnabled(true);
            user.setSelectedGroupIds(groupIds);
            users.createUser(user);
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("clientId", clientId);
        details.put("sponsorId", sponsor);
        details.put("scopes", List.copyOf(scopes));
        details.put("ownToken", ownToken);
        details.put("actsForPeople", actsForPeople);
        details.put("account", account);
        audit(AuditEventCategory.AGENT_REGISTERED, administrator, agentId, null, details);
        return new Credentials(registration, clientId, secret, account ? agentId : null, password);
    }

    @Override
    public Credentials rotateSecret(@Nullable String tenantId, String agentId, String administrator) {
        AgentRegistration registration = known(tenantId, agentId);
        RegisteredClient client = client(registration);
        String secret = secret();
        clients.save(RegisteredClient.from(client).clientSecret(passwordEncoder.encode(secret)).build());
        audit(AuditEventCategory.AGENT_SECRET_ROTATED, administrator, registration.agentId(), null,
                Map.of("clientId", client.getClientId()));
        return new Credentials(registration, client.getClientId(), secret, null, null);
    }

    @Override
    public AgentRegistration transferSponsor(@Nullable String tenantId, String agentId, String sponsorId,
                                             String administrator) {
        String sponsor = required(sponsorId, "A sponsor is required");
        AgentRegistration before = known(tenantId, agentId);
        AgentRegistration after = registry.transferSponsor(tenantId, before.agentId(), sponsor).orElseThrow();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("from", before.sponsorId() != null ? before.sponsorId() : "");
        details.put("to", sponsor);
        audit(AuditEventCategory.AGENT_SPONSOR_CHANGED, administrator, after.agentId(), null, details);
        return after;
    }

    @Override
    public AgentRegistration deregister(@Nullable String tenantId, String agentId, String reason,
                                        String administrator) {
        String why = required(reason, "A reason is required");
        AgentRegistration registration = known(tenantId, agentId);
        AgentRegistration deregistered = registry.deregister(tenantId, registration.agentId(), why).orElseThrow();
        int revoked = 0;
        if (registration.clientId() != null) {
            RegisteredClient client = clients.findByClientId(registration.clientId());
            if (client != null) {
                clients.save(RegisteredClient.from(client).clientSecret(passwordEncoder.encode(secret())).build());
            }
            revoked = revokeTokens(registration.clientId());
        }
        boolean accountDisabled = false;
        if (userRepository != null) {
            Users account = userRepository.findByUsername(registration.agentId()).orElse(null);
            if (account != null && account.isEnabled()) {
                account.setEnabled(false);
                userRepository.save(account);
                accountDisabled = true;
            }
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("revokedTokens", revoked);
        details.put("accountDisabled", accountDisabled);
        audit(AuditEventCategory.AGENT_DEREGISTERED, administrator, registration.agentId(), why, details);
        return deregistered;
    }

    @Override
    public AgentRegistration remove(@Nullable String tenantId, String agentId, String administrator) {
        AgentRegistration registration = known(tenantId, agentId);
        int revoked = 0;
        boolean clientRemoved = false;
        if (registration.clientId() != null) {
            revoked = revokeTokens(registration.clientId());
            requireDatabase();
            clientRemoved = jdbc.update("delete from ctxa_oauth2_registered_client where client_id = ?",
                    registration.clientId()) > 0;
        }
        boolean accountRemoved = false;
        if (userRepository != null && users != null) {
            Users account = userRepository.findByUsername(registration.agentId()).orElse(null);
            if (account != null) {
                users.deleteUser(account.getId());
                accountRemoved = true;
            }
        }
        boolean clientStatePurged = false;
        if (registration.clientId() != null && engineStatePurger != null) {
            UserEngineStatePurgeResult purged = engineStatePurger.purge(registration.clientId());
            clientStatePurged = purged != null && purged.complete();
        }
        registry.remove(tenantId, registration.agentId());
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("revokedTokens", revoked);
        details.put("clientRemoved", clientRemoved);
        details.put("accountRemoved", accountRemoved);
        details.put("clientStatePurged", clientStatePurged);
        audit(AuditEventCategory.AGENT_REMOVED, administrator, registration.agentId(), null, details);
        return registration;
    }

    private AgentRegistration known(@Nullable String tenantId, String agentId) {
        String agent = required(agentId, "An agent identifier is required");
        return registry.find(tenantId, agent)
                .orElseThrow(() -> new NoSuchElementException("Agent " + agent + " is not known"));
    }

    private RegisteredClient client(AgentRegistration registration) {
        if (registration.clientId() == null) {
            throw new IllegalArgumentException("Agent " + registration.agentId() + " has no OAuth2 client");
        }
        RegisteredClient client = clients.findByClientId(registration.clientId());
        if (client == null) {
            throw new NoSuchElementException("OAuth2 client " + registration.clientId() + " is not registered");
        }
        return client;
    }

    private int revokeTokens(String clientId) {
        if (jdbc == null) {
            return 0;
        }
        return jdbc.update("delete from ctxa_oauth2_authorization where registered_client_id in "
                + "(select id from ctxa_oauth2_registered_client where client_id = ?)", clientId);
    }

    private List<Long> groupIds(@Nullable List<String> names) {
        if (names == null || names.isEmpty()) {
            return List.of();
        }
        if (groups == null) {
            throw new IllegalStateException("Groups cannot be read here");
        }
        List<Long> ids = new ArrayList<>();
        for (String name : names) {
            String group = text(name);
            if (group != null) {
                ids.add(groups.findByName(group).map(Group::getId)
                        .orElseThrow(() -> new IllegalArgumentException("No group is named " + group)));
            }
        }
        return ids;
    }

    private void requireAccounts() {
        if (users == null || userRepository == null) {
            throw new IllegalStateException("Accounts cannot be created here");
        }
    }

    private void requireDatabase() {
        if (jdbc == null) {
            throw new IllegalStateException("The Contexa database is needed to remove an OAuth2 client");
        }
    }

    private void audit(AuditEventCategory category, String administrator, String agentId, @Nullable String reason,
                       Map<String, Object> details) {
        if (auditFacade == null) {
            return;
        }
        auditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(category)
                .principalName(administrator)
                .resourceIdentifier(agentId)
                .eventSource("IAM")
                .action(category.name())
                .outcome("SUCCESS")
                .reason(reason)
                .details(details)
                .build());
    }

    private static Set<String> scopes(@Nullable List<String> values) {
        Set<String> scopes = new LinkedHashSet<>();
        if (values != null) {
            for (String value : values) {
                String scope = text(value);
                if (scope != null) {
                    scopes.add(scope);
                }
            }
        }
        return scopes;
    }

    /** A client secret: 32 random bytes, URL-safe. */
    static String secret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** An account password with every character class a password policy asks for. */
    static String password() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return "Ag7!" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String required(@Nullable String value, String message) {
        String text = text(value);
        if (text == null) {
            throw new IllegalArgumentException(message);
        }
        return text;
    }

    @Nullable
    private static String text(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
