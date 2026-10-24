package io.contexa.showcase.workload.contexa.principal;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.workload.contexa.policy.EngineRbacSeeder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * The agents of a run (docs/agent A7-0), registered the way an application registers its agents with Contexa: the
 * agent's OAuth2 client in the authorization server's client repository (client credentials for its own token, token
 * exchange for a token acting for a person), and the agent itself in Contexa's agent registry, approved and with the
 * person accountable for it. An agent that signs in with its own account (a session agent) also gets an engine account
 * in the engine group of its role, so its requests meet the same policies as a person's of that role.
 */
public class RunAgentService {

    /** The agent kind the registry records for a run's agent. */
    public static final String AGENT_TYPE = "SHOWCASE_RUN_AGENT";
    /** How long an agent's access token lives; a run is shorter. */
    static final Duration TOKEN_LIFETIME = Duration.ofMinutes(30);

    /**
     * @param sponsor         the person accountable for the agent (an engine principal of the run)
     * @param scopes          the scopes the agent's client may receive
     * @param accountPassword the password of the agent's own engine account; null for an agent with tokens only
     * @param accountRoleKey  the company role whose engine group the account joins; null without an account
     */
    public record Agent(String runId, String agentId, String displayName, String sponsor, String clientId,
                        String clientSecret, List<String> scopes, String accountPassword, String accountRoleKey) {

        public Agent {
            scopes = scopes == null ? List.of() : List.copyOf(scopes);
        }

        public boolean hasAccount() {
            return accountPassword != null && !accountPassword.isBlank();
        }
    }

    private final RegisteredClientRepository clients;
    private final AgentRegistry registry;
    private final UserRepository users;
    private final JdbcTemplate engine;
    private final PasswordEncoder passwordEncoder;
    private final RunPrincipalService principals;

    public RunAgentService(RegisteredClientRepository clients, AgentRegistry registry, UserRepository users,
                           JdbcTemplate engine, PasswordEncoder passwordEncoder, RunPrincipalService principals) {
        this.clients = clients;
        this.registry = registry;
        this.users = users;
        this.engine = engine;
        this.passwordEncoder = passwordEncoder;
        this.principals = principals;
    }

    public void register(Agent agent) {
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(agent.clientId())
                .clientName(agent.displayName())
                .clientSecret(passwordEncoder.encode(agent.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scopes(scopes -> scopes.addAll(agent.scopes()))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(TOKEN_LIFETIME).build())
                .build());
        registry.register(new AgentRegistrationRequest(null, agent.agentId(), agent.displayName(), AGENT_TYPE,
                agent.clientId(), agent.sponsor(), true));
        if (agent.hasAccount()) {
            Users saved = users.save(Users.builder()
                    .username(agent.agentId())
                    .email(agent.agentId() + "@" + CompanyBlueprint.EMAIL_DOMAIN)
                    .password(passwordEncoder.encode(agent.accountPassword()))
                    .name(agent.displayName())
                    .position(agent.accountRoleKey())
                    .locale("en")
                    .timezone("UTC")
                    .build());
            engine.update("insert into user_groups (user_id, group_id, assigned_by) "
                    + "select ?, group_id, 'showcase' from app_group where group_name = ? "
                    + "on conflict (user_id, group_id) do nothing", saved.getId(),
                    EngineRbacSeeder.engineGroup(agent.accountRoleKey()));
        }
    }

    /** Removes the agent's client with its issued tokens, its registry row and its account. */
    public void remove(String agentId, String clientId) {
        engine.update("delete from oauth2_authorization where registered_client_id in "
                + "(select id from oauth2_registered_client where client_id = ?)", clientId);
        engine.update("delete from oauth2_registered_client where client_id = ?", clientId);
        engine.update("delete from agent_registration where agent_id = ?", agentId);
        if (principals.exists(agentId)) {
            principals.delete(agentId);
        }
    }
}
