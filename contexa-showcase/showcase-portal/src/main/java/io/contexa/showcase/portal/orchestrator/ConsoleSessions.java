package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyBlueprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * docs/agent RW-2 (A1-6): an operator's own browser sessions on control D's admin console. Each opens with a security
 * administrator of control D made the way a run's approver is (the IT administrator, with the engine's administrator
 * role). Its sign-in goes to the operator's local script through the ops port only, the one-time code comes from the
 * demo inbox, and the administrator is removed when the script closes the session or its lifetime ends.
 */
public final class ConsoleSessions {

    /** How long a session's administrator lives at most. */
    public static final Duration LIFETIME = Duration.ofMinutes(30);

    private static final Logger log = LoggerFactory.getLogger(ConsoleSessions.class);

    /** An open session: the administrator's sign-in and when it is removed at the latest. */
    public record Session(String key, String runId, String username, String password, String email,
                          Instant expiresAt) {
    }

    private final WorkloadAdmin admin;
    private final Clock clock;
    private final Map<String, Session> open = new ConcurrentHashMap<>();

    public ConsoleSessions(WorkloadAdmin admin, Clock clock) {
        this.admin = admin;
        this.clock = clock;
    }

    /** Creates the administrator of a new session in control D. */
    public Session open() throws IOException {
        closeExpired();
        byte[] random = new byte[6];
        new SecureRandom().nextBytes(random);
        String hex = HexFormat.of().formatHex(random);
        JsonNode employee = admin.employee(RunApprover.EMPLOYEE);
        RunIdentity identity = new RunIdentity("console-" + hex, "org-console-" + hex, "tenant-console-" + hex,
                RunOrchestrator.hostIn(employee.path("officeNetwork").asText(), 251), "ShowcasePortalConsole/1.0");
        String username = "v" + hex + "-" + RunApprover.EMPLOYEE;
        String password = "Console-" + UUID.randomUUID() + "-Aa1";
        Map<String, Object> principal = new LinkedHashMap<>();
        principal.put("username", username);
        principal.put("password", password);
        principal.put("employeeKey", RunApprover.EMPLOYEE);
        principal.put("roleKey", employee.path("roleKey").asText());
        principal.put("displayName", employee.path("displayName").asText());
        principal.put("department", employee.path("department").asText());
        principal.put("organizationId", identity.organization());
        principal.put("tenantId", identity.tenant());
        principal.put("template", null);
        principal.put("approver", true);
        admin.createEnginePrincipal(identity, principal);
        Session session = new Session(hex, identity.runId(), username, password,
                username + "@" + CompanyBlueprint.EMAIL_DOMAIN, clock.instant().plus(LIFETIME));
        open.put(hex, session);
        return session;
    }

    /** The one-time code the demo inbox holds for the session's administrator; empty for no open session or code. */
    public Optional<String> code(String key) throws IOException {
        closeExpired();
        Session session = open.get(key);
        return session == null ? Optional.empty() : admin.inboxCode(session.email());
    }

    /** Removes the session's administrator from control D; whether the session was open. */
    public boolean close(String key) throws IOException {
        Session session = open.remove(key);
        if (session == null) {
            return false;
        }
        admin.deleteEnginePrincipal(session.runId(), session.username());
        return true;
    }

    /** Removes every administrator whose lifetime ended. */
    public void closeExpired() {
        Instant now = clock.instant();
        for (Session session : List.copyOf(open.values())) {
            if (!session.expiresAt().isAfter(now)) {
                closeQuietly(session.key());
            }
        }
    }

    /** Removes every open administrator, as the portal stops. */
    public void closeAll() {
        for (String key : List.copyOf(open.keySet())) {
            closeQuietly(key);
        }
    }

    private void closeQuietly(String key) {
        try {
            close(key);
        } catch (IOException | RuntimeException e) {
            log.warn("A console session's administrator could not be removed: key={}", key, e);
        }
    }
}
