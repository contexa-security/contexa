package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyBlueprint;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The security administrator of one run (ADR-33): another employee of the IT administration, signed in to control D
 * with the engine's administrator role. It is created only when a release is asked for, so most runs never create it,
 * and the orchestrator removes it with the run. Its password never leaves the portal.
 */
final class RunApprover implements Approver {

    /** The employee who approves: Administrator B of the IT administration. */
    static final String EMPLOYEE = "adm-b";

    private final WorkloadAdmin admin;
    private final RunIdentity run;
    private final String username;
    private final Instant companyTime;
    private final Supplier<ControlSession> sessions;
    private Approver actions;
    private boolean created;
    private String displayName;

    RunApprover(WorkloadAdmin admin, RunIdentity run, String runHex, Instant companyTime,
                Supplier<ControlSession> sessions) {
        this.admin = admin;
        this.run = run;
        this.username = "v" + runHex + "-" + EMPLOYEE;
        this.companyTime = companyTime;
        this.sessions = sessions;
    }

    String username() {
        return username;
    }

    synchronized boolean created() {
        return created;
    }

    @Override
    public synchronized String displayName() {
        return displayName;
    }

    @Override
    public Optional<BlockRecord> request(String principal) throws IOException {
        return actions().request(principal);
    }

    @Override
    public int approve(long blockId, String reason) throws IOException {
        return actions().approve(blockId, reason);
    }

    private synchronized Approver actions() throws IOException {
        if (actions == null) {
            JsonNode employee = admin.employee(EMPLOYEE);
            String password = "Run-" + UUID.randomUUID() + "-Aa1";
            Map<String, Object> principal = new LinkedHashMap<>();
            principal.put("username", username);
            principal.put("password", password);
            principal.put("employeeKey", EMPLOYEE);
            principal.put("roleKey", employee.path("roleKey").asText());
            displayName = employee.path("displayName").asText();
            principal.put("displayName", displayName);
            principal.put("department", employee.path("department").asText());
            principal.put("organizationId", run.organization());
            principal.put("tenantId", run.tenant());
            principal.put("template", null);
            principal.put("approver", true);
            admin.createEnginePrincipal(run, principal);
            created = true;
            ControlSession session = sessions.get();
            session.signInEngine(username, password, username + "@" + CompanyBlueprint.EMAIL_DOMAIN, companyTime,
                    admin);
            actions = session.approverActions(companyTime);
        }
        return actions;
    }
}
