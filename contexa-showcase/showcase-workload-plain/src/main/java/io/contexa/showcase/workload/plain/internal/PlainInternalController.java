package io.contexa.showcase.workload.plain.internal;

import io.contexa.showcase.business.company.CompanyRepository;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.run.RunEvidence;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.plain.rules.RuleVersion;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Management API of the plain workload, called only by the portal orchestrator with a signed internal context
 * (docs/showcase/ADR.md ADR-24): run principals and their sign-in accounts, run facts, business evidence, run
 * cleanup, and the company facts the template learning replays.
 */
@RestController
public class PlainInternalController {

    public record PrincipalRequest(String username, String password, String employeeKey, String organizationId,
                                   String tenantId) {
    }

    /** @param clientIp address the activity was sent from; null means the office network of the employee */
    public record ScriptedActivityView(int activityNo, Instant observedAt, String operation, String targetKey,
                                       int items, String clientIp) {
    }

    public record EmployeeProfile(String employeeKey, String roleKey, String displayName, String department,
                                  String officeNetwork, String usualDevice,
                                  List<ScriptedActivityView> scriptedActivities) {
    }

    private final RunRegistry runs;
    private final CompanyRepository company;
    private final WorkDatabase database;
    private final PasswordEncoder passwordEncoder;
    private final BusinessContextLookup lookup;

    public PlainInternalController(RunRegistry runs, CompanyRepository company, WorkDatabase database,
                                   PasswordEncoder passwordEncoder, BusinessContextLookup lookup) {
        this.runs = runs;
        this.company = company;
        this.database = database;
        this.passwordEncoder = passwordEncoder;
        this.lookup = lookup;
    }

    @PostMapping("/internal/runs/{runId}/principals")
    public Map<String, String> registerPrincipal(@PathVariable("runId") String runId,
                                                 @RequestBody PrincipalRequest request) {
        runs.registerPrincipal(request.username(), runId, request.employeeKey(), request.organizationId(),
                request.tenantId());
        database.jdbc().update("""
                        insert into plain_user (username, password_hash) values (:username, :hash)
                        on conflict (username) do update set password_hash = excluded.password_hash""",
                new MapSqlParameterSource("username", request.username())
                        .addValue("hash", passwordEncoder.encode(request.password())));
        return Map.of("username", request.username(), "runId", runId);
    }

    @PostMapping("/internal/runs/{runId}/facts")
    public Map<String, Object> addFacts(@PathVariable("runId") String runId, @RequestBody RunFacts facts) {
        runs.addFacts(runId, facts);
        return Map.of("runId", runId, "tickets", facts.tickets().size(), "approvals", facts.approvals().size(),
                "oncall", facts.oncall().size());
    }

    @GetMapping("/internal/runs/{runId}/evidence")
    public RunEvidence evidence(@PathVariable("runId") String runId) {
        return runs.evidence(runId);
    }

    @DeleteMapping("/internal/runs/{runId}")
    public Map<String, Object> deleteRun(@PathVariable("runId") String runId) {
        int deleted = runs.deleteRun(runId);
        return Map.of("runId", runId, "deletedRows", deleted, "remainingRows", runs.remainingRows(runId));
    }

    /** The rule controls' published configuration and its hash (execution specification ruleVersion). */
    @GetMapping("/internal/rules")
    public Map<String, Object> rules() {
        return RuleVersion.describe(lookup.exportApprovalPolicy(), List.of(
                lookup.accessApprovalPolicy(BusinessOperation.ROLE_GRANT),
                lookup.accessApprovalPolicy(BusinessOperation.CUSTOMER_READ),
                lookup.accessApprovalPolicy(BusinessOperation.DOCUMENT_READ)));
    }

    /**
     * The protagonists: the employees whose normal work the business database scripts for the template learning
     * (docs/showcase/데모-재설계.md 5A.1.2), in key order.
     */
    @GetMapping("/internal/company/protagonists")
    public List<String> protagonists() {
        return database.jdbc().queryForList("select distinct employee_key from scripted_activity order by 1",
                new MapSqlParameterSource(), String.class);
    }

    /**
     * The choices of the lab (docs/showcase/데모-재설계.md 5A.1.1) as the business database holds them: the employees
     * asked for (the protagonists when none are named) with their project assignments, every project with its
     * sensitivity and owner, and every customer with its account manager. Nothing is chosen, filtered or worded here.
     */
    @GetMapping("/internal/company/lab-options")
    public Map<String, Object> labOptions(@RequestParam(name = "employees", required = false) List<String> employees) {
        MapSqlParameterSource keys = new MapSqlParameterSource("keys",
                employees == null || employees.isEmpty() ? protagonists() : employees);
        return Map.of(
                "employees", database.jdbc().queryForList("""
                        select employee_key, role_key, display_name, department, office_network from employee
                         where employee_key in (:keys) order by employee_key""", keys),
                "assignments", database.jdbc().queryForList("""
                        select project_key, employee_key, responsibility, assigned_from::text as assigned_from,
                               assigned_until::text as assigned_until
                          from project_assignment where employee_key in (:keys)
                         order by employee_key, project_key""", keys),
                "projects", database.jdbc().queryForList("""
                        select project_key, display_name, program, sensitivity, owner_employee_key from project
                         order by project_key""", new MapSqlParameterSource()),
                "customers", database.jdbc().queryForList("""
                        select customer_key, display_name, region, account_manager, project_key from customer
                         order by customer_key""", new MapSqlParameterSource()),
                "documentTypes", database.jdbc().queryForList("""
                        select project_key, document_type, count(*) as documents from document
                         where run_id is null
                         group by project_key, document_type order by project_key, document_type""",
                        new MapSqlParameterSource()));
    }

    @GetMapping("/internal/company")
    public ResponseEntity<CompanyRepository.Generation> generation() {
        return company.generation().map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    /**
     * Resolves a scenario's document selector: the n-th document (1-based, key order) of a type in a project.
     * Document keys are generated, so scenarios name documents by position instead of by key.
     */
    @GetMapping("/internal/company/documents/{projectKey}/{documentType}/{position}")
    public ResponseEntity<Map<String, String>> document(@PathVariable("projectKey") String projectKey,
                                                        @PathVariable("documentType") String documentType,
                                                        @PathVariable("position") int position) {
        if (position < 1) {
            return ResponseEntity.badRequest().build();
        }
        return database.jdbc().queryForList("""
                        select document_key from document
                         where project_key = :project and document_type = :type and run_id is null
                         order by document_key offset :skip limit 1""",
                        new MapSqlParameterSource("project", projectKey).addValue("type", documentType)
                                .addValue("skip", position - 1), String.class)
                .stream().findFirst()
                .map(key -> ResponseEntity.ok(Map.of("documentKey", key)))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/internal/company/employees/{employeeKey}")
    public ResponseEntity<EmployeeProfile> employee(@PathVariable("employeeKey") String employeeKey) {
        List<ScriptedActivityView> activities = database.jdbc().query("""
                        select activity_no, observed_at, operation, target_key, items, client_ip from scripted_activity
                         where employee_key = :employee order by activity_no""",
                new MapSqlParameterSource("employee", employeeKey),
                (rs, n) -> new ScriptedActivityView(rs.getInt(1), rs.getTimestamp(2).toInstant(), rs.getString(3),
                        rs.getString(4), rs.getInt(5), rs.getString(6)));
        return database.jdbc().query("""
                        select e.employee_key, e.role_key, e.display_name, e.department, e.office_network,
                               (select d.user_agent from device d where d.employee_key = e.employee_key
                                 order by d.device_key limit 1)
                          from employee e where e.employee_key = :employee""",
                        new MapSqlParameterSource("employee", employeeKey),
                        (rs, n) -> new EmployeeProfile(rs.getString(1), rs.getString(2), rs.getString(3),
                                rs.getString(4), rs.getString(5), rs.getString(6), activities))
                .stream().findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
