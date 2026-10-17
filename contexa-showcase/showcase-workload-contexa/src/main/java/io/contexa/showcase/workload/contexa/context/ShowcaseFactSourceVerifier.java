package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier;
import io.contexa.contexacore.verification.inspection.PromptInspectionSubject;
import io.contexa.contexacore.verification.inspection.PromptInspectionUnavailableException;
import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * W6-7 (P6-CHANGE-5): the showcase's own records of the company facts a sealed prompt states, read again from the work
 * database with queries of their own (not the lookup the engine asked), at the request's company time. It gives the
 * pieces the dictionary lines must hold: the on-call record, the assignment to the requested project, and the approval
 * the prompt names (its approver, its limit and what the requester exported under it before the request in this
 * control). Times, addresses and devices come from the request itself, which the fact accuracy check compares.
 */
public class ShowcaseFactSourceVerifier implements PromptFactSourceVerifier {

    private static final Pattern PROJECT = Pattern.compile("^/api/projects/([^/]+)(/.*)?$");
    private static final Pattern APPROVAL = Pattern.compile("^(\\S+) by ");
    private static final String SOURCE = "showcase work database ";

    private final WorkDatabase database;
    private final String control;

    public ShowcaseFactSourceVerifier(WorkDatabase database, String control) {
        this.database = database;
        this.control = control;
    }

    @Override
    public List<SourceFact> sourceFacts(PromptInspectionSubject subject) {
        return read(subject).facts();
    }

    /**
     * N-SRC-2: a request user the work database does not hold has no records here (the run rows go when the run ends,
     * RunRegistry.deleteRun), which is said as records not kept, not given as a source without facts; a database that
     * cannot be read now still inspects the package again later.
     */
    @Override
    public SourceReading read(PromptInspectionSubject subject) {
        CanonicalSecurityContext context = subject.canonicalContext();
        if (context == null || context.getActor() == null || context.getRequestObservedAt() == null) {
            return SourceReading.kept(List.of());
        }
        String username = context.getActor().getUserId();
        Instant at = context.getRequestObservedAt();
        try {
            Optional<Principal> principal = principal(username);
            if (principal.isEmpty()) {
                return SourceReading.notKept(SOURCE + "run_principal");
            }
            List<SourceFact> facts = new ArrayList<>();
            facts.add(onCall(principal.get(), at));
            project(context).ifPresent(project -> facts.add(assignment(principal.get(), project, at)));
            approvalKey(subject.prompt()).ifPresent(key -> facts.addAll(approval(principal.get(), key, at)));
            return SourceReading.kept(facts);
        } catch (DataAccessException e) {
            throw new PromptInspectionUnavailableException("the showcase work database cannot be read now", e);
        }
    }

    private Optional<Principal> principal(String username) {
        return database.jdbc().query("select employee_key, run_id from run_principal where username = :username",
                new MapSqlParameterSource("username", username),
                (rs, n) -> new Principal(username, rs.getString(1), rs.getString(2))).stream().findFirst();
    }

    private SourceFact onCall(Principal principal, Instant at) {
        Integer rosters = database.jdbc().queryForObject("""
                        select count(*) from oncall_roster
                         where employee_key = :employee and (run_id is null or run_id = :run)
                           and starts_at <= :at and ends_at > :at""",
                new MapSqlParameterSource("employee", principal.employeeKey()).addValue("run", principal.runId())
                        .addValue("at", Timestamp.from(at)), Integer.class);
        return rosters != null && rosters > 0
                ? new SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "on call", "not on call", SOURCE + "oncall_roster")
                : new SourceFact(PromptBlock.DECISION_FACTS, "OnCall", "not on call", null, SOURCE + "oncall_roster");
    }

    private SourceFact assignment(Principal principal, String project, Instant at) {
        Integer assignments = database.jdbc().queryForObject("""
                        select count(*) from project_assignment
                         where employee_key = :employee and project_key = :project
                           and assigned_from <= :day and (assigned_until is null or assigned_until >= :day)""",
                new MapSqlParameterSource("employee", principal.employeeKey()).addValue("project", project)
                        .addValue("day", Date.valueOf(at.atZone(ZoneOffset.UTC).toLocalDate())), Integer.class);
        String assigned = "assigned to " + project;
        return assignments != null && assignments > 0
                ? new SourceFact(PromptBlock.DECISION_FACTS, "Assignment", assigned, "not " + assigned,
                SOURCE + "project_assignment")
                : new SourceFact(PromptBlock.DECISION_FACTS, "Assignment", "not " + assigned, null,
                SOURCE + "project_assignment");
    }

    private List<SourceFact> approval(Principal principal, String key, Instant at) {
        return database.jdbc().query("""
                        select a.approver, a.max_items,
                               (select coalesce(sum(j.delivered_items), 0) from export_job j
                                 where j.username = :username and j.control = :control and j.project_key = a.project_key
                                   and j.company_at >= a.valid_from and j.company_at < least(a.valid_until, :at))
                          from approval a
                         where a.approval_key = :key and (a.run_id is null or a.run_id = :run)""",
                new MapSqlParameterSource("key", key).addValue("run", principal.runId())
                        .addValue("username", principal.username()).addValue("control", control)
                        .addValue("at", Timestamp.from(at)),
                (rs, n) -> List.of(
                        new SourceFact(PromptBlock.DECISION_FACTS, "Approval", key + " by " + rs.getString(1), null,
                                SOURCE + "approval"),
                        new SourceFact(PromptBlock.DECISION_FACTS, "Approval", "up to " + number(rs.getInt(2)) + " items",
                                null, SOURCE + "approval"),
                        new SourceFact(PromptBlock.DECISION_FACTS, "Approval",
                                "used " + number(rs.getInt(3)) + " before this request", null, SOURCE + "export_job")))
                .stream().findFirst().orElse(List.of());
    }

    private static Optional<String> project(CanonicalSecurityContext context) {
        String path = context.getResource() != null ? context.getResource().getRequestPath() : null;
        Matcher matcher = path != null ? PROJECT.matcher(path) : null;
        return matcher != null && matcher.matches() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    /** The approval the prompt names on its Approval line, which the source then reads by its key. */
    private static Optional<String> approvalKey(InspectedPrompt prompt) {
        return prompt.lines().stream()
                .filter(line -> line.kind() == InspectedPrompt.Kind.ENTRY && line.entryLine() != null)
                .filter(line -> line.block() == PromptBlock.DECISION_FACTS && "Approval".equals(line.entryLine().label()))
                .map(line -> APPROVAL.matcher(line.entryLine().value()))
                .filter(Matcher::find).map(matcher -> matcher.group(1)).findFirst();
    }

    private static String number(int value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    private record Principal(String username, String employeeKey, String runId) {
    }
}
