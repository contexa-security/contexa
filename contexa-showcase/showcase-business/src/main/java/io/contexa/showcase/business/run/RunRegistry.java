package io.contexa.showcase.business.run;

import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Per-run rows of the business database: the run principals, the facts a run adds on top of the company (its
 * chosen conditions), and the business evidence the controls wrote. {@link #deleteRun} removes all of them.
 */
public class RunRegistry {

    private final WorkDatabase database;

    public RunRegistry(WorkDatabase database) {
        this.database = database;
    }

    /** Idempotent: the plain and the Contexa workloads may both register the same principal. */
    public void registerPrincipal(String username, String runId, String employeeKey, String organizationId,
                                  String tenantId) {
        database.jdbc().update("""
                        insert into run_principal (username, run_id, employee_key, organization_id, tenant_id)
                        values (:username, :run, :employee, :org, :tenant)
                        on conflict (username) do nothing""",
                params().addValue("username", username).addValue("run", runId).addValue("employee", employeeKey)
                        .addValue("org", organizationId).addValue("tenant", tenantId));
    }

    public void addFacts(String runId, RunFacts facts) {
        database.transactions().executeWithoutResult(status -> {
            for (RunFacts.Ticket ticket : facts.tickets()) {
                database.jdbc().update("""
                                insert into itsm_ticket (ticket_key, run_id, kind, requester, approver, project_key,
                                                         purpose, summary, valid_from, valid_until, status)
                                values (:k, :run, :kind, :req, :appr, :project, :purpose, :summary, :from, :until,
                                        :status)""",
                        params().addValue("k", ticket.ticketKey()).addValue("run", runId)
                                .addValue("kind", ticket.kind()).addValue("req", ticket.requester())
                                .addValue("appr", ticket.approver()).addValue("project", ticket.projectKey())
                                .addValue("purpose", ticket.purpose()).addValue("summary", ticket.summary())
                                .addValue("from", timestamp(ticket.validFrom()))
                                .addValue("until", timestamp(ticket.validUntil())).addValue("status", ticket.status()));
            }
            for (RunFacts.Approval approval : facts.approvals()) {
                database.jdbc().update("""
                                insert into approval (approval_key, run_id, requester, approver, project_key, purpose,
                                                      max_items, valid_from, valid_until, status, approved_at)
                                values (:k, :run, :req, :appr, :project, :purpose, :max, :from, :until, :status,
                                        :approved)""",
                        params().addValue("k", approval.approvalKey()).addValue("run", runId)
                                .addValue("req", approval.requester()).addValue("appr", approval.approver())
                                .addValue("project", approval.projectKey()).addValue("purpose", approval.purpose())
                                .addValue("max", approval.maxItems()).addValue("from", timestamp(approval.validFrom()))
                                .addValue("until", timestamp(approval.validUntil()))
                                .addValue("status", approval.status())
                                .addValue("approved", approval.approvedAt() == null ? null
                                        : timestamp(approval.approvedAt())));
            }
            for (RunFacts.TravelPlan trip : facts.travel()) {
                database.jdbc().update("""
                                insert into travel_plan (plan_key, run_id, employee_key, city, country, network_cidr,
                                                         valid_from, valid_until)
                                values (:k, :run, :employee, :city, :country, :network, :from, :until)""",
                        params().addValue("k", trip.planKey()).addValue("run", runId)
                                .addValue("employee", trip.employeeKey()).addValue("city", trip.city())
                                .addValue("country", trip.country()).addValue("network", trip.networkCidr())
                                .addValue("from", timestamp(trip.validFrom()))
                                .addValue("until", timestamp(trip.validUntil())));
            }
            for (RunFacts.Document document : facts.documents()) {
                database.jdbc().update("""
                                insert into document (document_key, project_key, document_type, title, revision,
                                                      sensitivity, size_bytes, body, updated_on, run_id, author_name,
                                                      author_summary)
                                values (:k, :project, :type, :title, :revision, :sensitivity, :size, :body, :updated,
                                        :run, :author, :summary)""",
                        params().addValue("k", document.documentKey()).addValue("project", document.projectKey())
                                .addValue("type", document.documentType()).addValue("title", document.title())
                                .addValue("revision", document.revision()).addValue("sensitivity", document.sensitivity())
                                .addValue("size", document.body().getBytes(StandardCharsets.UTF_8).length)
                                .addValue("body", document.body()).addValue("updated", Date.valueOf(document.updatedOn()))
                                .addValue("run", runId).addValue("author", document.authorName())
                                .addValue("summary", document.authorSummary()));
            }
            for (RunFacts.Oncall oncall : facts.oncall()) {
                database.jdbc().update("""
                                insert into oncall_roster (roster_key, run_id, employee_key, team, starts_at, ends_at)
                                values (:k, :run, :employee, :team, :from, :until)""",
                        params().addValue("k", oncall.rosterKey()).addValue("run", runId)
                                .addValue("employee", oncall.employeeKey()).addValue("team", oncall.team())
                                .addValue("from", timestamp(oncall.startsAt()))
                                .addValue("until", timestamp(oncall.endsAt())));
            }
        });
    }

    /** Business evidence of a run: the export outcomes and the rule decisions, read before the run is deleted. */
    public RunEvidence evidence(String runId) {
        MapSqlParameterSource run = params().addValue("run", runId);
        List<Map<String, Object>> exports = database.jdbc().queryForList("""
                select job_id::text as job_id, request_id, control, username, project_key, mode, requested_items,
                       delivered_items, status, manifest_sha256, started_at, finished_at
                  from export_job where run_id = :run order by started_at, job_id""", run);
        List<Map<String, Object>> decisions = database.jdbc().queryForList("""
                select decision_id::text as decision_id, request_id, control, username, operation, rule_id, outcome,
                       reason, facts::text as facts, decided_at
                  from rule_decision_log where run_id = :run order by decided_at, decision_id""", run);
        return new RunEvidence(runId, exports, decisions);
    }

    /** Removes everything the run created in the business database. Returns the number of deleted rows. */
    public int deleteRun(String runId) {
        Integer deleted = database.transactions().execute(status -> {
            MapSqlParameterSource run = params().addValue("run", runId);
            int rows = 0;
            rows += database.jdbc().update("delete from rule_decision_log where run_id = :run", run);
            rows += database.jdbc().update("delete from export_job where run_id = :run", run);
            rows += database.jdbc().update("delete from itsm_ticket where run_id = :run", run);
            rows += database.jdbc().update("delete from approval where run_id = :run", run);
            rows += database.jdbc().update("delete from oncall_roster where run_id = :run", run);
            rows += database.jdbc().update("delete from travel_plan where run_id = :run", run);
            rows += database.jdbc().update("delete from role_grant where run_id = :run", run);
            rows += database.jdbc().update("delete from document where run_id = :run", run);
            rows += database.jdbc().update("delete from run_principal where run_id = :run", run);
            return rows;
        });
        return deleted == null ? 0 : deleted;
    }

    /** Rows a run still holds; zero after {@link #deleteRun} (isolation test T8). */
    public int remainingRows(String runId) {
        Integer count = database.jdbc().queryForObject("""
                select (select count(*) from rule_decision_log where run_id = :run)
                     + (select count(*) from export_job where run_id = :run)
                     + (select count(*) from itsm_ticket where run_id = :run)
                     + (select count(*) from approval where run_id = :run)
                     + (select count(*) from oncall_roster where run_id = :run)
                     + (select count(*) from travel_plan where run_id = :run)
                     + (select count(*) from role_grant where run_id = :run)
                     + (select count(*) from document where run_id = :run)
                     + (select count(*) from run_principal where run_id = :run)""",
                params().addValue("run", runId), Integer.class);
        return count == null ? 0 : count;
    }

    private static Timestamp timestamp(Instant value) {
        return value == null ? null : Timestamp.from(value);
    }

    private static MapSqlParameterSource params() {
        return new MapSqlParameterSource();
    }
}
