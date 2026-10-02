package io.contexa.demo.comparison.run.repository.jdbc;

import io.contexa.demo.comparison.run.dto.DispatchClaim;
import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.comparison.run.dto.RunStep;
import io.contexa.demo.comparison.run.repository.RunDispatchRepository;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;
import java.util.Set;
import java.util.UUID;

@Repository
public class JdbcRunDispatchRepository extends AbstractJdbcRepository implements RunDispatchRepository {

    private final TransactionOperations transactions;
    private final RunQuery query;

    public JdbcRunDispatchRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc,
            @Qualifier("comparisonTransactions") TransactionOperations transactions, RunQuery query) {
        super(jdbc);
        this.transactions = transactions;
        this.query = query;
    }

    @Override
    public DispatchClaim claim(UUID visitorId, UUID runId, UUID stepId, String arm, UUID requestId) {
        return transactions.execute(transaction -> {
            jdbc.queryForList("select id from lab.comparison_run where id=? and visitor_id=? for update",
                    runId, visitorId);
            RunRecord run = query.find(visitorId, runId);
            RunStep step = run == null ? null : query.steps(runId).stream()
                    .filter(value -> value.id().equals(stepId) && value.arm().equals(arm)).findFirst().orElse(null);
            if (step == null) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
            String outcome = outcome(run, step);
            if ("DISPATCHED".equals(outcome)) {
                jdbc.update("""
                        update lab.comparison_run_step set state='DISPATCHED',request_id=?,started_at=clock_timestamp()
                        where id=? and state='PLANNED'
                        """, requestId, stepId);
                jdbc.update("update lab.comparison_run set state='RUNNING' where id=?", runId);
            }
            jdbc.update("""
                    insert into lab.comparison_run_event(run_id,step_id,kind,detail)
                    values (?,?,?,?)
                    """, runId, stepId, outcome, requestId.toString());
            return new DispatchClaim(run, step, outcome, requestId);
        });
    }

    private String outcome(RunRecord run, RunStep step) {
        if ("NOT_DISPATCHED".equals(step.state())) {
            return "RUN_CLOSED";
        }
        if (!"PLANNED".equals(step.state())) {
            return "ALREADY_DISPATCHED";
        }
        if (!Set.of("READY", "RUNNING").contains(run.state())) {
            return "RUN_CLOSED";
        }
        Boolean active = jdbc.queryForObject("""
                select r.dispatch_deadline>clock_timestamp() and w.expires_at>clock_timestamp()
                from lab.comparison_run r join lab.workspace w on w.id=r.workspace_id where r.id=?
                """, Boolean.class, run.id());
        return Boolean.TRUE.equals(active) ? "DISPATCHED" : "RUN_EXPIRED";
    }

    @Override
    public void reject(UUID visitorId, UUID runId, UUID stepId, String arm, String reason) {
        jdbc.update("""
                insert into lab.comparison_run_event(run_id,step_id,kind,detail)
                select r.id,s.id,'INPUT_REJECTED',? from lab.comparison_run r
                join lab.comparison_run_step s on s.run_id=r.id
                where r.id=? and r.visitor_id=? and s.id=? and s.arm=?
                """, reason, runId, visitorId, stepId, arm);
    }

    @Override
    public void respond(UUID runId, UUID stepId, UUID requestId, Integer httpStatus, String failureType) {
        transactions.executeWithoutResult(transaction -> {
            jdbc.queryForList("select id from lab.comparison_run where id=? for update", runId);
            int updated = jdbc.update("""
                    update lab.comparison_run_step set state='RESPONDED',responded_at=clock_timestamp(),
                        http_status=?,failure_type=? where id=? and run_id=? and request_id=? and state='DISPATCHED'
                    """, httpStatus, failureType, stepId, runId, requestId);
            if (updated != 1) {
                return;
            }
            jdbc.update("""
                    insert into lab.comparison_run_event(run_id,step_id,kind,detail)
                    values (?,?,'HTTP_RETURNED',?)
                    """, runId, stepId, failureType == null ? String.valueOf(httpStatus) : failureType);
            jdbc.update("""
                    update lab.comparison_run set state='RESPONDED' where id=? and state in ('READY','RUNNING')
                        and not exists(select 1 from lab.comparison_run_step where run_id=? and state<>'RESPONDED')
                    """, runId, runId);
        });
    }
}
