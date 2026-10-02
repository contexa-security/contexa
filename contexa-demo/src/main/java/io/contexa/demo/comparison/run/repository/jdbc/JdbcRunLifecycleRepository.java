package io.contexa.demo.comparison.run.repository.jdbc;

import io.contexa.demo.comparison.run.repository.RunLifecycleRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import java.util.UUID;

@Repository
public class JdbcRunLifecycleRepository extends AbstractJdbcRepository implements RunLifecycleRepository {

    private final TransactionOperations transactions;

    public JdbcRunLifecycleRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc,
            @Qualifier("comparisonTransactions") TransactionOperations transactions) {
        super(jdbc);
        this.transactions = transactions;
    }

    @Override
    public void cancel(UUID visitorId, UUID runId) {
        close(visitorId, runId, "CANCELLED", false);
    }

    @Override
    public void expire(UUID visitorId, UUID runId) {
        close(visitorId, runId, "EXPIRED", true);
    }

    private void close(UUID visitorId, UUID runId, String state, boolean expiredOnly) {
        transactions.executeWithoutResult(transaction -> {
            jdbc.queryForList("select id from lab.comparison_run where id=? and visitor_id=? for update",
                    runId, visitorId);
            int updated = jdbc.update("""
                    update lab.comparison_run r set state=? where id=? and visitor_id=? and state in ('READY','RUNNING')
                        and (?=false or dispatch_deadline<=clock_timestamp()
                            or not exists(select 1 from lab.workspace w where w.id=r.workspace_id
                                and w.expires_at>clock_timestamp()))
                    """, state, runId, visitorId, expiredOnly);
            if (updated == 1) {
                stopPlanned(runId, state);
            }
        });
    }

    @Override
    public void interruptPreviousCoordinator(UUID instanceId) {
        transactions.executeWithoutResult(transaction -> {
            var active = jdbc.queryForList("""
                    select id from lab.comparison_run where state in ('READY','RUNNING')
                        and coordinator_instance_id<>? for update
                    """, UUID.class, instanceId);
            for (UUID runId : active) {
                jdbc.update("update lab.comparison_run set state='INTERRUPTED' where id=?", runId);
                stopPlanned(runId, "INTERRUPTED");
            }
        });
    }

    private void stopPlanned(UUID runId, String state) {
        jdbc.update("update lab.comparison_run_step set state='NOT_DISPATCHED' where run_id=? and state='PLANNED'", runId);
        jdbc.update("insert into lab.comparison_run_event(run_id,kind) values (?,?)", runId, state);
    }
}
