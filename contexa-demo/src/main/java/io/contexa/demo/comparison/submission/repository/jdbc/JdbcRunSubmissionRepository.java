package io.contexa.demo.comparison.submission.repository.jdbc;

import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.submission.dto.RunSubmission;
import io.contexa.demo.comparison.submission.repository.RunSubmissionRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcRunSubmissionRepository extends AbstractJsonJdbcRepository implements RunSubmissionRepository {

    private final TransactionOperations transactions;

    public JdbcRunSubmissionRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents,
            @Qualifier("comparisonTransactions") TransactionOperations transactions) {
        super(jdbc, documents);
        this.transactions = transactions;
    }

    @Override
    public UUID begin(UUID visitorId, RunCommand command) {
        return transactions.execute(transaction -> {
            var owned = jdbc.query("""
                    select id from lab.comparison_preparation where id=? and visitor_id=? for update
                    """, (row, index) -> row.getObject("id", UUID.class), command.preparationId(), visitorId);
            if (owned.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
            Integer count = jdbc.queryForObject("""
                    select count(*) from lab.comparison_run_submission where preparation_id=?
                    """, Integer.class, command.preparationId());
            if (count != null && count >= 32) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "PREPARATION_ATTEMPT_LIMIT");
            }
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into lab.comparison_run_submission(id,preparation_id,visitor_id,command_id,input_sha256)
                    values (?,?,?,?,?)
                    """, id, command.preparationId(), visitorId, command.commandId(), documents.hash(documents.write(command)));
            return id;
        });
    }

    @Override
    public void finish(UUID submissionId, String state, UUID runId, Integer httpStatus, String reason) {
        jdbc.update("""
                insert into lab.comparison_run_submission_result(submission_id,state,run_id,http_status,reason)
                values (?,?,?,?,?)
                """, submissionId, state, runId, httpStatus, reason);
    }

    @Override
    public List<RunSubmission> find(UUID visitorId, UUID preparationId) {
        return jdbc.query("""
                select s.*,r.state,r.run_id,r.http_status,r.finished_at,r.reason
                from lab.comparison_run_submission s left join lab.comparison_run_submission_result r
                    on r.submission_id=s.id
                where s.visitor_id=? and s.preparation_id=? order by s.started_at,s.id limit 32
                """, (row, index) -> new RunSubmission(row.getObject("id", UUID.class), preparationId,
                row.getObject("command_id", UUID.class), row.getTimestamp("started_at").toInstant(),
                row.getString("input_sha256"), row.getString("state") == null ? "UNCONFIRMED" : row.getString("state"),
                row.getObject("run_id", UUID.class), row.getObject("http_status", Integer.class),
                row.getTimestamp("finished_at") == null ? null : row.getTimestamp("finished_at").toInstant(),
                row.getString("reason")), visitorId, preparationId);
    }
}
