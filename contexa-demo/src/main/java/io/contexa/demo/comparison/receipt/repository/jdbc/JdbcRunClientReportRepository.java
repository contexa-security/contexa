package io.contexa.demo.comparison.receipt.repository.jdbc;

import io.contexa.demo.comparison.receipt.dto.RunClientReport;
import io.contexa.demo.comparison.receipt.dto.RunClientReportInput;
import io.contexa.demo.comparison.receipt.repository.RunClientReportRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcRunClientReportRepository extends AbstractJsonJdbcRepository implements RunClientReportRepository {

    private final TransactionOperations transactions;

    public JdbcRunClientReportRepository(@Qualifier("comparisonJdbc") JdbcOperations jdbc, DocumentCodec documents,
            @Qualifier("comparisonTransactions") TransactionOperations transactions) {
        super(jdbc, documents);
        this.transactions = transactions;
    }

    @Override
    public RunClientReport save(UUID visitorId, UUID runId, RunClientReportInput input) {
        return transactions.execute(status -> {
            var owned = jdbc.queryForList("select id from lab.comparison_run where id=? and visitor_id=? for update",
                    UUID.class, runId, visitorId);
            if (owned.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
            Boolean stepOwned = jdbc.queryForObject(
                    "select exists(select 1 from lab.comparison_run_step where run_id=? and id=?)",
                    Boolean.class, runId, input.stepId());
            if (!Boolean.TRUE.equals(stepOwned)) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
            String encoded = documents.write(input);
            String hash = documents.hash(encoded);
            RunClientReport prior = read(input.attemptId(), input.stage());
            if (prior != null) {
                return same(prior, runId, hash);
            }
            Integer count = jdbc.queryForObject("select count(*) from lab.comparison_client_report where run_id=?",
                    Integer.class, runId);
            if (count != null && count >= 32) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "CLIENT_REPORT_LIMIT");
            }
            jdbc.update("""
                    insert into lab.comparison_client_report(attempt_id,stage,run_id,step_id,content_sha256,payload)
                    values (?,?,?,?,?,cast(? as jsonb)) on conflict(attempt_id,stage) do nothing
                    """, input.attemptId(), input.stage(), runId, input.stepId(), hash, encoded);
            return same(read(input.attemptId(), input.stage()), runId, hash);
        });
    }

    @Override
    public List<RunClientReport> find(UUID visitorId, UUID runId) {
        return jdbc.query("""
                select c.* from lab.comparison_client_report c join lab.comparison_run r on r.id=c.run_id
                where r.id=? and r.visitor_id=? order by c.received_at,c.attempt_id,c.stage limit 32
                """, (rs, row) -> record(rs), runId, visitorId);
    }

    private RunClientReport read(UUID attemptId, String stage) {
        return first(jdbc.query("select * from lab.comparison_client_report where attempt_id=? and stage=?",
                (rs, row) -> record(rs), attemptId, stage));
    }

    private RunClientReport same(RunClientReport value, UUID runId, String hash) {
        if (value == null || !value.runId().equals(runId) || !value.sha256().equals(hash)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "CLIENT_REPORT_CHANGED");
        }
        return value;
    }

    private RunClientReport record(ResultSet rs) throws SQLException {
        return new RunClientReport(rs.getObject("run_id", UUID.class), rs.getTimestamp("received_at").toInstant(),
                rs.getString("content_sha256"), "UNVERIFIED_BROWSER_REPORT_NOT_ENGINE_OR_DELIVERY_PROOF",
                documents.read(rs.getString("payload"), RunClientReportInput.class));
    }
}
