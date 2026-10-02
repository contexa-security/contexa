package io.contexa.demo.comparison.preparation.repository.jdbc;

import io.contexa.demo.comparison.preparation.dto.PreparedComparison;
import io.contexa.demo.comparison.preparation.repository.ComparisonPreparationRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.util.UUID;

@Repository
@Profile("portal")
public class JdbcComparisonPreparationRepository extends AbstractJsonJdbcRepository
        implements ComparisonPreparationRepository {

    private final TransactionOperations transactions;

    public JdbcComparisonPreparationRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc,
            DocumentCodec documents, @Qualifier("applicationTransactions") TransactionOperations transactions) {
        super(jdbc, documents);
        this.transactions = transactions;
    }

    @Override
    public PreparedComparison find(UUID visitorId, UUID id) {
        return first(jdbc.query("""
                select preparation::text from lab.comparison_preparation where visitor_id=? and id=?
                """, (rs, row) -> documents.read(rs.getString(1), PreparedComparison.class), visitorId, id));
    }

    @Override
    public PreparedComparison findCommand(UUID visitorId, UUID commandId) {
        return first(jdbc.query("""
                select preparation::text from lab.comparison_preparation where visitor_id=? and command_id=?
                """, (rs, row) -> documents.read(rs.getString(1), PreparedComparison.class), visitorId, commandId));
    }

    @Override
    public PreparedComparison save(PreparedComparison candidate, String submittedInputSha256, UUID workspaceId) {
        PreparedComparison stored = transactions.execute(status -> store(candidate, submittedInputSha256, workspaceId));
        if (stored == null || !stored.inputSha256().equals(submittedInputSha256)
                || !stored.workspaceId().equals(workspaceId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        return stored;
    }

    private PreparedComparison store(PreparedComparison candidate, String submittedInputSha256, UUID workspaceId) {
        Boolean active = jdbc.queryForObject("""
                select exists(select 1 from lab.workspace where id=? and visitor_id=? and expires_at>clock_timestamp())
                """, Boolean.class, workspaceId, candidate.visitorId());
        if (!Boolean.TRUE.equals(active)) {
            throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
        }
        int inserted = jdbc.update("""
                insert into lab.comparison_preparation
                    (id,visitor_id,workspace_id,command_id,prepared_at,input_sha256,snapshot_sha256,preparation)
                values (?,?,?,?,?,?,?,cast(? as jsonb)) on conflict(visitor_id,command_id) do nothing
                """, candidate.id(), candidate.visitorId(), candidate.workspaceId(), candidate.commandId(),
                Timestamp.from(candidate.preparedAt()), candidate.inputSha256(), candidate.snapshotSha256(),
                documents.write(candidate));
        PreparedComparison stored = findCommand(candidate.visitorId(), candidate.commandId());
        boolean same = stored != null && stored.inputSha256().equals(submittedInputSha256)
                && stored.workspaceId().equals(workspaceId);
        jdbc.update("""
                insert into lab.comparison_preparation_attempt
                    (id,preparation_id,submitted_input_sha256,outcome) values (?,?,?,?)
                """, UUID.randomUUID(), stored.id(), submittedInputSha256,
                !same ? "INPUT_CONFLICT" : inserted == 0 ? "REUSED" : "CREATED");
        return stored;
    }
}
