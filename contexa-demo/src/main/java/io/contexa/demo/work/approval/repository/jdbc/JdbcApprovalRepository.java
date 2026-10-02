package io.contexa.demo.work.approval.repository.jdbc;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import io.contexa.demo.work.approval.dto.ApprovalActor;
import io.contexa.demo.work.approval.dto.ApprovalDecisionRecord;
import io.contexa.demo.work.approval.dto.ApprovalRequestRecord;
import io.contexa.demo.work.approval.repository.ApprovalRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;

@Repository
@Profile({"baseline", "contexa"})
public class JdbcApprovalRepository extends AbstractJsonJdbcRepository implements ApprovalRepository {

    private final TransactionOperations transactions;

    public JdbcApprovalRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents,
            @Qualifier("applicationTransactions") TransactionOperations transactions) {
        super(jdbc, documents);
        this.transactions = transactions;
    }

    @Override
    public ApprovalRequestRecord request(UUID requestId, ApprovalRequestRecord record) {
        return transactions.execute(status -> storeRequest(requestId, record));
    }

    private ApprovalRequestRecord storeRequest(UUID requestId, ApprovalRequestRecord record) {
        int inserted = jdbc.update("""
                insert into lab.business_approval
                    (id,visitor_id,workspace_id,command_id,requester,requested_at,expires_at,input_sha256,request_record)
                values (?,?,?,?,?,?,?,?,cast(? as jsonb)) on conflict(visitor_id,command_id) do nothing
                """, record.id(), record.visitorId(), record.workspaceId(), record.commandId(), record.requester(),
                Timestamp.from(record.requestedAt()), Timestamp.from(record.expiresAt()), record.inputSha256(),
                documents.write(record));
        ApprovalRequestRecord stored = first(jdbc.query("""
                select request_record::text from lab.business_approval where visitor_id=? and command_id=?
                """, (rs, row) -> documents.read(rs.getString(1), ApprovalRequestRecord.class),
                record.visitorId(), record.commandId()));
        if (stored == null || !stored.inputSha256().equals(record.inputSha256())
                || !stored.requester().equals(record.requester()) || !stored.workspaceId().equals(record.workspaceId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        appendAttempt(requestId, stored.id(), record.commandId(), "REQUEST", inserted == 0);
        return stored;
    }

    @Override
    public ApprovalDecisionRecord decide(UUID requestId, ApprovalActor actor, ApprovalDecisionRecord record) {
        try {
            return transactions.execute(status -> storeDecision(requestId, actor, record));
        } catch (DuplicateKeyException duplicateCommand) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_ALREADY_USED", duplicateCommand);
        }
    }

    private ApprovalDecisionRecord storeDecision(UUID requestId, ApprovalActor actor, ApprovalDecisionRecord record) {
        ApprovalRequestRecord locked = first(jdbc.query("""
                select request_record::text from lab.business_approval
                where id=? and visitor_id=? and workspace_id=? for update
                """, (rs, row) -> documents.read(rs.getString(1), ApprovalRequestRecord.class), record.approvalId(),
                actor.participant().visitorId(), actor.participant().workspaceId()));
        if (locked == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        ApprovalDecisionRecord previous = decision(record.approvalId());
        if (previous != null) {
            if (!previous.commandId().equals(record.commandId()) || !previous.reviewer().equals(record.reviewer())
                    || !previous.inputSha256().equals(record.inputSha256())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "APPROVAL_ALREADY_REVIEWED");
            }
            appendAttempt(requestId, locked.id(), record.commandId(), "DECISION", true);
            return previous;
        }
        Boolean expired = jdbc.queryForObject("select expires_at<=clock_timestamp() from lab.business_approval where id=?",
                Boolean.class, record.approvalId());
        if (Boolean.TRUE.equals(expired)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "APPROVAL_EXPIRED");
        }
        jdbc.update("""
                insert into lab.business_approval_decision
                    (id,approval_id,visitor_id,command_id,reviewer,verdict,decided_at,input_sha256,decision_record)
                values (?,?,?,?,?,?,?,?,cast(? as jsonb))
                """, record.id(), record.approvalId(), actor.participant().visitorId(), record.commandId(),
                record.reviewer(), record.verdict().name(), Timestamp.from(record.decidedAt()), record.inputSha256(),
                documents.write(record));
        appendAttempt(requestId, locked.id(), record.commandId(), "DECISION", false);
        return record;
    }

    private void appendAttempt(UUID requestId, UUID approvalId, UUID commandId, String operation, boolean reused) {
        jdbc.update("""
                insert into lab.business_approval_attempt (request_id,approval_id,command_id,operation,reused)
                values (?,?,?,?,?)
                """, requestId, approvalId, commandId, operation, reused);
    }

    @Override
    public List<ApprovalRequestRecord> list(ApprovalActor actor) {
        return jdbc.query("""
                select request_record::text from lab.business_approval where visitor_id=? and workspace_id=?
                    and (? or requester=?) order by requested_at desc,id limit 100
                """, (rs, row) -> documents.read(rs.getString(1), ApprovalRequestRecord.class),
                actor.participant().visitorId(), actor.participant().workspaceId(), actor.administrator(),
                actor.participant().username());
    }

    @Override
    public ApprovalRequestRecord find(UUID id, UUID visitorId, UUID workspaceId) {
        return first(jdbc.query("""
                select request_record::text from lab.business_approval where id=? and visitor_id=? and workspace_id=?
                """, (rs, row) -> documents.read(rs.getString(1), ApprovalRequestRecord.class), id, visitorId, workspaceId));
    }

    @Override
    public ApprovalDecisionRecord decision(UUID approvalId) {
        return first(jdbc.query("select decision_record::text from lab.business_approval_decision where approval_id=?",
                (rs, row) -> documents.read(rs.getString(1), ApprovalDecisionRecord.class), approvalId));
    }
}
