package io.contexa.demo.entry.repository.jdbc;

import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.entry.domain.EmailChallenge;
import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.entry.repository.EntryRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

@Repository
public class JdbcEntryRepository extends AbstractJdbcRepository implements EntryRepository {

    private final TransactionOperations transactions;

    public JdbcEntryRepository(@Qualifier("entryJdbc") JdbcOperations jdbc,
            @Qualifier("entryTransactions") TransactionOperations transactions) {
        super(jdbc);
        this.transactions = transactions;
    }

    public void lockRequest(UUID requestId) {
        jdbc.queryForList("select pg_advisory_xact_lock(hashtextextended(?,0))", "entry-request:" + requestId);
    }

    public Visitor find(String tokenHash, boolean lock) {
        if (tokenHash == null) {
            return null;
        }
        List<Visitor> rows = jdbc.query("""
                select id,email,verified_at,expires_at from lab.visitor
                where token_sha256=? and expires_at>current_timestamp
                """ + (lock ? " for update" : ""), (rs, n) -> {
            Timestamp verified = rs.getTimestamp("verified_at");
            return new Visitor(rs.getObject("id", UUID.class), rs.getString("email"),
                    verified == null ? null : verified.toInstant(), rs.getTimestamp("expires_at").toInstant());
        }, tokenHash);
        return rows.isEmpty() ? null : rows.get(0);
    }

    public <T> T transaction(Function<EntryRepository, T> work) {
        if (transactions == null) {
            throw new IllegalStateException("Entry mutations belong to portal");
        }
        return transactions.execute(status -> work.apply(this));
    }

    public Visitor create(String hash, Instant expiresAt) {
        UUID id = UUID.randomUUID();
        jdbc.update("insert into lab.visitor(id,token_sha256,expires_at) values(?,?,?)", id, hash,
                Timestamp.from(expiresAt));
        return new Visitor(id, null, null, expiresAt);
    }

    public EmailChallenge challenge(UUID id) {
        var rows = jdbc.query("""
                        select id,visitor_id,email,code_hash,delivery_state,created_at,expires_at,attempts
                        from lab.email_challenge where id=?
                        """,
                (rs, n) -> new EmailChallenge(rs.getObject("id", UUID.class), rs.getObject("visitor_id", UUID.class),
                        rs.getString("email"), rs.getString("code_hash"), rs.getString("delivery_state"),
                        rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("expires_at").toInstant(),
                        rs.getInt("attempts")), id);
        return rows.isEmpty() ? null : rows.get(0);
    }

    public void lockRateKeys(String email, String ip) {
        // Serialize quota checks across visitors; locks live only for this transaction.
        List.of("email:" + email, "ip:" + ip).stream().sorted().forEach(key ->
                jdbc.queryForList("select pg_advisory_xact_lock(hashtextextended(?,0))", key));
    }

    public boolean quotaExceeded(String email, String ip, EntryProperties properties) {
        Long emailCount = jdbc.queryForObject("""
                select count(*) from lab.email_challenge where email=? and created_at>current_timestamp-interval '1 day'
                """, Long.class, email);
        Long ipCount = jdbc.queryForObject("""
                select count(*) from lab.email_challenge where request_ip=? and created_at>current_timestamp-interval '1 day'
                """, Long.class, ip);
        return emailCount >= properties.emailDailyLimit() || ipCount >= properties.ipDailyLimit();
    }

    public EmailChallenge latestChallenge(UUID visitorId) {
        List<UUID> ids = jdbc.queryForList(
                "select id from lab.email_challenge where visitor_id=? order by created_at desc limit 1",
                UUID.class, visitorId);
        return ids.isEmpty() ? null : challenge(ids.get(0));
    }

    public Instant latestRequest(UUID visitorId) {
        Timestamp value = jdbc.queryForObject("select max(created_at) from lab.email_challenge where visitor_id=?",
                Timestamp.class, visitorId);
        return value == null ? null : value.toInstant();
    }

    public void insertChallenge(UUID id, Visitor visitor, String email, String codeHash, String ip, Instant expiresAt) {
        jdbc.update("""
                update lab.email_challenge set delivery_state='SUPERSEDED',code_hash=null
                where visitor_id=? and delivery_state in ('SENDING','SENT')
                """, visitor.id());
        jdbc.update("""
                insert into lab.email_challenge(id,visitor_id,email,code_hash,request_ip,expires_at,delivery_state)
                values(?,?,?,?,?,?,'SENDING')
                """, id, visitor.id(), email, codeHash, ip, Timestamp.from(expiresAt));
    }

    public void delivered(UUID id, boolean sent) {
        jdbc.update("""
                update lab.email_challenge set delivery_state=?,sent_at=case when ? then current_timestamp else null end,
                    code_hash=case when ? then code_hash else null end
                where id=? and delivery_state='SENDING'
                """, sent ? "SENT" : "FAILED", sent, sent, id);
    }

    public void reject(EmailChallenge challenge, String state) {
        jdbc.update("update lab.email_challenge set delivery_state=?,code_hash=null where id=?", state, challenge.id());
    }

    public void incorrect(EmailChallenge challenge, int maxAttempts) {
        int attempts = challenge.attempts() + 1;
        jdbc.update("""
                update lab.email_challenge set attempts=?,delivery_state=?,code_hash=case when ? then null else code_hash end
                where id=?
                """, attempts, attempts >= maxAttempts ? "LOCKED" : "SENT", attempts >= maxAttempts, challenge.id());
    }

    public void consume(EmailChallenge challenge, String newHash, Instant expiresAt) {
        jdbc.update("""
                update lab.email_challenge set delivery_state='CONSUMED',consumed_at=current_timestamp,code_hash=null where id=?
                """, challenge.id());
        jdbc.update("""
                update lab.visitor set email=?,verified_at=current_timestamp,token_sha256=?,expires_at=? where id=?
                """, challenge.email(), newHash, Timestamp.from(expiresAt), challenge.visitorId());
    }
}
