package io.contexa.demo.identity.repository.jdbc;

import io.contexa.demo.identity.dto.IdentityAccount;
import io.contexa.demo.identity.dto.IdentitySnapshotStatus;
import io.contexa.demo.identity.repository.IdentitySnapshotRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.persistence.AbstractJsonJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Repository
@Profile("contexa")
public class JdbcIdentitySnapshotRepository extends AbstractJsonJdbcRepository implements IdentitySnapshotRepository {

    private final TransactionOperations transactions;

    public JdbcIdentitySnapshotRepository(@Qualifier("baselineJdbc") JdbcOperations jdbc, DocumentCodec documents,
            @Qualifier("baselineTransactions") TransactionOperations transactions) {
        super(jdbc, documents);
        this.transactions = transactions;
    }

    public IdentitySnapshotStatus synchronize(String sourceDatabase, List<IdentityAccount> accounts) {
        return transactions.execute(status -> {
            jdbc.queryForList("select pg_advisory_xact_lock(hashtextextended(?,0))", "lab-identity-scope");
            String hash = documents.hash(documents.write(accounts));
            var current = jdbc.query(
                    "select s.id,s.content_sha256 from lab.identity_scope_binding b "
                            + "join lab.identity_snapshot s on s.id=b.snapshot_id where b.scope_key='demo'",
                    (rs, n) -> new IdentitySnapshotStatus("MATCHED", rs.getObject("id", UUID.class),
                            rs.getString("content_sha256"), accounts.size(), null));
            if (!current.isEmpty()) {
                var existing = current.get(0);
                if (!hash.equals(existing.contentSha256())) {
                    return new IdentitySnapshotStatus("SOURCE_CHANGED", existing.snapshotId(), existing.contentSha256(),
                            null, null);
                }
                if (!hash.equals(documents.hash(
                        documents.write(read(accounts.stream().map(IdentityAccount::username).toList()))))) {
                    return new IdentitySnapshotStatus("BASELINE_CHANGED", existing.snapshotId(), hash, null, null);
                }
                return existing;
            }
            UUID id = UUID.randomUUID();
            jdbc.update(
                    "insert into lab.identity_snapshot(id,source_database,content_sha256,account_count) "
                            + "values(?,?,?,?) on conflict(content_sha256) do nothing",
                    id, sourceDatabase, hash, accounts.size());
            id = jdbc.queryForObject("select id from lab.identity_snapshot where content_sha256=?", UUID.class, hash);
            for (var account : accounts) {
                importAccount(id, account);
            }
            if (!hash.equals(
                    documents.hash(documents.write(read(accounts.stream().map(IdentityAccount::username).toList()))))) {
                throw new IllegalStateException("Identity import differs from source");
            }
            jdbc.update("insert into lab.identity_scope_binding(scope_key,snapshot_id) values('demo',?)", id);
            return new IdentitySnapshotStatus("MATCHED", id, hash, accounts.size(), null);
        });
    }

    private void importAccount(UUID id, IdentityAccount account) {
        jdbc.update("""
                        insert into lab.account(username,display_name,password_hash,enabled,source_user_id,source_snapshot_id,
                            account_locked,credentials_expired,external_auth_only,lock_expires_at) values(?,?,?,?,?,?,?,?,?,?)
                        on conflict(username) do update set display_name=excluded.display_name,password_hash=excluded.password_hash,
                            enabled=excluded.enabled,source_user_id=excluded.source_user_id,source_snapshot_id=excluded.source_snapshot_id,
                            account_locked=excluded.account_locked,credentials_expired=excluded.credentials_expired,
                            external_auth_only=excluded.external_auth_only,lock_expires_at=excluded.lock_expires_at
                        """, account.username(), account.displayName(), account.passwordHash(), account.enabled(),
                account.sourceUserId(), id,
                account.accountLocked(), account.credentialsExpired(), account.externalAuthOnly(),
                account.lockExpiresAt() == null ? null : Timestamp.valueOf(account.lockExpiresAt()));
        jdbc.update("delete from lab.account_role where username=?", account.username());
        for (String role : account.authorities()) {
            jdbc.update("insert into lab.account_role(username,authority) values(?,?)", account.username(), role);
        }
    }

    private List<IdentityAccount> read(List<String> names) {
        List<IdentityAccount> result = new ArrayList<>();
        for (String name : names) {
            result.add(jdbc.queryForObject("select * from lab.account where username=?", (rs, n) -> {
                var expiry = rs.getTimestamp("lock_expires_at");
                var roles =
                        jdbc.queryForList("select authority from lab.account_role where username=? order by authority",
                                String.class, name);
                return new IdentityAccount(rs.getLong("source_user_id"), name, rs.getString("display_name"),
                        rs.getString("password_hash"),
                        rs.getBoolean("enabled"), rs.getBoolean("account_locked"), rs.getBoolean("credentials_expired"),
                        rs.getBoolean("external_auth_only"), expiry == null ? null : expiry.toLocalDateTime(), roles);
            }, name));
        }
        return result;
    }
}
