package io.contexa.demo.identity.repository.jdbc;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.identity.configuration.IdentityProperties;
import io.contexa.demo.identity.repository.AccountRepository;
import io.contexa.demo.shared.persistence.AbstractJdbcRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionOperations;

import java.util.HashSet;
import java.util.List;

@Repository
@Profile("!contexa")
public class JdbcAccountRepository extends AbstractJdbcRepository implements AccountRepository {

    private final LabProperties lab;
    private final IdentityProperties identities;
    private final TransactionOperations transactions;

    public JdbcAccountRepository(@Qualifier("jdbcTemplate") JdbcOperations jdbc, LabProperties lab,
            IdentityProperties identities, @Qualifier("applicationTransactions") TransactionOperations transactions) {
        super(jdbc);
        this.lab = lab;
        this.identities = identities;
        this.transactions = transactions;
    }

    public UserDetails find(String username) {
        boolean baseline = "baseline".equals(lab.role());
        if (baseline && !identities.usernames().contains(username)) {
            throw new UsernameNotFoundException("Account not found");
        }
        String source = baseline ? " and source_snapshot_id is not null" : "";
        var values = jdbc.query("""
                select username,password_hash,enabled,display_name,created_at,source_user_id,
                       account_locked,credentials_expired,external_auth_only,lock_expires_at
                from lab.account where username=?
                """ + source, (rs, n) -> UserDto.builder().id(rs.getObject("source_user_id", Long.class))
                .username(rs.getString("username")).password(rs.getString("password_hash"))
                .name(rs.getString("display_name")).enabled(rs.getBoolean("enabled"))
                .accountLocked(rs.getBoolean("account_locked")).credentialsExpired(rs.getBoolean("credentials_expired"))
                .externalAuthOnly(rs.getBoolean("external_auth_only"))
                .lockExpiresAt(rs.getTimestamp("lock_expires_at") == null ? null :
                        rs.getTimestamp("lock_expires_at").toLocalDateTime())
                .createdAt(rs.getTimestamp("created_at").toLocalDateTime()).build(), username);
        if (values.isEmpty()) {
            throw new UsernameNotFoundException("Account not found");
        }
        var roles = jdbc.queryForList("select authority from lab.account_role where username=? order by authority",
                String.class, username);
        return new UnifiedCustomUserDetails(values.get(0),
                new HashSet<>(roles.stream().map(SimpleGrantedAuthority::new).toList()));
    }

    public void seedPortalAccount(String username, String displayName, String hash, List<String> roles) {
        if (!"portal".equals(lab.role())) {
            throw new IllegalStateException("Portal seed cannot mutate a worker");
        }
        transactions.executeWithoutResult(status -> {
            int inserted = jdbc.update(
                    "insert into lab.account(username,display_name,password_hash) values(?,?,?) on conflict(username) do nothing",
                    username, displayName, hash);
            if (inserted == 1) {
                roles.forEach(
                        role -> jdbc.update("insert into lab.account_role(username,authority) values(?,?)", username,
                                role));
            }
        });
    }

    public int enabledCount() {
        return identities.usernames().stream().mapToInt(name -> {
            try {
                return find(name).isEnabled() ? 1 : 0;
            } catch (UsernameNotFoundException absent) {
                return 0;
            }
        }).sum();
    }
}
