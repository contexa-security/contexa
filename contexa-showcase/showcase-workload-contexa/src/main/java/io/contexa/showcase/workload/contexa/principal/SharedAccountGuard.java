package io.contexa.showcase.workload.contexa.principal;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * No shared account can sign in to control D (deck p.37, P5-SEC-01). The engine's sample seed adds accounts with
 * well-known passwords (admin, manager and others); a demo of a security product must not keep any. At every start,
 * after the seed, every engine account that is neither a run principal nor a bridge mirror is disabled, locked and
 * given a random password nobody knows. Run principals are created per run and deleted after it.
 */
public class SharedAccountGuard {

    private final JdbcTemplate engine;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom random = new SecureRandom();

    public SharedAccountGuard(JdbcTemplate engine, PasswordEncoder passwordEncoder) {
        this.engine = engine;
        this.passwordEncoder = passwordEncoder;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void lockSharedAccounts() {
        for (String username : usableSharedAccounts()) {
            byte[] secret = new byte[32];
            random.nextBytes(secret);
            engine.update("update users set enabled = false, account_locked = true, password = ? where username = ?",
                    passwordEncoder.encode(Base64.getEncoder().encodeToString(secret)), username);
        }
    }

    /** Engine accounts other than run principals and bridge mirrors that could still sign in; empty when guarded. */
    public List<String> usableSharedAccounts() {
        return engine.queryForList("""
                select username from users
                 where username !~ ? and not bridge_managed and enabled and not account_locked
                 order by username""", String.class, OrphanPrincipalSweeper.PRINCIPAL_PATTERN);
    }
}
