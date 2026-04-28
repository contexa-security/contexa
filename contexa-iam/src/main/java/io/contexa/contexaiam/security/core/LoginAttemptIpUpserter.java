package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.entity.LoginAttemptIp;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Helper bean that performs a first-time per-IP row insert in its own transaction.
 *
 * <p>Why a separate bean instead of inlining the {@code save()} call inside
 * {@link LoginPolicyService#onLoginFailure(String, String, String, String)}:</p>
 * <ul>
 *   <li>Concurrent first-attempt failures from the same IP can race so that two transactions
 *       both miss the unique-key check and one of them throws
 *       {@link DataIntegrityViolationException}.</li>
 *   <li>That exception poisons the surrounding transaction (Hibernate marks it
 *       {@code rollback-only}), which would also discard the per-username counter increment
 *       performed earlier in the same transaction.</li>
 *   <li>Running the insert in a {@link Propagation#REQUIRES_NEW} transaction on a different
 *       bean (so Spring's transactional proxy actually intercepts the call) lets the duplicate
 *       failure stay isolated to this side-transaction. The caller can then safely retry the
 *       atomic increment.</li>
 * </ul>
 */
@Slf4j
@RequiredArgsConstructor
public class LoginAttemptIpUpserter {

    private final LoginAttemptIpRepository loginAttemptIpRepository;

    /**
     * Inserts a first-seen per-IP row, swallowing duplicate-key collisions. Always returns
     * normally; the caller is expected to follow up with an atomic increment, which will
     * succeed regardless of whether this insert won the race or lost it.
     */
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void insertIfAbsent(String ip, LocalDateTime now, String username) {
        try {
            loginAttemptIpRepository.save(LoginAttemptIp.builder()
                    .ipAddress(ip)
                    .failedAttempts(1)
                    .windowStartAt(now)
                    .lastFailureAt(now)
                    .lastUsername(username == null ? "" : username)
                    .build());
        } catch (DataIntegrityViolationException dup) {
            // A concurrent transaction inserted first; the caller's follow-up increment will succeed.
            log.error("[login-policy] concurrent ip insert lost race ip={} username={}", ip, username);
        }
    }
}
