/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.security.core;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Login policy enforcement with atomic, race-free counters.
 *
 * <p>Concurrency design:</p>
 * <ul>
 *   <li><b>Per-username counter</b> — a single SQL {@code UPDATE ... SET counter = counter + 1}
 *       avoids the read-modify-write race the legacy implementation suffered from.</li>
 *   <li><b>Per-IP counter</b> — same atomic increment via {@link LoginAttemptIpRepository}.</li>
 *   <li><b>Idempotent guard</b> — a request-scoped {@link ThreadLocal} marker ensures the
 *       same authentication outcome is recorded only once even when both an
 *       {@code AuthenticationEvent} listener and a legacy {@code AuthenticationHandler}
 *       call this service for the same request.</li>
 *   <li><b>Lock flip</b> — runs inside the outer authentication transaction. The outer
 *       method swallows all exceptions in a try/catch so a stray failure cannot abort the
 *       lock; using REQUIRES_NEW would be defeated by Spring's self-invocation rules and
 *       offers no real isolation here.</li>
 * </ul>
 */
@Slf4j
@RequiredArgsConstructor
public class LoginPolicyService implements LoginPolicyHandler {

    private static final ThreadLocal<Set<String>> HANDLED_KEYS =
            ThreadLocal.withInitial(HashSet::new);

    private final UserRepository userRepository;
    private final LoginAttemptIpRepository loginAttemptIpRepository;
    private final PasswordPolicyService passwordPolicyService;
    private final LoginAttemptIpUpserter loginAttemptIpUpserter;
    private final ObjectProvider<SecurityContextDataStore> securityContextDataStoreProvider;

    // ---------------------------------------------------------------------
    // Public API — legacy signatures delegate to the extended ones
    // ---------------------------------------------------------------------

    @Override
    public void onLoginSuccess(String username, String ip) {
        onLoginSuccess(username, ip, "HANDLER");
    }

    @Override
    public void onLoginFailure(String username) {
        onLoginFailure(username, null, "UNKNOWN", "HANDLER");
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void onLoginSuccess(String username, String ip, String sourceTag) {
        if (username == null || username.isBlank()) return;
        if (!firstHandle("S:" + username)) return; // idempotent guard

        try {
            int rows = userRepository.resetOnSuccess(username, LocalDateTime.now(), ip);
            if (rows == 0) {
                log.error("[login-policy] success reset skipped — unknown user {} (sourceTag={})", username, sourceTag);
            }
            if (ip != null && !ip.isBlank()) {
                loginAttemptIpRepository.findByIpAddress(ip).ifPresent(row ->
                        loginAttemptIpRepository.resetWindow(ip, LocalDateTime.now(),
                                LocalDateTime.now(), username));
            }
        } catch (Exception e) {
            log.error("[login-policy] onLoginSuccess failed for {}", username, e);
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void onLoginFailure(String username, String ip, String failureType, String sourceTag) {
        if (username == null || username.isBlank()) {
            recordLoginFailureContext(null, ip);
            applyIpThrottle(ip, null, "MISSING_USERNAME");
            return;
        }
        if (!firstHandle("F:" + username + ":" + (ip == null ? "-" : ip))) return; // idempotent guard
        recordLoginFailureContext(username, ip);

        try {
            // Self-heal: clear an expired lock before counting, otherwise the next failure
            // immediately re-triggers the threshold and creates a perpetual lock.
            userRepository.clearExpiredLock(username, LocalDateTime.now());

            int rows = userRepository.incrementFailedAttempts(username);
            if (rows == 0) {
                // Unknown username — do not write per-user row, but throttle the IP
                applyIpThrottle(ip, username, "UNKNOWN_USERNAME");
                return;
            }
            int attempts = userRepository.findFailedAttempts(username).orElse(0);

            PasswordPolicy policy = passwordPolicyService.getCurrentPolicy();
            if (policy.getMaxFailedAttempts() > 0 && attempts >= policy.getMaxFailedAttempts()) {
                applyUserLock(username, policy.getLockoutDurationMinutes(), attempts, failureType);
            }
            applyIpThrottle(ip, username, failureType);
        } catch (Exception e) {
            log.error("[login-policy] onLoginFailure failed for {}", username, e);
        }
    }

    private void recordLoginFailureContext(String username, String ip) {
        try {
            SecurityContextDataStore dataStore = securityContextDataStoreProvider == null
                    ? null
                    : securityContextDataStoreProvider.getIfAvailable();
            if (dataStore != null) {
                dataStore.recordLoginFailure(username, ip, System.currentTimeMillis());
            }
        } catch (Exception e) {
            log.warn("[login-policy] authentication failure context recording failed username={} ip={}",
                    username, ip, e);
        }
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean checkAndUnlockIfExpired(String username) {
        if (username == null || username.isBlank()) return false;
        return userRepository.clearExpiredLock(username, LocalDateTime.now()) > 0;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean isCredentialsExpired(String username) {
        PasswordPolicy policy = passwordPolicyService.getCurrentPolicy();
        if (policy.getPasswordExpiryDays() <= 0) return false;
        return userRepository.findByUsername(username).map(user -> {
            LocalDateTime changedAt = user.getPasswordChangedAt();
            if (changedAt == null) return false;
            return LocalDateTime.now().isAfter(changedAt.plusDays(policy.getPasswordExpiryDays()));
        }).orElse(false);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean isIpBlocked(String ip) {
        if (ip == null || ip.isBlank()) return false;
        return loginAttemptIpRepository.findByIpAddress(ip)
                .map(row -> row.getBlockedUntil() != null
                        && row.getBlockedUntil().isAfter(LocalDateTime.now()))
                .orElse(false);
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    /** Returns true the FIRST time this key is seen on the current thread. */
    private boolean firstHandle(String key) {
        Set<String> seen = HANDLED_KEYS.get();
        if (!seen.add(key)) {
            return false;
        }
        // Best-effort cleanup: cap memory if a thread is reused for many requests
        if (seen.size() > 32) {
            seen.clear();
            seen.add(key);
        }
        return true;
    }

    /**
     * Removes the per-thread idempotency marker. Invoked by
     * {@link LoginAttemptCleanupFilter} at the end of every HTTP request so that a recycled
     * Tomcat worker thread cannot carry deduplication state into the next request.
     */
    public static void clearRequestState() {
        HANDLED_KEYS.remove();
    }

    /**
     * Joins the surrounding transaction (REQUIRED). REQUIRES_NEW would be silently dropped
     * here because this is a self-invocation from {@link #onLoginFailure(String, String, String, String)}
     * and would not be intercepted by the Spring transactional proxy.
     */
    private void applyUserLock(String username, int lockoutMinutes, int attempts, String failureType) {
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(Math.max(1, lockoutMinutes));
        userRepository.lockAccount(username, expiresAt);
        log.error("[login-policy] account locked username={} attempts={} until={} failureType={}",
                username, attempts, expiresAt, failureType);
    }

    /** IP-dimension throttling: rolling window + threshold lock. */
    private void applyIpThrottle(String ip, String username, String failureType) {
        if (ip == null || ip.isBlank()) return;
        PasswordPolicy policy = passwordPolicyService.getCurrentPolicy();
        if (policy.getIpMaxFailedAttempts() <= 0) return;

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowStart = now.minusMinutes(Math.max(1, policy.getIpWindowMinutes()));
        String tag = username == null ? "" : username;

        // Self-heal: clear an expired IP block before counting (mirrors per-user logic)
        loginAttemptIpRepository.clearExpiredBlock(ip, now);

        int updated = loginAttemptIpRepository.incrementFailedAttempts(ip, now, tag);
        if (updated == 0) {
            // First-seen IP — insert via a separate REQUIRES_NEW transaction so a
            // duplicate-key collision does not poison the outer transaction (which
            // already incremented the per-username counter).
            loginAttemptIpUpserter.insertIfAbsent(ip, now, tag);
            // Re-attempt the increment: regardless of who won the insert race, a row now exists.
            loginAttemptIpRepository.incrementFailedAttempts(ip, now, tag);
        }

        loginAttemptIpRepository.findByIpAddress(ip).ifPresent(row -> {
            // Reset window if it has rolled over
            if (row.getWindowStartAt() == null || row.getWindowStartAt().isBefore(windowStart)) {
                loginAttemptIpRepository.resetWindow(ip, now, now, tag);
                return;
            }
            if (row.getFailedAttempts() >= policy.getIpMaxFailedAttempts()) {
                LocalDateTime blockUntil = now.plusMinutes(Math.max(1, policy.getIpWindowMinutes()));
                loginAttemptIpRepository.blockIp(ip, blockUntil);
                log.error("[login-policy] ip blocked ip={} attempts={} until={} username={} failureType={}",
                        ip, row.getFailedAttempts(), blockUntil, tag, failureType);
            }
        });
    }
}
