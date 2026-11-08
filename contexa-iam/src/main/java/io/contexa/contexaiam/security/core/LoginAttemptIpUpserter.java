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

import io.contexa.contexacommon.entity.LoginAttemptIp;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
     * Inserts a first-seen per-IP row. A duplicate-key collision is reported by the exception, and the
     * caller, which stands outside this bean's transaction, takes it as "someone else inserted first" and
     * follows up with an atomic increment either way. That increment counts the attempt, so the row starts
     * at zero.
     *
     * <p>The collision is not swallowed here: the persistence exception has already marked this
     * {@code REQUIRES_NEW} transaction rollback-only, so a method that returned normally would fail its own
     * commit with an {@code UnexpectedRollbackException}, and that one reached the sign-in. Left to leave the
     * method, the exception rolls this transaction back cleanly and touches nothing of the caller's.</p>
     */
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public void insertIfAbsent(String ip, LocalDateTime now, String username) {
        loginAttemptIpRepository.save(LoginAttemptIp.builder()
                .ipAddress(ip)
                .failedAttempts(0)
                .windowStartAt(now)
                .lastFailureAt(now)
                .lastUsername(username == null ? "" : username)
                .build());
    }
}
