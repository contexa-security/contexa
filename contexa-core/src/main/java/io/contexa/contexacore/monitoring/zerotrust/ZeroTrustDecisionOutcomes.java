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
package io.contexa.contexacore.monitoring.zerotrust;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * What happened after a decision (console design 7.3): the account owner passed or failed the challenge, it expired,
 * the user asked to be unblocked, an administrator released the block or kept it, an administrator evaluated the
 * decision. These are the answers a decision gets later, the only signals of whether it was right. A write that fails
 * never stops the flow that reports the outcome (an authentication, a release); it is logged as an error.
 */
@Slf4j
public class ZeroTrustDecisionOutcomes {

    /** The outcome of a decision. */
    public enum Kind {
        /**
         * Console design 6.2: a code was mailed to the challenged account owner for the additional authentication (the
         * funnel's "code requested"); a factor without a mailed code (a passkey, an authenticator app) has none.
         */
        CHALLENGE_CODE_REQUESTED,
        /** The challenged account owner passed the additional authentication. */
        CHALLENGE_PASSED,
        /** The additional authentication failed. */
        CHALLENGE_FAILED,
        /** Nobody answered the challenge within its time; the aggregation records it. */
        CHALLENGE_EXPIRED,
        /** The blocked user asked to be unblocked. */
        UNBLOCK_REQUESTED,
        /** An administrator released the block (the decision was overridden). */
        ADMIN_RELEASED,
        /** The block stayed: an administrator kept it, or its answer time passed without a release. */
        BLOCK_KEPT,
        /** An administrator judged the decision right. */
        EVALUATED_VALID,
        /** An administrator judged the decision wrong, with a reason. */
        EVALUATED_INVALID
    }

    /** Why an administrator judged a decision wrong (console design 6.4). */
    public enum EvaluationReason {
        /** The response was stronger than the facts called for. */
        OVERREACTION,
        /** The reason the decision gave does not match the facts. */
        FACTS_WRONG,
        /** The decision missed a signal it should have weighed. */
        MISSED_SIGNAL,
        OTHER
    }

    /** The outcome kinds that answer a challenge; the aggregation records an expiry only for a challenge without one. */
    public static final List<Kind> CHALLENGE_ANSWERS =
            List.of(Kind.CHALLENGE_PASSED, Kind.CHALLENGE_FAILED, Kind.CHALLENGE_EXPIRED);

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final Clock clock;

    public ZeroTrustDecisionOutcomes(Supplier<JdbcOperations> jdbcOperationsSupplier) {
        this(jdbcOperationsSupplier, Clock.systemUTC());
    }

    public ZeroTrustDecisionOutcomes(Supplier<JdbcOperations> jdbcOperationsSupplier, Clock clock) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * Records an outcome of the decision of a request. The decision row is found by the request id when the caller
     * does not know it; an outcome whose decision cannot be found is kept with its request id, so a later decision row
     * of the same request still meets it.
     *
     * @return the outcome id, or null when nothing was written
     */
    public String record(String requestId, String userId, String tenantId, Kind kind, String actor, String note) {
        return record(null, requestId, userId, tenantId, kind, null, actor, note);
    }

    /** Records an administrator's evaluation of a decision (console design 11.3). */
    public String evaluate(String observationId, String requestId, String userId, String tenantId, boolean valid,
                           EvaluationReason reason, String actor, String note) {
        return record(observationId, requestId, userId, tenantId,
                valid ? Kind.EVALUATED_VALID : Kind.EVALUATED_INVALID,
                valid ? null : (reason != null ? reason : EvaluationReason.OTHER), actor, note);
    }

    /** Records an outcome; the caller may give the decision row it belongs to. */
    public String record(String observationId, String requestId, String userId, String tenantId, Kind kind,
                         EvaluationReason reason, String actor, String note) {
        if (kind == null) {
            return null;
        }
        JdbcOperations jdbc = jdbcOperationsSupplier.get();
        if (jdbc == null) {
            return null;
        }
        String outcomeId = UUID.randomUUID().toString();
        Instant now = clock.instant();
        try {
            String decision = observationId != null ? observationId : decisionOf(jdbc, requestId);
            jdbc.update("""
                    INSERT INTO ctxa_zt_decision_outcome
                        (outcome_id, observation_id, request_id, user_id, tenant_id, outcome_kind, evaluation_reason,
                         actor, note, occurred_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    outcomeId, decision, truncate(requestId, 160), truncate(userId, 160), truncate(tenantId, 160),
                    kind.name(), reason != null ? reason.name() : null, truncate(actor, 255), truncate(note, 1024),
                    Timestamp.from(now), Timestamp.from(now));
            return outcomeId;
        }
        catch (DataAccessException exception) {
            log.error("[ZeroTrustDecisionOutcomes] Failed to record the {} outcome of request {}", kind, requestId,
                    exception);
            return null;
        }
    }

    /** The latest successful decision row of the request, or null. */
    private static String decisionOf(JdbcOperations jdbc, String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return null;
        }
        List<String> found = jdbc.queryForList("""
                SELECT observation_id
                  FROM ctxa_ai_security_decision_observation
                 WHERE request_id = ?
                   AND success = TRUE
                 ORDER BY created_at DESC
                 LIMIT 1
                """, String.class, requestId);
        return found.isEmpty() ? null : found.get(0);
    }

    private static String truncate(String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }
}
