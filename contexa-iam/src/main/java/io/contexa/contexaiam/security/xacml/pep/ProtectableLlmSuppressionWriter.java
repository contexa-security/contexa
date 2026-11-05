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
package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

@Slf4j
public class ProtectableLlmSuppressionWriter {

    /** The reason of a row that says a protected method ran with no user, so nothing was decided. */
    public static final String RAN_WITHOUT_USER = "RAN_WITHOUT_USER";
    /** A job can run every second: its calls share a row per interval and method. */
    private static final long WITHOUT_USER_ROW_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactionTemplate;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, CallsWithoutUser> callsWithoutUser = new ConcurrentHashMap<>();

    public ProtectableLlmSuppressionWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper,
            PlatformTransactionManager transactionManager) {
        this(jdbcOperationsSupplier, objectMapper, transactionManager, System::nanoTime);
    }

    ProtectableLlmSuppressionWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper,
            PlatformTransactionManager transactionManager,
            LongSupplier clock) {
        this.clock = clock;
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.objectMapper = objectMapper;
        this.transactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
        if (this.transactionTemplate != null) {
            this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            this.transactionTemplate.setReadOnly(false);
        }
    }

    /**
     * Q-10: a protected method ran with no user and no request, so there was nothing to decide. An operator is told once
     * per method; the row counts the calls since the last one, so a job that runs every second costs a row a minute.
     */
    public void recordRanWithoutUser(MethodInvocation invocation, String zeroTrustMode) {
        if (invocation == null) {
            return;
        }
        String resourceId = resourceIdOf(invocation);
        CallsWithoutUser calls = callsWithoutUser.computeIfAbsent(resourceId, key -> new CallsWithoutUser());
        long callsToRecord = calls.count(clock.getAsLong());
        if (callsToRecord == 0) {
            return;
        }
        if (calls.firstRecord()) {
            log.warn("[Contexa] @Protectable method {} ran with no user and no request, so it was not decided. Pass the "
                    + "user's security context to its thread to have it decided.", resourceId);
        }
        JdbcOperations jdbcOperations = jdbcOperationsSupplier.get();
        if (jdbcOperations != null) {
            write(jdbcOperations, null, invocation, RAN_WITHOUT_USER, zeroTrustMode,
                    Map.of("callsSinceLastRecord", callsToRecord));
        }
    }

    public void recordSuppressed(
            Authentication authentication,
            MethodInvocation invocation,
            String suppressionReason,
            String zeroTrustMode) {
        JdbcOperations jdbcOperations = jdbcOperationsSupplier.get();
        if (jdbcOperations == null || authentication == null || invocation == null) {
            return;
        }
        write(jdbcOperations, authentication.getName(), invocation, suppressionReason, zeroTrustMode, Map.of());
    }

    private void write(JdbcOperations jdbcOperations, String userId, MethodInvocation invocation, String suppressionReason,
                       String zeroTrustMode, Map<String, Object> details) {
        HttpServletRequest request = currentRequest();
        String suppressionId = UUID.randomUUID().toString();
        String contextBindingHash = request == null ? null : SessionFingerprintUtil.generateContextBindingHash(request);
        // The same server id the engine records for this request; the caller's own id is kept for correlation only.
        String requestId = request == null ? suppressionId : RequestInfoExtractor.extractRequestId(request);
        String clientRequestId = request == null ? null : RequestInfoExtractor.extractClientRequestId(request);
        String testRunId = firstText(
                request == null ? null : request.getHeader("X-Contexa-Test-Run-Id"),
                request == null ? null : request.getParameter("testRunId"),
                request == null ? null : request.getParameter("perfRun"));
        String path = request == null ? null : request.getRequestURI();
        String method = request == null ? null : request.getMethod();
        String resourceId = resourceIdOf(invocation);
        String actorSessionKey = buildActorSessionKey(userId, contextBindingHash);
        String suppressionKey = buildSuppressionKey(userId, contextBindingHash, resourceId);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zeroTrustMode", zeroTrustMode);
        metadata.put("suppressionReason", firstText(suppressionReason, "UNKNOWN"));
        metadata.put("methodName", invocation.getMethod().getName());
        metadata.put("declaringClass", invocation.getMethod().getDeclaringClass().getName());
        metadata.put("requestPath", path);
        metadata.put("httpMethod", method);
        if (clientRequestId != null) {
            metadata.put("clientRequestId", clientRequestId);
        }
        metadata.putAll(details);

        try {
            Runnable insert = () -> jdbcOperations.update("""
                    INSERT INTO ctxa_ai_security_llm_trigger_suppression (
                        suppression_id,
                        event_id,
                        request_id,
                        correlation_id,
                        test_run_id,
                        user_id,
                        session_id,
                        context_binding_hash,
                        actor_session_key,
                        suppression_key,
                        suppression_reason,
                        trigger_source,
                        trigger_relation,
                        http_method,
                        request_path,
                        resource_id,
                        metadata_json,
                        created_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
                    )
                    """,
                    suppressionId,
                    null,
                    requestId,
                    requestId,
                    testRunId,
                    userId,
                    request == null || request.getSession(false) == null ? null
                            : RequestFactRedaction.sessionReference(request.getSession(false).getId()),
                    contextBindingHash,
                    actorSessionKey,
                    suppressionKey,
                    firstText(suppressionReason, "UNKNOWN"),
                    "PROTECTABLE",
                    "PROTECTABLE_SUPPRESSED",
                    method,
                    path,
                    resourceId,
                    writeJson(metadata));
            if (transactionTemplate != null) {
                transactionTemplate.executeWithoutResult(status -> insert.run());
            } else {
                insert.run();
            }
        } catch (DataAccessException ex) {
            log.warn("[ProtectableLlmSuppressionWriter] Failed to record suppressed protectable LLM trigger: userId={}, resourceId={}, reason={}",
                    userId,
                    resourceId,
                    suppressionReason,
                    ex);
        }
    }

    private static String resourceIdOf(MethodInvocation invocation) {
        return invocation.getMethod().getDeclaringClass().getSimpleName() + "." + invocation.getMethod().getName();
    }

    private HttpServletRequest currentRequest() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs == null ? null : attrs.getRequest();
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private String buildActorSessionKey(String userId, String contextBindingHash) {
        return firstText(userId, "unknown") + ":" + firstText(contextBindingHash, "unknown");
    }

    private String buildSuppressionKey(String userId, String contextBindingHash, String resourceId) {
        return firstText(userId, "unknown") + "|" + firstText(contextBindingHash, "unknown")
                + "|" + firstText(resourceId, "unknown");
    }

    private String writeJson(Object value) {
        if (objectMapper == null || value == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            return null;
        }
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    /** The calls of one method with no user since its last row. */
    private static final class CallsWithoutUser {

        private long waiting;
        private long lastRecordNanos;
        private boolean recorded;
        private boolean firstRecord;

        /** Counts this call; the calls a row now has to record, zero while the interval runs. */
        synchronized long count(long now) {
            waiting++;
            if (recorded && now - lastRecordNanos < WITHOUT_USER_ROW_INTERVAL_NANOS) {
                return 0;
            }
            firstRecord = !recorded;
            recorded = true;
            lastRecordNanos = now;
            long calls = waiting;
            waiting = 0;
            return calls;
        }

        synchronized boolean firstRecord() {
            return firstRecord;
        }
    }
}
