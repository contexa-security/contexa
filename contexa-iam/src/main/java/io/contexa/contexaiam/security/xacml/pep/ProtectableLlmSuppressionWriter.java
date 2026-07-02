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
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

@Slf4j
public class ProtectableLlmSuppressionWriter {

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final ObjectMapper objectMapper;
    private final HcadEvaluationWriter hcadEvaluationWriter;
    private final TransactionTemplate transactionTemplate;

    public ProtectableLlmSuppressionWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper,
            PlatformTransactionManager transactionManager) {
        this(jdbcOperationsSupplier, objectMapper, transactionManager, null);
    }

    public ProtectableLlmSuppressionWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper,
            PlatformTransactionManager transactionManager,
            HcadEvaluationWriter hcadEvaluationWriter) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.objectMapper = objectMapper;
        this.hcadEvaluationWriter = hcadEvaluationWriter;
        this.transactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
        if (this.transactionTemplate != null) {
            this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            this.transactionTemplate.setReadOnly(false);
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

        HttpServletRequest request = currentRequest();
        String suppressionId = UUID.randomUUID().toString();
        String userId = authentication.getName();
        String contextBindingHash = request == null ? null : SessionFingerprintUtil.generateContextBindingHash(request);
        String requestId = firstText(
                request == null ? null : request.getHeader("X-Request-Id"),
                request == null ? null : request.getHeader("X-Correlation-Id"),
                request == null ? null : request.getParameter("requestId"),
                suppressionId);
        String testRunId = firstText(
                request == null ? null : request.getHeader("X-Contexa-Test-Run-Id"),
                request == null ? null : request.getParameter("testRunId"),
                request == null ? null : request.getParameter("perfRun"));
        String path = request == null ? null : request.getRequestURI();
        String method = request == null ? null : request.getMethod();
        String resourceId = invocation.getMethod().getDeclaringClass().getSimpleName()
                + "." + invocation.getMethod().getName();
        String actorSessionKey = buildActorSessionKey(userId, contextBindingHash);
        String suppressionKey = buildSuppressionKey(userId, contextBindingHash, resourceId);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("zeroTrustMode", zeroTrustMode);
        metadata.put("suppressionReason", firstText(suppressionReason, "UNKNOWN"));
        metadata.put("methodName", invocation.getMethod().getName());
        metadata.put("declaringClass", invocation.getMethod().getDeclaringClass().getName());
        metadata.put("requestPath", path);
        metadata.put("httpMethod", method);

        try {
            Runnable insert = () -> jdbcOperations.update("""
                    INSERT INTO ai_security_llm_trigger_suppression (
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
                    request == null || request.getSession(false) == null ? null : request.getSession(false).getId(),
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
        markHcadProtectableObservation(request, path, method);
    }

    private void markHcadProtectableObservation(HttpServletRequest request, String path, String method) {
        if (request == null) {
            return;
        }
        request.setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_OBSERVED, true);
        request.setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_RESOURCE_ID, path);
        request.setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_RESOURCE_URL, path);
        request.setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_HTTP_METHOD, method);
        request.setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_LLM_REUSED, false);
    }

    private String attributeText(HttpServletRequest request, String attributeName) {
        Object value = request == null || attributeName == null ? null : request.getAttribute(attributeName);
        return value == null ? null : String.valueOf(value);
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
}