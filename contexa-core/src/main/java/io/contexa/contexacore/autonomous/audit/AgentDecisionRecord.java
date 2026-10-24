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
package io.contexa.contexacore.autonomous.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.event.support.InvocationArguments;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * The decision record of a request as AG-8 (IETF AIMS audit fields) names it (docs/agent A5-5): who the request acted
 * as and for, the operation it asked for, the risk facts the decision cited, what was enforced and why, and the hash of
 * the request's context (AG-11l). Every decision gets the record; the agent and delegation fields are empty for a
 * person's request.
 *
 * @param subjectKind        the subject kind the publisher recorded (A1-3)
 * @param agentId            the agent of an agent's request
 * @param delegatorId        the person a delegated agent acted for
 * @param delegationId       the delegation the request ran under, when known
 * @param targetAction       the operation the request asked for (its action family)
 * @param riskState          the risk facts the decision cited: its reason codes with their fact IDs
 * @param enforcementAction  what was enforced
 * @param enforcementCause   why it was enforced so
 * @param requestContextHash the SHA-256 of the request's context
 */
public record AgentDecisionRecord(@Nullable String subjectKind, @Nullable String agentId, @Nullable String delegatorId,
                                  @Nullable String delegationId, @Nullable String targetAction,
                                  @Nullable String riskState, @Nullable String enforcementAction,
                                  @Nullable String enforcementCause, String requestContextHash) {

    /** The event metadata the enforcement writes what it did to the decision under (A5-5). */
    public static final String ENFORCEMENT_OUTCOME = "enforcementOutcome";
    /** The enforcement applied the decision. */
    public static final String APPLIED = "APPLIED";
    /** A stricter action in force stayed, so the decision was not written (W5-3). */
    public static final String KEPT_STRICTER = "KEPT_STRICTER";
    /** The decision was observed inside a shadow boundary without runtime effect. */
    public static final String OBSERVED_ONLY = "OBSERVED_ONLY";
    /** The decision's processing ownership lapsed and the result was discarded. */
    public static final String DISCARDED = "DISCARDED";

    /** The event metadata the steps that stopped an agent are written under (A5-3). */
    public static final String CONTAINMENT = "agentContainment";

    /** The version of the request context the hashes are computed over. */
    static final String CONTEXT_VERSION = "ctxa.request-context.v1";

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The record of the decided request. */
    public static AgentDecisionRecord of(SecurityEvent event, @Nullable ProcessingResult result) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        String kind = text(metadata.get("executionSubjectKind"));
        LearningSubject subject = LearningSubject.of(event);
        boolean agent = subject != null && subject.agent();
        boolean delegated = SubjectKind.DELEGATED_AGENT.name().equals(kind);
        return new AgentDecisionRecord(
                kind,
                agent ? subject.agentId() : null,
                delegated ? nullIfEmpty(firstText(metadata.get("delegatorId"), event.getUserId())) : null,
                agent ? subject.delegationId() : null,
                targetAction(metadata),
                riskState(result),
                enforcementAction(metadata, result),
                enforcementCause(result),
                requestContextHash(event));
    }

    /**
     * The SHA-256 (hex) of the request's context (AG-11l): its time, tenant, user, agent and delegation, the operation,
     * the method, path and target, the requested size and the call's argument summary, in that order. A time-free
     * {@link #requestContentHash} lets a request sent again after a confirmation be matched to the one confirmed.
     */
    public static String requestContextHash(SecurityEvent event) {
        List<String> parts = new ArrayList<>();
        parts.add(CONTEXT_VERSION);
        parts.add(event.getTimestamp() != null ? event.getTimestamp().toString() : "");
        parts.addAll(content(event));
        return sha256(parts);
    }

    /** The SHA-256 (hex) of the request's context without its time: the same request sent again hashes the same. */
    public static String requestContentHash(SecurityEvent event) {
        List<String> parts = new ArrayList<>();
        parts.add(CONTEXT_VERSION + ".content");
        parts.addAll(content(event));
        return sha256(parts);
    }

    private static List<String> content(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        LearningSubject subject = LearningSubject.of(event);
        return Arrays.asList(
                firstText(metadata.get("tenantId"), metadata.get("tenant_id")),
                text(event.getUserId()),
                subject != null && subject.agent() ? subject.agentId() : "",
                subject != null && subject.agent() && subject.delegationId() != null ? subject.delegationId() : "",
                targetAction(metadata),
                firstText(metadata.get("httpMethod"), metadata.get("method")),
                firstText(metadata.get("requestPath"), metadata.get("requestUri")),
                firstText(metadata.get("resourceId"), metadata.get("targetResource")),
                firstText(metadata.get("requestItems")),
                firstText(metadata.get(InvocationArguments.KEY)));
    }

    private static String targetAction(Map<String, Object> metadata) {
        ActionFamily family = ActionFamilyResolver.resolve(metadata).family();
        return family != null && family != ActionFamily.UNKNOWN ? family.name() : "";
    }

    @Nullable
    private static String riskState(@Nullable ProcessingResult result) {
        if (result == null) {
            return null;
        }
        List<SecurityDecisionOutputContract.Citation> codes = result.getReasonCodes();
        if (codes != null && !codes.isEmpty()) {
            List<String> cited = new ArrayList<>();
            for (SecurityDecisionOutputContract.Citation code : codes) {
                if (code != null && StringUtils.hasText(code.code())) {
                    cited.add(StringUtils.hasText(code.fact()) ? code.code() + "(" + code.fact() + ")" : code.code());
                }
            }
            if (!cited.isEmpty()) {
                return String.join(", ", cited);
            }
        }
        List<String> indicators = result.getThreatIndicators();
        return indicators != null && !indicators.isEmpty() ? String.join(", ", indicators) : null;
    }

    @Nullable
    private static String enforcementAction(Map<String, Object> metadata, @Nullable ProcessingResult result) {
        String outcome = text(metadata.get(ENFORCEMENT_OUTCOME));
        String decided = result != null && StringUtils.hasText(result.getAction()) ? result.getAction().trim() : null;
        if (outcome == null) {
            return null;
        }
        String enforced = APPLIED.equals(outcome) && decided != null ? decided : outcome;
        // docs/agent A5-3: what stopped the agent after its BLOCK.
        String containment = text(metadata.get(CONTAINMENT));
        return containment != null ? enforced + "; " + containment : enforced;
    }

    @Nullable
    private static String enforcementCause(@Nullable ProcessingResult result) {
        if (result == null) {
            return null;
        }
        if (Boolean.TRUE.equals(result.getTechnicalFallbackApplied())) {
            return "TECHNICAL_FALLBACK" + suffix(firstText(result.getTechnicalFallbackReason(),
                    result.getTechnicalFallbackCategory()));
        }
        if (Boolean.TRUE.equals(result.getResponseActionFallbackApplied())) {
            return "RESPONSE_ACTION_FALLBACK" + suffix(firstText(result.getResponseActionFallbackReason(),
                    result.getResponseActionFallbackCategory()));
        }
        if (Boolean.TRUE.equals(result.getAutonomyConstraintApplied())) {
            return "AUTONOMY_CONSTRAINT" + suffix(text(result.getAutonomyConstraintSummary()));
        }
        return Boolean.FALSE.equals(result.getLlmDecisionPresent()) ? null : "MODEL_DECISION";
    }

    private static String suffix(@Nullable String detail) {
        return StringUtils.hasText(detail) ? ": " + detail : "";
    }

    @Nullable
    private static String nullIfEmpty(String value) {
        return StringUtils.hasText(value) ? value : null;
    }

    private static String sha256(List<String> parts) {
        try {
            byte[] canonical = JSON.writeValueAsString(parts).getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("The request context could not be hashed", e);
        }
    }

    private static String firstText(Object... values) {
        for (Object value : values) {
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return "";
    }

    @Nullable
    private static String text(@Nullable Object value) {
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }
}
