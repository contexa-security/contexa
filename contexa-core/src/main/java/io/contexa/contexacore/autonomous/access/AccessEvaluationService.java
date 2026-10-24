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
package io.contexa.contexacore.autonomous.access;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * docs/agent B4: Contexa's decision about a request another enforcement point received (OpenID AuthZEN Authorization
 * API 1.0). The evaluation becomes an authorization event built from its own facts alone, never from the enforcement
 * point's call, and is decided as a synchronous {@code @Protectable} is: a restriction in force answers it, else it is
 * analysed in place. Each evaluation is an event of its own (its own event and request IDs), so the evaluations of one
 * batch are not taken for one request.
 */
@Slf4j
public class AccessEvaluationService {

    /** The source of the decision in the event, as other authorization checks name theirs. */
    public static final String AUTHORIZATION_CHECK = "AUTHZEN";

    /** How a batch stops (AuthZEN {@code options.evaluations_semantic}). */
    public enum Semantic {
        EXECUTE_ALL,
        DENY_ON_FIRST_DENY,
        PERMIT_ON_FIRST_PERMIT;

        /** The semantic an AuthZEN request names; {@link #EXECUTE_ALL} for none. */
        public static Semantic of(@Nullable String name) {
            if (name == null || name.isBlank()) {
                return EXECUTE_ALL;
            }
            try {
                return valueOf(name.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unknown evaluations_semantic " + name);
            }
        }
    }

    private final ZeroTrustEventPublisher events;
    private final SynchronousProtectableDecisionService decisions;
    private final SecurityZeroTrustProperties properties;
    private final Clock clock;

    public AccessEvaluationService(ZeroTrustEventPublisher events, SynchronousProtectableDecisionService decisions,
                                   @Nullable SecurityZeroTrustProperties properties, @Nullable Clock clock) {
        this.events = Objects.requireNonNull(events, "events");
        this.decisions = Objects.requireNonNull(decisions, "decisions");
        this.properties = properties != null ? properties : new SecurityZeroTrustProperties();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * Decides one evaluation.
     *
     * @param request          the evaluation
     * @param enforcementPoint the enforcement point asking (its credential's name), recorded with the decision
     * @param clientRequestId  the enforcement point's request identifier, or null
     * @throws IllegalArgumentException when the evaluation lacks a required member or names an unknown subject type
     */
    public AccessEvaluation evaluate(AccessEvaluationRequest request, String enforcementPoint,
                                     @Nullable String clientRequestId) {
        Described described = describe(request, enforcementPoint, clientRequestId);
        boolean enforced = properties.isEnforcementEnabled();
        if (!properties.allowsLlmAnalysis()) {
            return new AccessEvaluation(true, null, null, null, described.eventId(), false, null, null);
        }
        ZeroTrustSpringEvent event = events.buildDescribedAuthorizationEvent(described.userId(),
                described.sessionId(), described.clientIp(), described.userAgent(), described.resource(),
                described.payload(), described.at());
        SynchronousProtectableDecisionService.SyncDecisionResult result = decisions.analyze(event);
        ZeroTrustAction action = result.action() != null ? result.action() : ZeroTrustAction.PENDING_ANALYSIS;
        ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = result.analysisData();
        boolean decision = enforced ? action == ZeroTrustAction.ALLOW : true;
        return new AccessEvaluation(decision, action, analysis != null ? analysis.riskScore() : null,
                analysis != null ? firstText(analysis.reasoningSummary(), analysis.reasoning()) : null,
                analysis != null && analysis.requestId() != null ? analysis.requestId() : described.eventId(),
                enforced, null, null);
    }

    /**
     * Decides a batch in order; an invalid evaluation answers closed with its error and the batch goes on. The batch
     * stops after the first deny or permit when its semantic says so; the answers up to it are returned.
     */
    public List<AccessEvaluation> evaluateAll(List<AccessEvaluationRequest> requests, Semantic semantic,
                                              String enforcementPoint, @Nullable String clientRequestId) {
        List<AccessEvaluation> answers = new ArrayList<>();
        for (AccessEvaluationRequest request : requests) {
            AccessEvaluation answer = evaluateOrError(request, enforcementPoint, clientRequestId);
            answers.add(answer);
            if (semantic == Semantic.DENY_ON_FIRST_DENY && !answer.decision()
                    || semantic == Semantic.PERMIT_ON_FIRST_PERMIT && answer.decision()) {
                break;
            }
        }
        return answers;
    }

    /** One evaluation of a batch: an invalid or failing one answers closed with its error, not failing the batch. */
    public AccessEvaluation evaluateOrError(AccessEvaluationRequest request, String enforcementPoint,
                                            @Nullable String clientRequestId) {
        try {
            return evaluate(request, enforcementPoint, clientRequestId);
        } catch (IllegalArgumentException e) {
            return AccessEvaluation.invalid(400, e.getMessage());
        } catch (RuntimeException e) {
            log.error("An access evaluation failed: enforcementPoint={}", enforcementPoint, e);
            return AccessEvaluation.invalid(500, "The evaluation could not be made");
        }
    }

    /** The event's facts from the evaluation alone. */
    Described describe(AccessEvaluationRequest request, String enforcementPoint, @Nullable String clientRequestId) {
        if (request == null || request.subject() == null || request.action() == null || request.resource() == null) {
            throw new IllegalArgumentException("subject, action and resource are required");
        }
        AccessEvaluationRequest.Subject subject = request.subject();
        String type = required(subject.type(), "subject.type").toLowerCase(Locale.ROOT);
        String id = required(subject.id(), "subject.id");
        String actionName = required(request.action().name(), "action.name");
        String resourceType = required(request.resource().type(), "resource.type");
        String resourceId = required(request.resource().id(), "resource.id");
        Map<String, Object> context = request.context();
        Map<String, Object> facts = subject.properties();

        String eventId = UUID.randomUUID().toString();
        Map<String, Object> payload = new HashMap<>();
        payload.put("eventId", eventId);
        payload.put("requestId", eventId);
        payload.put("correlationId", eventId);
        put(payload, "clientRequestId", clientRequestId);
        payload.put("authorizationCheck", AUTHORIZATION_CHECK);
        put(payload, "authzenEnforcementPoint", enforcementPoint);
        payload.put("authzenAction", actionName);
        payload.put("resourceId", resourceId);
        payload.put("resourceType", resourceType);
        put(payload, "decisionBoundaryMode", properties.getMode() != null ? properties.getMode().name() : null);

        String userId;
        switch (type) {
            case "user" -> userId = id;
            case "agent" -> {
                payload.put("agentId", id);
                String delegator = AccessEvaluationRequest.text(facts, "delegator_id");
                if (delegator != null) {
                    userId = delegator;
                    payload.put("delegated", true);
                    payload.put("delegatorId", delegator);
                    put(payload, "delegationId", AccessEvaluationRequest.text(facts, "delegation_id"));
                } else {
                    String client = AccessEvaluationRequest.text(facts, "client_id");
                    userId = client != null ? client : id;
                }
            }
            case "service" -> {
                userId = id;
                payload.put("serviceClientPrincipal", true);
            }
            default -> throw new IllegalArgumentException("Unknown subject.type " + subject.type()
                    + "; one of user, agent, service");
        }
        put(payload, "tenantId", firstText(AccessEvaluationRequest.text(facts, "tenant_id"),
                AccessEvaluationRequest.text(context, "tenant_id")));
        put(payload, "clientId", AccessEvaluationRequest.text(facts, "client_id"));

        String clientIp = AccessEvaluationRequest.text(context, "client_ip");
        String userAgent = AccessEvaluationRequest.text(context, "user_agent");
        String sessionId = AccessEvaluationRequest.text(context, "session_id");
        put(payload, "clientIp", clientIp);
        put(payload, "userAgent", userAgent);
        put(payload, "contextBindingHash", SessionFingerprintUtil.generateContextBindingHash(sessionId, clientIp,
                userAgent));
        Map<String, Object> httpRequest = context.get("request") instanceof Map<?, ?> map ? stringKeys(map) : Map.of();
        String method = AccessEvaluationRequest.text(httpRequest, "method");
        String path = AccessEvaluationRequest.text(httpRequest, "path");
        put(payload, "httpMethod", method != null ? method.toUpperCase(Locale.ROOT) : null);
        if (path != null) {
            payload.put("requestPath", path);
            payload.put("requestUri", path);
            payload.put("httpUri", path);
        }
        String resource = path != null ? path : resourceType + "/" + resourceId;
        return new Described(eventId, userId, sessionId, clientIp, userAgent, resource, payload,
                time(AccessEvaluationRequest.text(context, "time")));
    }

    private Instant time(@Nullable String value) {
        if (value == null) {
            return clock.instant();
        }
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException e) {
            try {
                return Instant.parse(value);
            } catch (DateTimeParseException ignored) {
                throw new IllegalArgumentException("context.time is not an RFC 3339 date-time: " + value);
            }
        }
    }

    private static Map<String, Object> stringKeys(Map<?, ?> map) {
        Map<String, Object> values = new HashMap<>();
        map.forEach((key, value) -> {
            if (key != null && value != null) {
                values.put(key.toString(), value);
            }
        });
        return values;
    }

    private static String required(@Nullable String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value.trim();
    }

    private static void put(Map<String, Object> payload, String key, @Nullable Object value) {
        if (value != null) {
            payload.put(key, value);
        }
    }

    @Nullable
    private static String firstText(@Nullable String first, @Nullable String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        return second != null && !second.isBlank() ? second : null;
    }

    /** The event an evaluation becomes. */
    record Described(String eventId, String userId, @Nullable String sessionId, @Nullable String clientIp,
                     @Nullable String userAgent, String resource, Map<String, Object> payload, Instant at) {
    }
}
