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
package io.contexa.contexaiam.access.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.access.AccessEvaluation;
import io.contexa.contexacore.autonomous.access.AccessEvaluationRequest;
import io.contexa.contexacore.autonomous.access.AccessEvaluationService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * docs/agent B4: the OpenID AuthZEN Authorization API 1.0 evaluation endpoints and metadata. An enforcement point (an
 * API gateway, an MCP server) authenticated with the configured authority asks Contexa's decision about a request it
 * received; {@code decision} is true only for an enforced ALLOW (or while Contexa does not enforce), and {@code context}
 * carries Contexa's decision, risk and reasoning. The search APIs are not offered.
 */
@Slf4j
@RestController
public class AccessEvaluationController {

    /** The AuthZEN request identifier header, answered with the same value. */
    public static final String REQUEST_ID_HEADER = "X-Request-ID";
    static final String EVALUATION = "/access/v1/evaluation";
    static final String EVALUATIONS = "/access/v1/evaluations";
    static final String METADATA = "/.well-known/authzen-configuration";

    private final AccessEvaluationService evaluations;
    private final SecurityZeroTrustProperties.Authzen settings;

    public AccessEvaluationController(AccessEvaluationService evaluations,
                                      @Nullable SecurityZeroTrustProperties.Authzen settings) {
        this.evaluations = Objects.requireNonNull(evaluations, "evaluations");
        this.settings = settings != null ? settings : new SecurityZeroTrustProperties.Authzen();
    }

    @PostMapping(path = "${contexa.security.zerotrust.authzen.base-path:/contexa/authzen}" + EVALUATION,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> evaluate(@RequestBody(required = false) Map<String, Object> body,
                                           @Nullable Authentication authentication,
                                           @RequestHeader(value = REQUEST_ID_HEADER, required = false) String requestId) {
        ResponseEntity<Object> refused = refused(authentication, requestId);
        if (refused != null) {
            return refused;
        }
        try {
            AccessEvaluation answer = evaluations.evaluate(request(body, Map.of()), authentication.getName(),
                    requestId);
            return answer(HttpStatus.OK, view(answer), requestId);
        } catch (IllegalArgumentException e) {
            return answer(HttpStatus.BAD_REQUEST, e.getMessage(), requestId);
        } catch (RuntimeException e) {
            log.error("An access evaluation failed: enforcementPoint={}", authentication.getName(), e);
            return answer(HttpStatus.INTERNAL_SERVER_ERROR, "The evaluation could not be made", requestId);
        }
    }

    @PostMapping(path = "${contexa.security.zerotrust.authzen.base-path:/contexa/authzen}" + EVALUATIONS,
            consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> evaluateAll(@RequestBody(required = false) Map<String, Object> body,
                                              @Nullable Authentication authentication,
                                              @RequestHeader(value = REQUEST_ID_HEADER, required = false)
                                              String requestId) {
        ResponseEntity<Object> refused = refused(authentication, requestId);
        if (refused != null) {
            return refused;
        }
        Map<String, Object> defaults = body != null ? body : Map.of();
        List<Map<String, Object>> items = maps(defaults.get("evaluations"));
        if (items == null) {
            // Without an evaluations array the request is a single evaluation (AuthZEN 7.1).
            return evaluate(body, authentication, requestId);
        }
        if (items.size() > Math.max(1, settings.getMaxEvaluations())) {
            return answer(HttpStatus.BAD_REQUEST, "At most " + settings.getMaxEvaluations()
                    + " evaluations are taken in one request", requestId);
        }
        AccessEvaluationService.Semantic semantic;
        try {
            Map<String, Object> options = map(defaults.get("options"));
            semantic = AccessEvaluationService.Semantic.of(options != null && options.get("evaluations_semantic")
                    != null ? options.get("evaluations_semantic").toString() : null);
        } catch (IllegalArgumentException e) {
            return answer(HttpStatus.BAD_REQUEST, e.getMessage(), requestId);
        }
        List<AccessEvaluationRequest> requests = new ArrayList<>();
        List<AccessEvaluation> invalid = new ArrayList<>();
        for (Map<String, Object> item : items) {
            try {
                requests.add(request(item, defaults));
                invalid.add(null);
            } catch (IllegalArgumentException e) {
                requests.add(null);
                invalid.add(AccessEvaluation.invalid(400, e.getMessage()));
            }
        }
        List<Map<String, Object>> views = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            AccessEvaluation answer = invalid.get(i) != null ? invalid.get(i)
                    : evaluations.evaluateOrError(requests.get(i), authentication.getName(), requestId);
            views.add(view(answer));
            if (semantic == AccessEvaluationService.Semantic.DENY_ON_FIRST_DENY && !answer.decision()
                    || semantic == AccessEvaluationService.Semantic.PERMIT_ON_FIRST_PERMIT && answer.decision()) {
                break;
            }
        }
        return answer(HttpStatus.OK, Map.of("evaluations", views), requestId);
    }

    /** The decision point's metadata (AuthZEN 9): its identifier and the evaluation endpoints it offers. */
    @GetMapping(path = METADATA, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> metadata(HttpServletRequest request) {
        String base = ServletUriComponentsBuilder.fromContextPath(request).build().toUriString();
        String pdp = settings.getPolicyDecisionPoint() != null && !settings.getPolicyDecisionPoint().isBlank()
                ? settings.getPolicyDecisionPoint().trim() : base;
        String endpoints = base + settings.getBasePath();
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("policy_decision_point", pdp);
        metadata.put("access_evaluation_endpoint", endpoints + EVALUATION);
        metadata.put("access_evaluations_endpoint", endpoints + EVALUATIONS);
        return metadata;
    }

    /** 401 without an authenticated caller, 403 without the configured authority; null for an enforcement point. */
    @Nullable
    private ResponseEntity<Object> refused(@Nullable Authentication authentication, @Nullable String requestId) {
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return answer(HttpStatus.UNAUTHORIZED, "An authenticated enforcement point is required", requestId);
        }
        String required = settings.getRequiredAuthority();
        boolean holds = required == null || required.isBlank() || authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).anyMatch(required.trim()::equals);
        return holds ? null : answer(HttpStatus.FORBIDDEN, "The caller is not an enforcement point of this decision "
                + "point", requestId);
    }

    /** The evaluation an AuthZEN object states, its missing members taken from the defaults (a batch's top level). */
    static AccessEvaluationRequest request(@Nullable Map<String, Object> body, Map<String, Object> defaults) {
        Map<String, Object> values = body != null ? body : Map.of();
        Map<String, Object> subject = member(values, defaults, "subject");
        Map<String, Object> action = member(values, defaults, "action");
        Map<String, Object> resource = member(values, defaults, "resource");
        Map<String, Object> context = member(values, defaults, "context");
        if (subject == null || action == null || resource == null) {
            throw new IllegalArgumentException("subject, action and resource are required");
        }
        return new AccessEvaluationRequest(
                new AccessEvaluationRequest.Subject(text(subject.get("type")), text(subject.get("id")),
                        map(subject.get("properties"))),
                new AccessEvaluationRequest.Action(text(action.get("name")), map(action.get("properties"))),
                new AccessEvaluationRequest.Resource(text(resource.get("type")), text(resource.get("id")),
                        map(resource.get("properties"))),
                context);
    }

    /** The AuthZEN answer of one evaluation (AuthZEN 6.2): the decision and Contexa's context. */
    static Map<String, Object> view(AccessEvaluation answer) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("decision", answer.decision());
        Map<String, Object> context = new LinkedHashMap<>();
        if (answer.failed()) {
            context.put("error", Map.of("status", answer.errorStatus(), "message", answer.errorMessage()));
        } else {
            Map<String, Object> contexa = new LinkedHashMap<>();
            contexa.put("action", answer.action() != null ? answer.action().name() : null);
            contexa.put("risk_score", answer.riskScore());
            contexa.put("request_id", answer.requestId());
            contexa.put("enforced", answer.enforced());
            context.put("contexa", contexa);
            ZeroTrustAction action = answer.action();
            if (action != null && action != ZeroTrustAction.ALLOW) {
                String status = String.valueOf(action.getHttpStatus());
                if (answer.reason() != null) {
                    context.put("reason_admin", Map.of(status, answer.reason()));
                }
                context.put("reason_user", Map.of(status, userReason(action)));
            }
        }
        view.put("context", context);
        return view;
    }

    /** A plain sentence for the person whose request it is; the analysis itself stays with the administrator. */
    private static String userReason(ZeroTrustAction action) {
        return switch (action) {
            case CHALLENGE -> "Additional verification is required to continue.";
            case BLOCK -> "This request was stopped by a security decision.";
            case ESCALATE -> "This request is held for a security review.";
            default -> "This request could not be decided now; try again later.";
        };
    }

    private static ResponseEntity<Object> answer(HttpStatus status, Object body, @Nullable String requestId) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
        if (requestId != null && !requestId.isBlank()) {
            builder.header(REQUEST_ID_HEADER, requestId);
        }
        if (body instanceof String text) {
            return builder.header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE).body(text);
        }
        return builder.contentType(MediaType.APPLICATION_JSON).body(body);
    }

    @Nullable
    private static Map<String, Object> member(Map<String, Object> values, Map<String, Object> defaults, String name) {
        Map<String, Object> own = map(values.get(name));
        return own != null ? own : map(defaults.get(name));
    }

    @Nullable
    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(@Nullable Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, Object> values = new LinkedHashMap<>();
        map.forEach((key, item) -> {
            if (key != null) {
                values.put(key.toString(), item);
            }
        });
        return values;
    }

    @Nullable
    private static List<Map<String, Object>> maps(@Nullable Object value) {
        if (!(value instanceof List<?> list)) {
            return null;
        }
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object item : list) {
            Map<String, Object> map = map(item);
            items.add(map != null ? map : Map.of());
        }
        return items;
    }

    @Nullable
    private static String text(@Nullable Object value) {
        return value != null ? value.toString() : null;
    }
}
