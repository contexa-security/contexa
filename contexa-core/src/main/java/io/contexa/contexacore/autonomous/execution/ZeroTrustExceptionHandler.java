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
package io.contexa.contexacore.autonomous.execution;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ZeroTrustScreens;
import io.contexa.contexacore.autonomous.blocking.BlockableResponseWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.net.URI;
import java.time.Instant;

/**
 * Answers the zero-trust decisions made at a protected method. It goes before every other advice: it handles Contexa's
 * own exceptions only, and an application's advice for {@code AccessDeniedException} (a subtype) would otherwise turn
 * every decision into the application's own 403 (finding F-7, ownership harness 2026-11-03). A browser is sent to the
 * screen of the decision, as the request filters send it; an API client gets the status and the JSON body.
 * <p>
 * An order cannot go ahead of an application's advice of the same order or of a handler inside a controller, so these
 * answers are given through {@link ZeroTrustEnforcementExceptionResolver} wherever Spring MVC dispatches.
 */
@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class ZeroTrustExceptionHandler implements Ordered {

    private final ZeroTrustChallengeFlowStarter challengeFlowStarter;

    public ZeroTrustExceptionHandler() {
        this(null);
    }

    /**
     * @param challengeFlowStarter starts the step-up flow when a synchronous decision answers CHALLENGE; may be null,
     *                             and then the flow starts on the user's next request
     */
    public ZeroTrustExceptionHandler(ZeroTrustChallengeFlowStarter challengeFlowStarter) {
        this.challengeFlowStarter = challengeFlowStarter;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @ExceptionHandler(ZeroTrustAccessDeniedException.class)
    public ResponseEntity<ZeroTrustErrorResponse> handleZeroTrustDenied(
            ZeroTrustAccessDeniedException ex, HttpServletRequest request, HttpServletResponse servletResponse) {
        // R-12: this deny response answers the decision itself and carries no protected data; a BLOCK must not cut it.
        BlockableResponseWrapper.permitOwnDenyResponse(servletResponse);

        // O-2: a denial is the decision working as meant, not a failure.
        log.warn("Zero Trust access denied - action: {}, resource: {}, risk: {}, reason: {}",
            ex.getAction(), ex.getResourceId(), ex.getRiskScore(), ex.getReason());

        if (answeredForAgent(ex, request, servletResponse)) {
            return null;
        }
        if (ex.getBusyRetryAfterSeconds() > 0) {
            // RL-12: refused because the engine had no place or time to analyse the request; try again later.
            servletResponse.setHeader("Retry-After", Integer.toString(ex.getBusyRetryAfterSeconds()));
        }

        String mfaUrl = startChallengeFlow(ex, request, servletResponse);
        String screen = screenFor(ex, mfaUrl, request);
        if (screen != null) {
            return ResponseEntity.status(302).location(URI.create(screen)).build();
        }

        ZeroTrustErrorResponse response = ZeroTrustErrorResponse.builder()
            .status(ex.getHttpStatus())
            .code(ex.getErrorCode())
            .message(ex.getReason())
            .action(ex.getAction())
            .resourceId(ex.getResourceId())
            .riskScore(ex.getRiskScore())
            .analysisTimeout(ex.isAnalysisTimeout())
            .timestamp(Instant.now())
            .mfaUrl(mfaUrl)
            .build();

        return ResponseEntity
            .status(response.getStatus())
            .body(response);
    }

    @ExceptionHandler(AnomalyDetectedException.class)
    public ResponseEntity<ZeroTrustErrorResponse> handleAnomalyDetected(
            AnomalyDetectedException ex, HttpServletResponse servletResponse) {
        BlockableResponseWrapper.permitOwnDenyResponse(servletResponse);

        log.warn("Anomaly detection access denied - message: {}", ex.getMessage());

        ZeroTrustErrorResponse response = ZeroTrustErrorResponse.builder()
            .status(403)
            .code("ZERO_TRUST_ANOMALY_DETECTED")
            .message(ex.getMessage())
            .action(ZeroTrustAction.BLOCK.name())
            .resourceId("unknown")
            .riskScore(null)
            .analysisTimeout(false)
            .timestamp(Instant.now())
            .build();

        return ResponseEntity
            .status(403)
            .body(response);
    }


    @ExceptionHandler(RapidProtectableReentryDeniedException.class)
    public ResponseEntity<ZeroTrustErrorResponse> handleRapidProtectableReentryDenied(
            RapidProtectableReentryDeniedException ex, HttpServletResponse servletResponse) {
        BlockableResponseWrapper.permitOwnDenyResponse(servletResponse);

        log.warn("Rapid protectable re-entry denied - resource: {}, windowSeconds: {}",
            ex.getResourceId(), ex.getWindowSeconds());

        ZeroTrustErrorResponse response = ZeroTrustErrorResponse.builder()
            .status(ex.getHttpStatus())
            .code(ex.getErrorCode())
            .message(ex.getMessage())
            .action(ZeroTrustAction.CHALLENGE.name())
            .resourceId(ex.getResourceId())
            .riskScore(null)
            .analysisTimeout(false)
            .timestamp(Instant.now())
            .build();

        return ResponseEntity
            .status(response.getStatus())
            .body(response);
    }
    /**
     * The screen a browser goes to for a BLOCK, a CHALLENGE (when its step-up started) or an ESCALATE, or null for an
     * API client and for the other answers (busy, timeout, analysis required), which keep the status and the body.
     */
    private static String screenFor(ZeroTrustAccessDeniedException ex, String mfaUrl, HttpServletRequest request) {
        if (request == null || !ZeroTrustScreens.isBrowserNavigation(request) || ex.getBusyRetryAfterSeconds() > 0) {
            return null;
        }
        if (ZeroTrustAction.BLOCK.name().equals(ex.getAction())) {
            return ZeroTrustScreens.blocked(request);
        }
        if (ZeroTrustAction.CHALLENGE.name().equals(ex.getAction()) && mfaUrl != null) {
            return ZeroTrustScreens.challengeRequired(request, mfaUrl);
        }
        if (ZeroTrustAction.ESCALATE.name().equals(ex.getAction())) {
            return ZeroTrustScreens.analysisPending(request);
        }
        return null;
    }

    /**
     * docs/agent A5-2: an agent's request a CHALLENGE decided in the request stopped asks its accountable person to
     * confirm it; the answer is written there, so this handler writes none (a null entity leaves it as it is).
     */
    private boolean answeredForAgent(ZeroTrustAccessDeniedException ex, HttpServletRequest request,
                                     HttpServletResponse servletResponse) {
        if (challengeFlowStarter == null || !ZeroTrustAction.CHALLENGE.name().equals(ex.getAction())) {
            return false;
        }
        try {
            return challengeFlowStarter.answerAgentChallenge(request, servletResponse);
        } catch (RuntimeException e) {
            log.error("Could not ask the agent's accountable person to confirm a request: resource={}",
                ex.getResourceId(), e);
            return false;
        }
    }

    /**
     * A CHALLENGE decided in the request starts the step-up flow here, as the request filters do for an earlier
     * CHALLENGE, so the user can step up at once; the answer then says where to continue it.
     */
    private String startChallengeFlow(ZeroTrustAccessDeniedException ex, HttpServletRequest request,
                                      HttpServletResponse servletResponse) {
        if (challengeFlowStarter == null || !ZeroTrustAction.CHALLENGE.name().equals(ex.getAction())) {
            return null;
        }
        try {
            return challengeFlowStarter.start(request, servletResponse).orElse(null);
        } catch (RuntimeException e) {
            log.error("Could not start the step-up flow for a CHALLENGE decided in the request: resource={}",
                ex.getResourceId(), e);
            return null;
        }
    }

    @Builder
    @Getter
    public static class ZeroTrustErrorResponse {

        private final int status;

        private final String code;

        private final String message;

        private final String action;

        private final String resourceId;

        private final Double riskScore;

        private final boolean analysisTimeout;

        private final Instant timestamp;

        /** Where the user continues the step-up of a CHALLENGE decided in the request; absent otherwise. */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        private final String mfaUrl;
    }
}
