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

import java.util.Locale;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.springframework.security.authorization.AuthorizationDeniedException;

public class ZeroTrustAccessDeniedException extends AuthorizationDeniedException {

    private static final long serialVersionUID = 1L;

    private final ZeroTrustAction action;

    private final String resourceId;

    private final Double riskScore;

    private final String reason;

    private final boolean analysisTimeout;

    /** RL-12: the engine could not take the request in; it is refused, not passed. Zero when the exception is no such answer. */
    private final int busyRetryAfterSeconds;

    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          Double riskScore, String reason) {
        super(formatMessage(action, reason));
        this.action = ZeroTrustAction.fromString(action);
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = false;
        this.busyRetryAfterSeconds = 0;
    }

    private ZeroTrustAccessDeniedException(String resourceId, int retryAfterSeconds) {
        super(formatMessage(ZeroTrustAction.PENDING_ANALYSIS.name(),
                "The security analysis is busy for this agent; retry after " + retryAfterSeconds + " seconds"));
        this.action = ZeroTrustAction.PENDING_ANALYSIS;
        this.resourceId = resourceId;
        this.riskScore = null;
        this.reason = "The security analysis is busy for this agent; retry after " + retryAfterSeconds + " seconds";
        this.analysisTimeout = false;
        this.busyRetryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          Double riskScore, String reason,
                                          boolean analysisTimeout) {
        super(formatMessage(action, reason));
        this.action = ZeroTrustAction.fromString(action);
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = analysisTimeout;
        this.busyRetryAfterSeconds = 0;
    }

    /**
     * RL-12: an agent's request the engine had no place or time to analyse (the agent already has its limit of analyses
     * running, the queue is full, or the wait ran out). The request is refused with HTTP 429 and a {@code Retry-After}.
     * It is never let through for lack of an answer.
     */
    public static ZeroTrustAccessDeniedException analysisBusy(String resourceId, int retryAfterSeconds) {
        return new ZeroTrustAccessDeniedException(resourceId, retryAfterSeconds);
    }

    public static ZeroTrustAccessDeniedException analysisTimeout(String resourceId, long timeoutMs) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.PENDING_ANALYSIS.name(),
            resourceId,
            null,
            String.format(Locale.ROOT, "Security analysis timeout after %dms", timeoutMs),
            true
        );
    }

    public static ZeroTrustAccessDeniedException analysisRequired(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.PENDING_ANALYSIS.name(),
            resourceId,
            null,
            "Security analysis required but not completed"
        );
    }

    public static ZeroTrustAccessDeniedException blocked(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.BLOCK.name(),
            resourceId,
            null,
            "Access blocked by AI security analysis"
        );
    }

    public static ZeroTrustAccessDeniedException challengeRequired(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.CHALLENGE.name(),
            resourceId,
            null,
            "Additional authentication required"
        );
    }

    public static ZeroTrustAccessDeniedException pendingReview(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            ZeroTrustAction.ESCALATE.name(),
            resourceId,
            null,
            "Access pending security review"
        );
    }

    private static String formatMessage(String action, String reason) {
        return String.format("Zero Trust: %s - %s", action, reason);
    }

    public int getHttpStatus() {
        if (action == null) {
            return 403;
        }
        if (busyRetryAfterSeconds > 0) {
            return 429;
        }
        if (action == ZeroTrustAction.PENDING_ANALYSIS && analysisTimeout) {
            return 408;
        }
        return action.getHttpStatus();
    }

    public String getErrorCode() {
        if (busyRetryAfterSeconds > 0) {
            return "ZERO_TRUST_ANALYSIS_BUSY";
        }
        return "ZERO_TRUST_" + (action != null ? action.name() : "UNKNOWN");
    }

    /** The seconds after which the refused request may be sent again; zero when this is not a busy answer. */
    public int getBusyRetryAfterSeconds() {
        return busyRetryAfterSeconds;
    }

    public String getAction() {
        return action != null ? action.name() : null;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Double getRiskScore() {
        return riskScore;
    }

    public String getReason() {
        return reason;
    }

    public boolean isAnalysisTimeout() {
        return analysisTimeout;
    }
}
