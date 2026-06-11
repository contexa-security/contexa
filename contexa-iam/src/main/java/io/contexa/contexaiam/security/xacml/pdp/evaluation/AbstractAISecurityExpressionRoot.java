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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

import java.util.Arrays;

@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;
    protected final ZeroTrustActionRepository actionRedisRepository;

    protected AbstractAISecurityExpressionRoot(Authentication authentication,
                                               AuthorizationContext authorizationContext,
                                               AuditLogRepository auditLogRepository,
                                               ZeroTrustActionRepository actionRedisRepository) {
        super(authentication);
        this.authorizationContext = authorizationContext;
        this.auditLogRepository = auditLogRepository;
        this.actionRedisRepository = actionRedisRepository;
    }

    protected String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return authentication.getName();
    }

    protected ZeroTrustAction getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
        return actionRedisRepository.getCurrentAction(userId);
    }

    public boolean isAllowed() {
        return getCurrentAction() == ZeroTrustAction.ALLOW;
    }

    public boolean isBlocked() {
        return getCurrentAction() == ZeroTrustAction.BLOCK;
    }

    public boolean needsChallenge() {
        return getCurrentAction() == ZeroTrustAction.CHALLENGE;
    }

    public boolean needsEscalation() {
        return getCurrentAction() == ZeroTrustAction.ESCALATE;
    }

    public boolean isPendingAnalysis() {
        return getCurrentAction() == ZeroTrustAction.PENDING_ANALYSIS;
    }

    public boolean hasAction(String expectedAction) {
        return ZeroTrustAction.fromString(expectedAction) == getCurrentAction();
    }

    public boolean hasActionIn(String... allowedActions) {
        ZeroTrustAction action = getCurrentAction();
        return Arrays.stream(allowedActions)
                .anyMatch(a -> ZeroTrustAction.fromString(a) == action);
    }

    public boolean hasActionOrDefault(String defaultAction, String... allowedActions) {
        ZeroTrustAction action = getCurrentAction();
        if (action == ZeroTrustAction.PENDING_ANALYSIS) {
            action = ZeroTrustAction.fromString(defaultAction);
        }

        final ZeroTrustAction finalAction = action;
        return Arrays.stream(allowedActions)
                .anyMatch(a -> ZeroTrustAction.fromString(a) == finalAction);
    }
}