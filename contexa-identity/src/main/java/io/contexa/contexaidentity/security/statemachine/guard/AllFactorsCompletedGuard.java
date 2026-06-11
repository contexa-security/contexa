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
package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class AllFactorsCompletedGuard extends AbstractMfaStateGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    public AllFactorsCompletedGuard(MfaPolicyProvider mfaPolicyProvider) {
        this.mfaPolicyProvider = mfaPolicyProvider;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {

        if (factorContext == null) {
            log.error("[AllFactorsCompletedGuard] FactorContext is NULL! Cannot evaluate. Returning false.");
            return false;
        }

        String sessionId = factorContext.getMfaSessionId();

        try {

            int completedCount = factorContext.getCompletedFactors() != null ?
                    factorContext.getCompletedFactors().size() : 0;

            long requiredCount = getRequiredFactorCount(factorContext);

            if (requiredCount <= 0) {
                log.error("[AllFactorsCompletedGuard] Invalid required factor count ({}) for session: {}. Defaulting to 1.",
                        requiredCount, sessionId);
                requiredCount = 1;
            }

            return completedCount >= requiredCount;

        } catch (Exception e) {
            log.error("[AllFactorsCompletedGuard] Exception during guard evaluation for session: {}. Returning false to complete Reactive Stream.",
                    sessionId, e);
            return false;
        }
    }

    private long getRequiredFactorCount(FactorContext factorContext) {
        String userId = factorContext.getUsername();
        String flowType = factorContext.getFlowTypeName();

        long requiredFactors = mfaPolicyProvider.getRequiredFactorCount(userId, flowType);

        if (requiredFactors > 0) {
            return requiredFactors;
        }

        log.error("PolicyProvider returned null/invalid for user: {}, flow: {}. Using default: 1",
                userId, flowType);
        return 1;
    }

    @Override
    public String getFailureReason() {
        return "Not all required MFA factors have been completed. Check factor requirements and completion status.";
    }

    @Override
    public String getGuardName() {
        return "AllFactorsCompletedGuard";
    }
}