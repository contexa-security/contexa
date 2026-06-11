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

import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class RetryLimitGuard extends AbstractMfaStateGuard {

    private final MfaSettings mfaSettings;

    public RetryLimitGuard(MfaSettings mfaSettings) {
        this.mfaSettings = mfaSettings;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        int currentRetryCount = factorContext.getRetryCount();
        int maxRetries = mfaSettings.getMaxRetryAttempts();

        String currentFactor = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (currentFactor != null) {
            Integer factorRetryCount = getFactorRetryCount(factorContext, currentFactor);

            if (factorRetryCount >= maxRetries) {
                log.error("Factor {} retry limit exceeded for session: {}",
                        currentFactor, sessionId);
                return false;
            }
        }

        boolean withinLimit = currentRetryCount < maxRetries;

        if (!withinLimit) {
            log.error("Total retry limit exceeded for session: {}", sessionId);
        }

        return withinLimit;
    }

    private Integer getFactorRetryCount(FactorContext factorContext, String factorType) {
        String key = "retryCount_" + factorType;
        Object retryCount = factorContext.getAttribute(key);

        if (retryCount instanceof Integer) {
            return (Integer) retryCount;
        }

        return 0;
    }

    @Override
    public String getFailureReason() {
        return "Maximum retry attempts exceeded";
    }

    @Override
    public String getGuardName() {
        return "RetryLimitGuard";
    }
}
