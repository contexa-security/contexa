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
package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class HandleFailureAction extends AbstractMfaStateAction {

    private final MfaSettings mfaSettings;

    public HandleFailureAction(MfaSettings mfaSettings) {
        this.mfaSettings = mfaSettings;
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();

        String failureReason = (String) context.getMessageHeader("failureReason");
        if (failureReason == null) {
            failureReason = (String) context.getExtendedState().getVariables().get("lastError");
        }

        factorContext.setLastError(failureReason != null ? failureReason : "Unknown error");

        int retryCount = factorContext.getRetryCount();
        factorContext.setRetryCount(retryCount + 1);

        if (factorContext.getCurrentProcessingFactor() != null) {
            String factorName = factorContext.getCurrentProcessingFactor().name();
            factorContext.setAttribute("retryCount_" + factorName,
                    factorContext.getAttemptCount(factorContext.getCurrentProcessingFactor()));
        }

        int maxRetries = mfaSettings.getMaxRetryAttempts();

        if (factorContext.getRetryCount() >= maxRetries) {
            log.error("Max retry attempts exceeded for session: {}", sessionId);
        }
    }
}