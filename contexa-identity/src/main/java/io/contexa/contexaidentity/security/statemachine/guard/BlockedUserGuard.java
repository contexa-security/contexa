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
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

@Slf4j
public class BlockedUserGuard extends AbstractMfaStateGuard {

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();
        String username = factorContext.getUsername();

        Object blockedObj = factorContext.getAttribute(FactorContextAttributes.StateControl.BLOCKED);
        boolean isBlocked = Boolean.TRUE.equals(blockedObj);

        if (isBlocked) {
            String blockReason = (String) factorContext.getAttribute(FactorContextAttributes.MessageAndReason.BLOCK_REASON);
            log.warn("[BlockedUserGuard] User {} is blocked for session: {}, reason: {}",
                    username, sessionId, blockReason != null ? blockReason : "UNKNOWN");
            return false;
        }

        return true;
    }

    @Override
    public String getFailureReason() {
        return "User is blocked from MFA process";
    }

    @Override
    public String getGuardName() {
        return "BlockedUserGuard";
    }

}
