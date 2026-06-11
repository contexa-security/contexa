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
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.guard.Guard;

@Slf4j
public abstract class AbstractMfaStateGuard implements Guard<MfaState, MfaEvent>, MfaStateGuard {

    @Override
    public final boolean evaluate(StateContext<MfaState, MfaEvent> context) {
        try {
            
            FactorContext factorContext = extractFactorContext(context);
            if (factorContext == null) {
                log.warn("FactorContext not found in state context for guard: {}", getGuardName());
                return false;
            }

            return doEvaluate(context, factorContext);

        } catch (Exception e) {
            log.error("Error evaluating guard: {}", getGuardName(), e);
            return false;
        }
    }

    protected abstract boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                          FactorContext factorContext);

    protected FactorContext extractFactorContext(StateContext<MfaState, MfaEvent> context) {
        return StateContextHelper.getFactorContext(context);
    }

    public Guard<MfaState, MfaEvent> negate() {
        return context -> !this.evaluate(context);
    }

    @Override
    public abstract String getFailureReason();

    @Override
    public abstract String getGuardName();
}