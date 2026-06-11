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
package io.contexa.contexaidentity.security.statemachine.support;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.springframework.statemachine.ExtendedState;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.StateMachine;

public class StateContextHelper {

    public static final String FACTOR_CONTEXT_KEY = "factorContext";

    private StateContextHelper() {}

    public static FactorContext getFactorContext(ExtendedState extendedState) {
        if (extendedState == null) return null;
        return extendedState.get(FACTOR_CONTEXT_KEY, FactorContext.class);
    }

    public static void setFactorContext(ExtendedState extendedState, FactorContext factorContext) {
        if (extendedState != null) {
            extendedState.getVariables().put(FACTOR_CONTEXT_KEY, factorContext);
        }
    }

    public static FactorContext getFactorContext(StateMachine<MfaState, MfaEvent> stateMachine) {
        if (stateMachine == null) return null;
        return getFactorContext(stateMachine.getExtendedState());
    }

    public static void setFactorContext(StateMachine<MfaState, MfaEvent> stateMachine, FactorContext factorContext) {
        if (stateMachine != null) {
            setFactorContext(stateMachine.getExtendedState(), factorContext);
        }
    }

    public static FactorContext getFactorContext(StateContext<MfaState, MfaEvent> context) {
        if (context == null) return null;
        return getFactorContext(context.getExtendedState());
    }

    public static void setFactorContext(StateContext<MfaState, MfaEvent> context, FactorContext factorContext) {
        if (context != null) {
            setFactorContext(context.getExtendedState(), factorContext);
        }
    }
}