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
package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import org.springframework.lang.Nullable;

import java.util.List;

public interface MfaPolicyEvaluator {

    MfaDecision evaluatePolicy(FactorContext context);

    default boolean isMfaRequired(String username, @Nullable FactorContext context) {
        if (context == null) {
            
            return true;
        }
        MfaDecision decision = evaluatePolicy(context);
        return decision.isRequired();
    }

    default int getRequiredFactorCount(FactorContext context) {
        MfaDecision decision = evaluatePolicy(context);
        return decision.getFactorCount();
    }

    default List<AuthType> determineRequiredFactors(
            List<AuthType> availableFactors, 
            FactorContext context) {
        MfaDecision decision = evaluatePolicy(context);
        List<AuthType> requiredFactors = decision.getRequiredFactors();

        if (requiredFactors == null || requiredFactors.isEmpty()) {
            return availableFactors;
        }

        return requiredFactors.stream()
            .filter(availableFactors::contains)
            .toList();
    }

    default boolean supports(FactorContext context) {
        return isAvailable();
    }

    default boolean isAvailable() {
        return true;
    }

    default int getPriority() {
        return 0;
    }

    default String getName() {
        return this.getClass().getSimpleName();
    }
}