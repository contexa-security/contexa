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
package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class FeatureAvailabilityValidator implements Validator<AuthenticationStepConfig> {

    private final AdapterRegistry adapterRegistry;

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getType() == null) {
            result.addError("Critical error: Authentication step or step type is null. Please check DSL configuration.");
            return result;
        }

        String stepType = step.getType().toLowerCase();
        if (adapterRegistry.getAuthenticationAdapter(stepType) == null) {
            result.addError(String.format("Critical platform error: No AuthenticationFeature implementation registered in FeatureRegistry for authentication type '%s' defined in DSL. (Step order: %d)",
                    step.getType(), step.getOrder()));
            log.error("DSL VALIDATION ERROR: AuthenticationFeature not found for type '{}'", step.getType());
        }
        return result;
    }
}
