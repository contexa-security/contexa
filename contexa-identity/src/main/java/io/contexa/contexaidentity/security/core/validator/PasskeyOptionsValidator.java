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

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Slf4j
public class PasskeyOptionsValidator implements Validator<AuthenticationStepConfig> {

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getOptions() == null) {
            return result;
        }

        if (!"passkey".equalsIgnoreCase(step.getType())) {
            return result;
        }

        String stepIdentifier = String.format("Step (type: '%s', order: %d)", step.getType(), step.getOrder());
        Object optionsObject = step.getOptions().get(AuthenticationStepConfig.OPTIONS_KEY);

        if (!(optionsObject instanceof PasskeyOptions passkeyOptions)) {
            result.addError(String.format("Options object for %s is not of PasskeyOptions type. (Actual type: %s)",
                    stepIdentifier, optionsObject != null ? optionsObject.getClass().getName() : "null"));
            return result;
        }

        if (!StringUtils.hasText(passkeyOptions.getRpId())) {
            result.addError(String.format("Required option 'rpId' is not set for %s. Passkey authentication requires a Relying Party ID.", stepIdentifier));
        }

        if (!StringUtils.hasText(passkeyOptions.getRpName())) {
            result.addWarning(String.format("'rpName' is not set for %s. This is the Relying Party name displayed to users.", stepIdentifier));
        }

        if (result.hasErrors() || result.hasWarnings()) {
            log.error("DSL VALIDATION for {}: Errors: {}, Warnings: {}", stepIdentifier, result.getErrors(), result.getWarnings());
        }
        return result;
    }
}
