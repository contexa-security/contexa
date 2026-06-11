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

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;

import java.util.List;

@Slf4j
public class MfaFlowStructureValidator implements Validator<AuthenticationFlowConfig> {

    @Override
    public ValidationResult validate(AuthenticationFlowConfig flow) {
        ValidationResult result = new ValidationResult();
        if (flow == null || !MfaFlowTypeUtils.isMfaFlow(flow.getTypeName())) {
            return result;
        }

        List<AuthenticationStepConfig> steps = flow.getStepConfigs();
        if (CollectionUtils.isEmpty(steps)) {
            return result;
        }

        String flowIdentifier = String.format("MFA Flow (type: '%s', order: %d)", flow.getTypeName(), flow.getOrder());

        AuthenticationStepConfig firstStep = steps.get(0);
        if (firstStep.getOrder() != 0 ||
                !("mfa_form".equalsIgnoreCase(firstStep.getType()) || "mfa_rest".equalsIgnoreCase(firstStep.getType()))) {
            result.addError(String.format("The first authentication step of %s must be 'mfa_form' or 'mfa_rest' type with order 0. Current: type='%s', order=%d",
                    flowIdentifier, firstStep.getType(), firstStep.getOrder()));
            log.error("DSL VALIDATION ERROR for {}: {}", flowIdentifier, result.getErrors());
        }

        return result;
    }
}
