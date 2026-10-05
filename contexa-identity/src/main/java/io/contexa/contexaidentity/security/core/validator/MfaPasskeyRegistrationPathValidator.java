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

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import lombok.extern.slf4j.Slf4j;

/**
 * Reports MFA flows in which a user without a passkey has no way to register one.
 *
 * <p>Passkey registration is denied until the MFA flow completes, so that the first factor alone
 * cannot enroll a new credential. A user who has no passkey yet completes the MFA flow with the email
 * OTT factor and is then taken to passkey registration. An MFA flow that offers the passkey factor
 * without the OTT factor therefore leaves new users unable to register a passkey and to sign in.</p>
 *
 * <p>The finding is reported as a warning and logged as an error. It does not abort startup, because
 * such a flow still works for users whose passkeys were registered by other means.</p>
 */
@Slf4j
public class MfaPasskeyRegistrationPathValidator implements Validator<AuthenticationFlowConfig> {

    @Override
    public ValidationResult validate(AuthenticationFlowConfig flow) {
        ValidationResult result = new ValidationResult();
        if (flow == null || !MfaFlowTypeUtils.isMfaFlow(flow.getTypeName())) {
            return result;
        }

        if (!hasFactor(flow, AuthType.MFA_PASSKEY) || hasFactor(flow, AuthType.MFA_OTT)) {
            return result;
        }

        String message = String.format(
                "MFA flow '%s' offers the passkey factor without the email OTT factor. Passkey registration is "
                        + "denied until MFA completes, so new users without a passkey cannot register one and "
                        + "cannot sign in. Add the OTT factor (.ott(...)) to this MFA flow so that users can verify "
                        + "their identity by email and then register a passkey.",
                flow.getTypeName());
        result.addWarning(message);
        log.error("DSL VALIDATION for {}: {}", flow.getTypeName(), message);
        return result;
    }

    private boolean hasFactor(AuthenticationFlowConfig flow, AuthType factorType) {
        if (flow.getRegisteredFactorOptions() != null && flow.getRegisteredFactorOptions().containsKey(factorType)) {
            return true;
        }
        if (flow.getStepConfigs() == null) {
            return false;
        }
        for (AuthenticationStepConfig step : flow.getStepConfigs()) {
            if (step != null && !step.isPrimary() && factorType.name().equalsIgnoreCase(step.getType())) {
                return true;
            }
        }
        return false;
    }
}
