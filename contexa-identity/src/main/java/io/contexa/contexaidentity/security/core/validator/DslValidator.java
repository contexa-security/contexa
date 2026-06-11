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
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.util.CollectionUtils;

import java.util.List;

@RequiredArgsConstructor
public class DslValidator implements Validator<PlatformConfig> {

    private final List<Validator<PlatformConfig>> platformConfigValidators;

    private final List<Validator<List<AuthenticationFlowConfig>>> flowListValidators;

    private final List<Validator<AuthenticationFlowConfig>> singleFlowValidators;

    private final List<Validator<AuthenticationStepConfig>> stepValidators;

    @Override
    public ValidationResult validate(PlatformConfig platformConfig) {
        ValidationResult finalResult = new ValidationResult();

        if (platformConfig == null) {
            finalResult.addError("PlatformConfig is null. Unable to validate DSL configuration.");
            return finalResult;
        }

        if (!CollectionUtils.isEmpty(platformConfigValidators)) {
            for (Validator<PlatformConfig> pv : platformConfigValidators) {
                finalResult.merge(pv.validate(platformConfig));
            }
        }

        List<AuthenticationFlowConfig> flows = platformConfig.getFlows();

        if (!CollectionUtils.isEmpty(flowListValidators)) {
            for (Validator<List<AuthenticationFlowConfig>> flv : flowListValidators) {
                finalResult.merge(flv.validate(flows));
            }
        }

        if (!CollectionUtils.isEmpty(flows)) {
            for (AuthenticationFlowConfig flow : flows) {
                
                if (!CollectionUtils.isEmpty(singleFlowValidators)) {
                    for (Validator<AuthenticationFlowConfig> sfv : singleFlowValidators) {
                        finalResult.merge(sfv.validate(flow));
                    }
                }
                
                if (!CollectionUtils.isEmpty(stepValidators) && !CollectionUtils.isEmpty(flow.getStepConfigs())) {
                    for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                        for (Validator<AuthenticationStepConfig> sv : stepValidators) {
                            finalResult.merge(sv.validate(step));
                        }
                    }
                }
            }
        }
        return finalResult;
    }
}

