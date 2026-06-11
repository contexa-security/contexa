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
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;

import java.util.*;

@Slf4j
public class LoginProcessingUrlUniquenessValidator implements Validator<List<AuthenticationFlowConfig>> {

    private static class UrlInfo {
        final String url;
        final HttpMethod method;
        final String flowId;
        final String stepType;
        final int stepOrder;

        UrlInfo(String url, HttpMethod method, AuthenticationFlowConfig flow, AuthenticationStepConfig step) {
            this.url = url;
            this.method = method;
            this.flowId = flow.getTypeName() + "@" + flow.getOrder();
            this.stepType = step.getType();
            this.stepOrder = step.getOrder();
        }

        String getContext() {
            return String.format("Flow '%s', Step '%s'(order:%d)", flowId, stepType, stepOrder);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            UrlInfo that = (UrlInfo) o;
            return Objects.equals(url, that.url) && method == that.method;
        }

        @Override
        public int hashCode() {
            return Objects.hash(url, method);
        }

        @Override
        public String toString() {
            return method + " " + url;
        }
    }

    @Override
    public ValidationResult validate(List<AuthenticationFlowConfig> flows) {
        ValidationResult result = new ValidationResult();
        if (flows == null || flows.isEmpty()) {
            return result;
        }

        Map<UrlInfo, List<String>> urlUsageMap = new HashMap<>();

        for (AuthenticationFlowConfig flow : flows) {

            for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                Object optionsObject = step.getOptions().get(AuthenticationStepConfig.OPTIONS_KEY);
                if (optionsObject instanceof AuthenticationProcessingOptions processingOptions) {
                    String loginProcessingUrl = processingOptions.getLoginProcessingUrl();

                    if (loginProcessingUrl != null) {

                        HttpMethod httpMethod = HttpMethod.POST;

                        UrlInfo currentUrlInfoKey = new UrlInfo(loginProcessingUrl, httpMethod, flow, step);
                        String usageContext = currentUrlInfoKey.getContext();

                        urlUsageMap.computeIfAbsent(currentUrlInfoKey, k -> new ArrayList<>()).add(usageContext);
                    }
                }
            }
        }

        for (Map.Entry<UrlInfo, List<String>> entry : urlUsageMap.entrySet()) {
            if (entry.getValue().size() > 1) {
                result.addError(String.format(
                        "Duplicate login processing URL detected: '%s' is used by: %s",
                        entry.getKey(), String.join(", ", entry.getValue())));
            }
        }

        return result;
    }
}
