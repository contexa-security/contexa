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
package io.contexa.contexaidentity.security.core.config;

import io.contexa.contexacommon.enums.AuthType;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Getter
@Setter
@ToString
public class AuthenticationStepConfig {

    public static final String OPTIONS_KEY = "_options";

    private String stepId;
    private boolean isPrimary;
    private String type;
    private AuthType authType;
    private final Map<String, Object> options = new HashMap<>();
    private int order = 0;

    private boolean required = true;

    public AuthenticationStepConfig() {
    }

    public AuthenticationStepConfig(String type, int order) {
        this.type = type;
        this.order = order;

    }

    public AuthenticationStepConfig(String flowName, String type, int order, boolean isPrimary) {
        this.type = type;
        this.order = order;
        this.isPrimary = isPrimary;
        this.stepId = generateId(flowName, type, order);
        this.authType = AuthType.valueOf(type);
    }

    public void addOption(String key, Object value) {
        this.options.put(key, value);
    }

    public <T> T getOption(String key) {
        return (T) this.options.get(key);
    }

    public static String generateId(String flowName, String factorType, int order) {
        return flowName.toLowerCase() + ":" + factorType.toLowerCase() + ":" + order;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationStepConfig that = (AuthenticationStepConfig) o;

        return order == that.order &&
                required == that.required &&
                Objects.equals(stepId, that.stepId) &&
                Objects.equals(type, that.type) &&
                Objects.equals(options, that.options);
    }

    @Override
    public int hashCode() {
        return Objects.hash(stepId, type, options, order, required);
    }
}