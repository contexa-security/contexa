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
package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityMode;
import io.contexa.contexacommon.autoconfigure.capability.ContexaCapability;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

@ConfigurationProperties(prefix = "contexa.capability")
public class ContexaCapabilityProperties {

    private CapabilityMode mode = CapabilityMode.AUTO;
    private Map<ContexaCapability, Boolean> required = new EnumMap<>(ContexaCapability.class);
    private boolean exposeDiagnosticsEndpoint = true;

    public CapabilityMode getMode() {
        return mode;
    }

    public void setMode(CapabilityMode mode) {
        this.mode = mode == null ? CapabilityMode.AUTO : mode;
    }

    public Map<ContexaCapability, Boolean> getRequired() {
        return required;
    }

    public void setRequired(Map<ContexaCapability, Boolean> required) {
        this.required = new EnumMap<>(ContexaCapability.class);
        if (required != null) {
            this.required.putAll(required);
        }
    }

    public boolean isExposeDiagnosticsEndpoint() {
        return exposeDiagnosticsEndpoint;
    }

    public void setExposeDiagnosticsEndpoint(boolean exposeDiagnosticsEndpoint) {
        this.exposeDiagnosticsEndpoint = exposeDiagnosticsEndpoint;
    }

    public Optional<Boolean> requiredOverride(ContexaCapability capability) {
        return Optional.ofNullable(required.get(capability));
    }
}
