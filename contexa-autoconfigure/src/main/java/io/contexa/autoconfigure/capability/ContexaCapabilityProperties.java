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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@ConfigurationProperties(prefix = "contexa.capability")
public class ContexaCapabilityProperties {

    private CapabilityMode mode = CapabilityMode.AUTO;
    /**
     * Whether a capability is required, by its key (contexa.capability.required.rag-vector=true). The keys are bound
     * as names and read as capabilities here, so a key of a capability an upgrade removed (pqa-engine) does not stop
     * the start: the resolver reports it and leaves it.
     */
    private Map<String, Boolean> required = new LinkedHashMap<>();
    private boolean exposeDiagnosticsEndpoint = true;

    public CapabilityMode getMode() {
        return mode;
    }

    public void setMode(CapabilityMode mode) {
        this.mode = mode == null ? CapabilityMode.AUTO : mode;
    }

    public Map<String, Boolean> getRequired() {
        return required;
    }

    public void setRequired(Map<String, Boolean> required) {
        this.required = new LinkedHashMap<>();
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
        return required.entrySet().stream()
                .filter(entry -> entry.getValue() != null && capabilityOf(entry.getKey()).orElse(null) == capability)
                .map(Map.Entry::getValue)
                .findFirst();
    }

    /** The keys of contexa.capability.required that name no capability, in the order they were set. */
    public List<String> unknownRequirements() {
        return required.keySet().stream().filter(key -> capabilityOf(key).isEmpty()).toList();
    }

    /**
     * The capability a key names, read as the binding read the enum before: letters and digits alone, case ignored
     * (rag-vector, RAG_VECTOR and the rag.vector of an environment variable name RAG_VECTOR).
     */
    static Optional<ContexaCapability> capabilityOf(String key) {
        String wanted = lenient(key);
        return Stream.of(ContexaCapability.values()).filter(capability -> lenient(capability.name()).equals(wanted))
                .findFirst();
    }

    private static String lenient(String value) {
        return value == null ? "" : value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    }
}
