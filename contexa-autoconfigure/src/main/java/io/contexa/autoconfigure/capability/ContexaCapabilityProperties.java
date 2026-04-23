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
