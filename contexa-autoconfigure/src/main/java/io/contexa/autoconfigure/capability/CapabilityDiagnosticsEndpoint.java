package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;

import java.util.List;

@Endpoint(id = "contexacapabilities")
public class CapabilityDiagnosticsEndpoint {

    private final ContexaCapabilityRegistry registry;
    private final CapabilityRequirementResolver requirementResolver;

    public CapabilityDiagnosticsEndpoint(
            ContexaCapabilityRegistry registry,
            CapabilityRequirementResolver requirementResolver) {
        this.registry = registry;
        this.requirementResolver = requirementResolver;
    }

    @ReadOperation
    public CapabilityDiagnostics diagnostics() {
        return new CapabilityDiagnostics(requirementResolver.effectiveMode().name(), registry.lastResults());
    }

    public record CapabilityDiagnostics(String mode, List<CapabilityCheckResult> capabilities) {
    }
}
