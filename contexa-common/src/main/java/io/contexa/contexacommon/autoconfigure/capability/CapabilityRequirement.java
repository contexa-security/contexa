package io.contexa.contexacommon.autoconfigure.capability;

public record CapabilityRequirement(
        ContexaCapability capability,
        boolean enabled,
        boolean required,
        String reason) {

    public static CapabilityRequirement disabled(ContexaCapability capability, String reason) {
        return new CapabilityRequirement(capability, false, false, reason);
    }

    public static CapabilityRequirement optional(ContexaCapability capability, String reason) {
        return new CapabilityRequirement(capability, true, false, reason);
    }

    public static CapabilityRequirement required(ContexaCapability capability, String reason) {
        return new CapabilityRequirement(capability, true, true, reason);
    }
}
