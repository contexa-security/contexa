package io.contexa.contexacore.std.llm.client;

public record StructuredOutputCapability(
        String providerFamily,
        boolean nativeStructuredSupported,
        boolean validationAdvisorSupported,
        String resolutionSource
) {

    public StructuredOutputMode resolvePreferredMode() {
        if (nativeStructuredSupported) {
            return StructuredOutputMode.NATIVE_STRUCTURED;
        }
        if (validationAdvisorSupported) {
            return StructuredOutputMode.VALIDATED_CONVERTER;
        }
        return StructuredOutputMode.LEGACY_RAW;
    }
}
