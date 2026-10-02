package io.contexa.demo.readiness.dto;

public record RuntimeMode(
        boolean enabled,
        String mode,
        boolean analysisEnabled,
        boolean enforcementEnabled
) {

}
