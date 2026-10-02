package io.contexa.demo.readiness.dto;

public record ReadinessCheckResult(
        String component,
        String state,
        String detail,
        Object observed
) {

}
