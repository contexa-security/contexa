package io.contexa.demo.readiness.dto;

import java.util.UUID;

public record ReadinessCapture(
        UUID id,
        ReadinessReport report
) {

}
