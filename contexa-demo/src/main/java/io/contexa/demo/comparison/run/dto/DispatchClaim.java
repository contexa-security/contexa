package io.contexa.demo.comparison.run.dto;

import java.util.UUID;

public record DispatchClaim(RunRecord run, RunStep step, String outcome, UUID attemptedRequestId) {
}
