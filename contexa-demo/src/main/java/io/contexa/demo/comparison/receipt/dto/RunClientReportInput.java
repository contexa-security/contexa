package io.contexa.demo.comparison.receipt.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.time.Instant;
import java.util.UUID;

public record RunClientReportInput(
        @NotNull UUID attemptId,
        @NotNull UUID stepId,
        @NotNull @Pattern(regexp = "STARTED|FINISHED") String stage,
        @NotNull @Pattern(regexp = "PREPARATION|BUSINESS") String phase,
        @NotNull @Pattern(regexp = "UNCONFIRMED|RESPONSE_RECEIVED|TIMED_OUT|NETWORK_FAILED|PREPARATION_FAILED|RESPONSE_LIMIT") String outcome,
        @NotNull Instant startedAt,
        @NotNull Instant observedAt,
        @Min(100) @Max(599) Integer httpStatus,
        @Min(0) @Max(2097152) Long responseBytes
) {
}
