package io.contexa.demo.observation.receipt.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.time.Instant;
import java.util.UUID;

public record ClientReceiptInput(
        @NotNull UUID id,
        @NotNull ReceiptState state,
        @Min(0) @Max(10485760) long receivedBytes,
        @Pattern(regexp = "[a-f0-9]{64}") String contentSha256,
        @NotNull Instant startedAt,
        @NotNull Instant endedAt) {
}
