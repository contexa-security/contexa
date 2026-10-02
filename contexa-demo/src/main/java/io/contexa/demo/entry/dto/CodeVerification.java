package io.contexa.demo.entry.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

public record CodeVerification(
        @NotNull UUID requestId,
        @NotNull @Pattern(regexp = "[0-9]{6}") String code
) {

}
