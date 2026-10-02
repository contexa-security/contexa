package io.contexa.demo.entry.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record CodeRequest(
        @NotNull UUID requestId,
        @NotBlank @Email @Size(max = 254) String email,
        @NotNull @Pattern(regexp = "ko|en") String language
) {

}
