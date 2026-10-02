package io.contexa.demo.entry.configuration;

import jakarta.validation.constraints.NotBlank;

public record EntryStoreProperties(
        @NotBlank String url,
        @NotBlank String username,
        String password
) {

}
