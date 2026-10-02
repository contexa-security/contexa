package io.contexa.demo.entry.configuration;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record EntryMailProperties(
        String host,
        @Min(1) @Max(65535) int port,
        String username,
        String password,
        String from,
        boolean starttls,
        boolean ssl
) {

}
