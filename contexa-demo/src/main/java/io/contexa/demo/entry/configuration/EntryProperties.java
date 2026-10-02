package io.contexa.demo.entry.configuration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties("lab.entry")
public record EntryProperties(
        @NotBlank String portalUrl,
        @NotBlank String cookieName,
        boolean secureCookie,
        @NotNull Duration pendingLifetime,
        @NotNull Duration verifiedLifetime,
        @NotNull Duration codeLifetime,
        @NotNull Duration resendInterval,
        @Min(1) int maxAttempts,
        @Min(1) int emailDailyLimit,
        @Min(1) int ipDailyLimit,
        @Valid @NotNull EntryStoreProperties store,
        @Valid @NotNull EntryMailProperties mail
) {

    public EntryProperties {
        for (Duration value : new Duration[]{pendingLifetime, verifiedLifetime, codeLifetime, resendInterval}) {
            if (value == null || value.isZero() || value.isNegative()) {
                throw new IllegalArgumentException("Entry duration must be positive");
            }
        }
    }
}
