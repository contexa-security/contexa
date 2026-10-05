package io.contexa.contexacore.config;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * GlobalOpenTelemetry can be set once per JVM. A second application context in the same JVM (several test
 * configurations, a devtools restart) must still start with its own OpenTelemetry bean instead of failing.
 */
class OpenTelemetryConfigurationTest {

    @BeforeEach
    @AfterEach
    void resetGlobal() {
        GlobalOpenTelemetry.resetForTest();
    }

    @Test
    void registeringTheSecondApplicationContextsSdkDoesNotFail() {
        try (OpenTelemetrySdk first = OpenTelemetrySdk.builder().build();
             OpenTelemetrySdk second = OpenTelemetrySdk.builder().build()) {
            assertThatCode(() -> OpenTelemetryConfiguration.registerGlobal(first)).doesNotThrowAnyException();
            assertThatCode(() -> OpenTelemetryConfiguration.registerGlobal(second)).doesNotThrowAnyException();
        }
    }
}
