package io.contexa.sandbox.fullstack.prompt;

import org.springframework.test.context.DynamicPropertyRegistry;

import java.time.Duration;
import java.util.Locale;
import java.util.Set;

/**
 * sandbox full-stack benchmark의 wall-clock 실행 시간을 조절하는 공통 설정.
 *
 * 핵심 원칙:
 * - 장기 시나리오의 의미는 observedAt 헤더와 round plan에 담고,
 * - 실제 Thread.sleep 은 기술적 재진입 완화 용도로만 최소화한다.
 *
 * 따라서 벤치마크가 몇 주/몇 달의 행동 패턴을 검증하더라도,
 * 테스트 wall-clock 은 불필요하게 그 간격을 그대로 따라가지 않는다.
 */
public final class SandboxBenchmarkRuntimeSettings {

    private static final long DEFAULT_ROUND_COOLDOWN_MS = 350L;
    private static final long MIN_SAFE_ROUND_COOLDOWN_MS = 200L;
    private static final long DEFAULT_RAPID_REENTRY_WINDOW_MS = 250L;
    private static final long DEFAULT_RAG_TIMEOUT_MS = 4000L;
    private static final String PROMPT_PROFILE_PROPERTY = "sandbox.prompt.benchmark.profile";
    private static final Set<String> KNOWN_PROMPT_PROFILES = Set.of(
            "CORTEX_L1_DECISION_COMPACT",
            "CORTEX_L1_COMPACT",
            "CORTEX_L2_COMPACT",
            "CORTEX_L1_STANDARD",
            "CORTEX_L2_STANDARD",
            "CORTEX_L1_EXPANDED",
            "CORTEX_L2_EXPANDED",
            "CORTEX_ENTERPRISE_ENRICHED");

    private SandboxBenchmarkRuntimeSettings() {
    }

    public static Duration roundCooldown() {
        long configured = Long.getLong("sandbox.prompt.benchmark.cooldown.ms", DEFAULT_ROUND_COOLDOWN_MS);
        return Duration.ofMillis(Math.max(MIN_SAFE_ROUND_COOLDOWN_MS, configured));
    }

    public static long minSafeRoundCooldownMs() {
        return MIN_SAFE_ROUND_COOLDOWN_MS;
    }

    public static long rapidReentryWindowMs() {
        long configured = Long.getLong(
                "sandbox.prompt.benchmark.rapid-reentry.window.ms",
                DEFAULT_RAPID_REENTRY_WINDOW_MS);
        return Math.max(0L, configured);
    }

    public static String promptBudgetProfileOverride() {
        String configured = System.getProperty(PROMPT_PROFILE_PROPERTY);
        if (configured == null || configured.isBlank()) {
            if (SandboxDecisionBenchmarkSettings.useRealLlm()) {
                return "CORTEX_L1_DECISION_COMPACT";
            }
            return null;
        }
        String normalized = configured.trim().toUpperCase(Locale.ROOT);
        return KNOWN_PROMPT_PROFILES.contains(normalized) ? normalized : null;
    }

    public static long ragTimeoutMs() {
        long configured = Long.getLong("sandbox.prompt.benchmark.rag-timeout.ms", DEFAULT_RAG_TIMEOUT_MS);
        return Math.max(1000L, configured);
    }

    public static void registerSandboxBenchmarkProperties(DynamicPropertyRegistry registry) {
        // Sandbox full-stack tests replace production PlatformConfig with a test-only OTT-first config.
        // Bean overriding must be enabled before the context refresh starts.
        registry.add("spring.main.allow-bean-definition-overriding", () -> "true");
        registry.add("contexa.opentelemetry.enabled", () -> false);
        registry.add("contexa.iam.protectable.rapid-reentry.window-ms",
                SandboxBenchmarkRuntimeSettings::rapidReentryWindowMs);
        registry.add("spring.ai.security.tiered.layer1.timeout.rag-ms",
                SandboxBenchmarkRuntimeSettings::ragTimeoutMs);
        registry.add("spring.ai.vectorstore.pgvector.search-timeout-ms",
                SandboxBenchmarkRuntimeSettings::ragTimeoutMs);
        registry.add("spring.ai.vectorstore.pgvector.store-timeout-ms",
                SandboxBenchmarkRuntimeSettings::ragTimeoutMs);
    }
}
