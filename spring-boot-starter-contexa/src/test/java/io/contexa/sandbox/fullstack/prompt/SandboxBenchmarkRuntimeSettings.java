package io.contexa.sandbox.fullstack.prompt;

import org.springframework.test.context.DynamicPropertyRegistry;

import java.time.Duration;

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

    public static void registerSandboxBenchmarkProperties(DynamicPropertyRegistry registry) {
        registry.add("contexa.iam.protectable.rapid-reentry.window-ms",
                SandboxBenchmarkRuntimeSettings::rapidReentryWindowMs);
    }
}
