package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptReplayScenarioCatalogTest {

    @Test
    @DisplayName("EXTENDED 시나리오 세트는 최소 8개의 장기 행동 시나리오를 제공해야 한다")
    void shouldExposeAtLeastEightExtendedScenarios() {
        // 공식 benchmark의 when은 짧은 path 반복이 아니라
        // 같은 계정의 장기 업무 패턴을 다양한 family로 분리해 가져가야 한다.
        List<SandboxPromptReplayScenario> scenarios = SandboxPromptReplayScenarioCatalog.extendedScenarioSet();

        assertThat(scenarios).hasSizeGreaterThanOrEqualTo(8);
        assertThat(scenarios)
                .extracting(SandboxPromptReplayScenario::scenarioKey)
                .doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("CORE selector는 기본 세트와 같고 ALL selector는 EXTENDED와 같아야 한다")
    void shouldResolveScenarioSelectorsDeterministically() {
        List<SandboxPromptReplayScenario> defaultScenarios = SandboxPromptReplayScenarioCatalog.resolve("DEFAULT");
        List<SandboxPromptReplayScenario> coreScenarios = SandboxPromptReplayScenarioCatalog.resolve("CORE");
        List<SandboxPromptReplayScenario> allScenarios = SandboxPromptReplayScenarioCatalog.resolve("ALL");
        List<SandboxPromptReplayScenario> extendedScenarios = SandboxPromptReplayScenarioCatalog.resolve("EXTENDED");

        assertThat(defaultScenarios).containsExactlyElementsOf(coreScenarios);
        assertThat(allScenarios).containsExactlyElementsOf(extendedScenarios);
    }

    @Test
    @DisplayName("장기 시나리오는 24회차와 다중 세션 시간축을 기본으로 가져야 한다")
    void shouldExposeLongHorizonRoundsAndSessionBoundaries() {
        List<SandboxPromptReplayScenario> scenarios = SandboxPromptReplayScenarioCatalog.coreScenarioSet();

        assertThat(scenarios)
                .extracting(SandboxPromptReplayScenario::roundCount)
                .containsOnly(24);

        // 장기 benchmark의 핵심은 몇 초짜리 반복이 아니라 여러 주기의 session 재진입이다.
        assertThat(scenarios)
                .flatExtracting(SandboxPromptReplayScenario::roundPlans)
                .extracting(SandboxPromptRoundPlan::sessionMode)
                .contains(SandboxPromptSessionMode.NEW_SESSION, SandboxPromptSessionMode.REUSE_SESSION);

        assertThat(scenarios)
                .flatExtracting(SandboxPromptReplayScenario::roundPlans)
                .extracting(SandboxPromptRoundPlan::observedAt)
                .doesNotContainNull()
                .allSatisfy(value -> assertThat(value.toString()).contains("+09:00"));
    }

    @Test
    @DisplayName("장기 시나리오는 경로 IP UA 디바이스 민감도 순서 속도 축을 모두 변화시켜야 한다")
    void shouldExposeRichLongHorizonVariationAcrossExtendedScenarios() {
        // 이 테스트는 coarse signal 몇 개만 바뀌는 피상적 benchmark를 막기 위한 것이다.
        // 같은 계정 안에서 업무군, 순서, cadence, device, network, scope가 함께 섞여야 한다.
        List<SandboxPromptReplayScenario> scenarios = SandboxPromptReplayScenarioCatalog.extendedScenarioSet();
        List<SandboxPromptRoundPlan> roundPlans = scenarios.stream()
                .flatMap(scenario -> scenario.roundPlans().stream())
                .toList();

        assertThat(roundPlans)
                .extracting(SandboxPromptRoundPlan::requestPath)
                .anyMatch(path -> String.valueOf(path).contains("/normal/"))
                .anyMatch(path -> String.valueOf(path).contains("/sensitive/"))
                .anyMatch(path -> String.valueOf(path).contains("/critical/"));

        assertThat(roundPlans)
                .extracting(SandboxPromptRoundPlan::clientIp)
                .contains("192.168.1.100", "192.168.1.118", "10.10.8.44", "172.16.20.52");

        assertThat(roundPlans)
                .extracting(SandboxPromptRoundPlan::simulatedUserAgentLabel)
                .contains("Chrome 120 / Windows 11", "Edge 120 / Windows 11", "Chrome 120 / Windows 11 VDI");

        assertThat(roundPlans)
                .extracting(SandboxPromptRoundPlan::deviceAlias)
                .contains("corp-laptop-a", "corp-laptop-b", "managed-vdi");

        assertThat(roundPlans)
                .extracting(SandboxPromptRoundPlan::anomalySignal)
                .contains(
                        "NONE",
                        "RESOURCE_SENSITIVITY_SURGE",
                        "UNSEEN_RESOURCE_FANOUT",
                        "DEVICE_FINGERPRINT_SHIFT",
                        "NETWORK_PIVOT",
                        "CADENCE_BURST",
                        "SEQUENCE_REVERSAL",
                        "LATE_CRITICAL_APPROVAL",
                        "TEMPORARY_NORMALIZATION");
    }

    @Test
    @DisplayName("resizeScenario는 회차를 줄일 때 prefix를 유지하고 늘릴 때는 시간을 앞으로 밀어 장기 패턴을 이어가야 한다")
    void shouldResizeScenarioWithoutRepeatingTheLastRoundForever() {
        SandboxPromptReplayScenario scenario = SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE;

        SandboxPromptReplayScenario shortened = SandboxPromptReplayScenarioCatalog.resizeScenario(scenario, 6);
        SandboxPromptReplayScenario expanded = SandboxPromptReplayScenarioCatalog.resizeScenario(scenario, 30);

        assertThat(shortened.roundCount()).isEqualTo(6);
        assertThat(shortened.roundPlanForRound(6).requestPath()).isEqualTo(scenario.roundPlanForRound(6).requestPath());

        assertThat(expanded.roundCount()).isEqualTo(30);
        assertThat(expanded.roundPlanForRound(25).observedAt()).isAfter(scenario.roundPlanForRound(24).observedAt());
        assertThat(expanded.roundPlanForRound(30).roundKey()).isEqualTo("R30");
    }
}