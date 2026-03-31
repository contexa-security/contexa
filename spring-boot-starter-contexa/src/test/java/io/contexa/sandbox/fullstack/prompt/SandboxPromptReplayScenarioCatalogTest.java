package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptReplayScenarioCatalogTest {

    @Test
    @DisplayName("EXTENDED 시나리오 세트는 최소 8개의 장기 행동 시나리오를 제공해야 한다")
    void shouldExposeAtLeastEightExtendedScenarios() {
        // 벤치마킹 카탈로그는 단순 path 반복이 아니라,
        // 같은 계정의 baseline 축적과 anomaly injection을 여러 family로 커버해야 한다.
        List<SandboxPromptReplayScenario> scenarios = SandboxPromptReplayScenarioCatalog.extendedScenarioSet();

        assertThat(scenarios).hasSizeGreaterThanOrEqualTo(8);
        assertThat(scenarios)
                .extracting(SandboxPromptReplayScenario::scenarioKey)
                .doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("CORE selector는 기본보다 넓고 ALL selector는 EXTENDED와 같아야 한다")
    void shouldResolveScenarioSelectorsDeterministically() {
        List<SandboxPromptReplayScenario> defaultScenarios = SandboxPromptReplayScenarioCatalog.resolve("DEFAULT");
        List<SandboxPromptReplayScenario> coreScenarios = SandboxPromptReplayScenarioCatalog.resolve("CORE");
        List<SandboxPromptReplayScenario> allScenarios = SandboxPromptReplayScenarioCatalog.resolve("ALL");
        List<SandboxPromptReplayScenario> extendedScenarios = SandboxPromptReplayScenarioCatalog.resolve("EXTENDED");

        assertThat(defaultScenarios).hasSize(1);
        assertThat(coreScenarios.size()).isGreaterThan(defaultScenarios.size());
        assertThat(allScenarios).containsExactlyElementsOf(extendedScenarios);
    }

    @Test
    @DisplayName("시나리오 카탈로그는 같은 계정 기준으로 path IP UA device cadence anomaly를 모두 변화시킬 수 있어야 한다")
    void shouldExposeRichRoundPlanVariationAcrossExtendedScenarios() {
        // 정부 제출용 benchmark의 when은 고정된 coarse signal이 아니라
        // 다양한 round plan 조합이어야 한다. 그렇지 않으면 baseline과 RAG가 단조롭게 쌓여
        // subtle anomaly를 검증할 수 없다.
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
                .extracting(SandboxPromptRoundPlan::cooldownBeforeRoundMs)
                .contains(5200L, 6200L, 8800L);

        assertThat(roundPlans)
                .extracting(SandboxPromptRoundPlan::anomalySignal)
                .contains("NONE",
                        "RESOURCE_SENSITIVITY_SURGE",
                        "UNSEEN_RESOURCE_FANOUT",
                        "DEVICE_FINGERPRINT_SHIFT",
                        "NETWORK_PIVOT",
                        "CADENCE_BURST",
                        "SEQUENCE_REVERSAL",
                        "LATE_CRITICAL_APPROVAL",
                        "TEMPORARY_NORMALIZATION");

        assertThat(scenarios)
                .extracting(SandboxPromptReplayScenario::scenarioHeader)
                .containsOnly("NORMAL_USER");

        assertThat(scenarios)
                .extracting(SandboxPromptReplayScenario::userProfileKey)
                .doesNotContainNull()
                .allMatch(value -> !String.valueOf(value).isBlank());

        assertThat(scenarios)
                .extracting(SandboxPromptReplayScenario::scenarioFamily)
                .containsOnly(
                        "RESOURCE_SURGE",
                        "RESOURCE_FANOUT",
                        "DEVICE_SHIFT",
                        "NETWORK_PIVOT",
                        "CADENCE_BURST",
                        "SEQUENCE_REVERSAL",
                        "LATE_ESCALATION",
                        "RECOVERY");
    }
}
