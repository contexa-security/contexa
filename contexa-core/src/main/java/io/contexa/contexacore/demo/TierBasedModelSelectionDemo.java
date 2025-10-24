package io.contexa.contexacore.demo;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.core.ExecutionContext.AnalysisLevel;
import io.contexa.contexacore.std.llm.core.ExecutionContext.SecurityTaskType;
import org.springframework.ai.chat.prompt.Prompt;

/**
 * 계층 기반 모델 선택 데모
 *
 * 이 클래스는 ExecutionContext의 tier 기반 모델 선택 기능을 시연합니다.
 * 우선순위: preferredModel > analysisLevel > tier
 */
public class TierBasedModelSelectionDemo {

    public static void main(String[] args) {
        System.out.println("=== AI3Security 계층 기반 모델 선택 데모 ===\n");

        // 1. AnalysisLevel 기반 모델 선택
        demonstrateAnalysisLevelSelection();

        // 2. Tier 기반 모델 선택
        demonstrateTierSelection();

        // 3. PreferredModel 우선순위 시연
        demonstratePreferredModelPriority();

        // 4. SecurityTaskType 기반 선택 (UnifiedLLMOrchestrator에서 처리)
        demonstrateSecurityTaskType();

        // 5. 복합 시나리오
        demonstrateComplexScenario();
    }

    private static void demonstrateAnalysisLevelSelection() {
        System.out.println("1. AnalysisLevel 기반 모델 선택");
        System.out.println("-".repeat(50));

        // QUICK 분석
        ExecutionContext quickContext = ExecutionContext.forAnalysisLevel(
                AnalysisLevel.QUICK,
                new Prompt("Quick security check"));
        printContext(quickContext, "QUICK 분석");

        // NORMAL 분석
        ExecutionContext normalContext = ExecutionContext.forAnalysisLevel(
                AnalysisLevel.NORMAL,
                new Prompt("Normal security analysis"));
        printContext(normalContext, "NORMAL 분석");

        // DEEP 분석
        ExecutionContext deepContext = ExecutionContext.forAnalysisLevel(
                AnalysisLevel.DEEP,
                new Prompt("Deep security investigation"));
        printContext(deepContext, "DEEP 분석");

        System.out.println();
    }

    private static void demonstrateTierSelection() {
        System.out.println("2. Tier 기반 모델 선택");
        System.out.println("-".repeat(50));

        // Tier 1 (98% 트래픽)
        ExecutionContext tier1 = ExecutionContext.forTier(1, new Prompt("Layer 1 filtering"));
        printContext(tier1, "Tier 1 (Layer 1)");

        // Tier 2 (1.8% 트래픽)
        ExecutionContext tier2 = ExecutionContext.forTier(2, new Prompt("Layer 2 analysis"));
        printContext(tier2, "Tier 2 (Layer 2)");

        // Tier 3 (0.2% 트래픽)
        ExecutionContext tier3 = ExecutionContext.forTier(3, new Prompt("Layer 3 investigation"));
        printContext(tier3, "Tier 3 (Layer 3)");

        System.out.println();
    }

    private static void demonstratePreferredModelPriority() {
        System.out.println("3. PreferredModel 우선순위 (최우선)");
        System.out.println("-".repeat(50));

        ExecutionContext context = ExecutionContext.builder()
                .prompt(new Prompt("Custom model test"))
                .tier(1)  // Layer 1 설정
                .analysisLevel(AnalysisLevel.QUICK)  // QUICK 분석 설정
                .preferredModel("gpt-4")  // 명시적 모델 지정 (최우선)
                .build();

        System.out.println("설정: Tier=1, AnalysisLevel=QUICK, PreferredModel=gpt-4");
        System.out.println("결과:");
        System.out.println("  - Effective Tier: " + context.getEffectiveTier());
        System.out.println("  - Effective Model: " + context.getEffectiveModelName());
        System.out.println("  → preferredModel이 최우선으로 선택됨!");

        System.out.println();
    }

    private static void demonstrateSecurityTaskType() {
        System.out.println("4. SecurityTaskType 기반 선택");
        System.out.println("-".repeat(50));
        System.out.println("(UnifiedLLMOrchestrator의 determineOllamaModelName에서 처리)\n");

        // Layer 1 태스크
        ExecutionContext threatFiltering = ExecutionContext.builder()
                .prompt(new Prompt("Threat filtering"))
                .securityTaskType(SecurityTaskType.THREAT_FILTERING)
                .build();
        System.out.println("THREAT_FILTERING → tinyllama:latest (Layer 1)");

        // Layer 2 태스크
        ExecutionContext contextualAnalysis = ExecutionContext.builder()
                .prompt(new Prompt("Contextual analysis"))
                .securityTaskType(SecurityTaskType.CONTEXTUAL_ANALYSIS)
                .build();
        System.out.println("CONTEXTUAL_ANALYSIS → llama3.1:8b (Layer 2)");

        // Layer 3 태스크
        ExecutionContext expertInvestigation = ExecutionContext.builder()
                .prompt(new Prompt("Expert investigation"))
                .securityTaskType(SecurityTaskType.EXPERT_INVESTIGATION)
                .build();
        System.out.println("EXPERT_INVESTIGATION → llama3.1:8b (Layer 3)");

        System.out.println();
    }

    private static void demonstrateComplexScenario() {
        System.out.println("5. 복합 시나리오 - 실제 사용 예시");
        System.out.println("-".repeat(50));

        // 시나리오 1: 빠른 위협 필터링
        ExecutionContext scenario1 = ExecutionContext.builder()
                .prompt(new Prompt("Check if this request is malicious"))
                .analysisLevel(AnalysisLevel.QUICK)
                .securityTaskType(SecurityTaskType.THREAT_FILTERING)
                .requireFastResponse(true)
                .timeoutMs(50)
                .build();
        System.out.println("시나리오 1: 빠른 위협 필터링");
        printContext(scenario1, "");

        // 시나리오 2: 컨텍스트 기반 행동 분석
        ExecutionContext scenario2 = ExecutionContext.builder()
                .prompt(new Prompt("Analyze user behavior patterns"))
                .analysisLevel(AnalysisLevel.NORMAL)
                .securityTaskType(SecurityTaskType.BEHAVIOR_ANALYSIS)
                .timeoutMs(300)
                .build();
        System.out.println("\n시나리오 2: 컨텍스트 기반 행동 분석");
        printContext(scenario2, "");

        // 시나리오 3: 전문가 수준 인시던트 대응
        ExecutionContext scenario3 = ExecutionContext.builder()
                .prompt(new Prompt("Investigate security incident and recommend response"))
                .analysisLevel(AnalysisLevel.DEEP)
                .securityTaskType(SecurityTaskType.INCIDENT_RESPONSE)
                .toolExecutionEnabled(true)  // SOAR 도구 활성화
                .timeoutMs(5000)
                .build();
        System.out.println("\n시나리오 3: 전문가 수준 인시던트 대응");
        printContext(scenario3, "");
    }

    private static void printContext(ExecutionContext context, String label) {
        if (!label.isEmpty()) {
            System.out.println(label + ":");
        }
        System.out.println("  - AnalysisLevel: " + context.getAnalysisLevel());
        System.out.println("  - Tier: " + context.getTier());
        System.out.println("  - Effective Tier: " + context.getEffectiveTier());
        System.out.println("  - Effective Model: " + context.getEffectiveModelName());
        System.out.println("  - Timeout: " + context.getTimeoutMs() + "ms");
        System.out.println("  - Temperature: " + context.getTemperature());
        if (context.getSecurityTaskType() != null) {
            System.out.println("  - SecurityTaskType: " + context.getSecurityTaskType());
        }
        if (Boolean.TRUE.equals(context.getToolExecutionEnabled())) {
            System.out.println("  - Tool Execution: Enabled");
        }
    }
}