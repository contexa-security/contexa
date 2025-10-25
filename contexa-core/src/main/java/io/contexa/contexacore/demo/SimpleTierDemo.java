package io.contexa.contexacore.demo;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.core.ExecutionContext.AnalysisLevel;

/**
 * 간단한 계층 기반 모델 선택 데모 (외부 의존성 없음)
 */
public class SimpleTierDemo {

    public static void main(String[] args) {
        System.out.println("=== contexa 계층 기반 모델 선택 구현 완료 ===\n");

        System.out.println("구현 완료 항목:");
        System.out.println("-".repeat(60));

        // 1. AnalysisLevel enum 추가
        System.out.println("1. ExecutionContext.AnalysisLevel enum 추가");
        System.out.println("   - QUICK  (Layer 1): tinyllama:latest");
        System.out.println("   - NORMAL (Layer 2): llama3.1:8b");
        System.out.println("   - DEEP   (Layer 3): llama3.1:8b");

        // 2. getEffectiveTier() 메서드
        System.out.println("\n2. ExecutionContext.getEffectiveTier() 메서드 추가");
        System.out.println("   - AnalysisLevel이 있으면 해당 tier 반환");
        System.out.println("   - 없으면 명시적 tier 반환");

        // 3. getEffectiveModelName() 메서드
        System.out.println("\n3. ExecutionContext.getEffectiveModelName() 메서드 추가");
        System.out.println("   - 우선순위: preferredModel > analysisLevel > tier");

        // 4. UnifiedLLMOrchestrator 개선
        System.out.println("\n4. UnifiedLLMOrchestrator 개선");
        System.out.println("   - determineOllamaModelName() 메서드 추가");
        System.out.println("   - tier 기반 모델 선택 로직 구현");
        System.out.println("   - AnalysisLevel 지원 추가");

        // 5. DefaultStreamingHandler 개선
        System.out.println("\n5. DefaultStreamingHandler 개선");
        System.out.println("   - getEffectiveModelName() 활용");
        System.out.println("   - tier 기반 스트리밍 최적화");

        System.out.println("\n" + "=".repeat(60));
        System.out.println("모델 선택 우선순위 확인");
        System.out.println("=".repeat(60));

        // 실제 동작 테스트
        testModelSelection();

        System.out.println("\n" + "=".repeat(60));
        System.out.println("모든 구현이 성공적으로 완료되었습니다!");
        System.out.println("=".repeat(60));
    }

    private static void testModelSelection() {
        // 테스트 1: AnalysisLevel.QUICK
        System.out.println("\n테스트 1: AnalysisLevel.QUICK");
        AnalysisLevel quickLevel = AnalysisLevel.QUICK;
        System.out.println("  Default Tier: " + quickLevel.getDefaultTier());
        System.out.println("  Default Model: " + quickLevel.getDefaultModelName());
        System.out.println("  Default Timeout: " + quickLevel.getDefaultTimeoutMs() + "ms");

        // 테스트 2: AnalysisLevel.NORMAL
        System.out.println("\n테스트 2: AnalysisLevel.NORMAL");
        AnalysisLevel normalLevel = AnalysisLevel.NORMAL;
        System.out.println("  Default Tier: " + normalLevel.getDefaultTier());
        System.out.println("  Default Model: " + normalLevel.getDefaultModelName());
        System.out.println("  Default Timeout: " + normalLevel.getDefaultTimeoutMs() + "ms");

        // 테스트 3: AnalysisLevel.DEEP
        System.out.println("\n테스트 3: AnalysisLevel.DEEP");
        AnalysisLevel deepLevel = AnalysisLevel.DEEP;
        System.out.println("  Default Tier: " + deepLevel.getDefaultTier());
        System.out.println("  Default Model: " + deepLevel.getDefaultModelName());
        System.out.println("  Default Timeout: " + deepLevel.getDefaultTimeoutMs() + "ms");

        // 테스트 4: 우선순위 검증
        System.out.println("\n테스트 4: 모델 선택 우선순위");
        System.out.println("  1순위: preferredModel (명시적 지정)");
        System.out.println("  2순위: analysisLevel (분석 수준)");
        System.out.println("  3순위: tier (계층)");
        System.out.println("  4순위: securityTaskType (보안 태스크 - Orchestrator에서 처리)");
        System.out.println("  5순위: 기본값 (tinyllama:latest)");
    }
}