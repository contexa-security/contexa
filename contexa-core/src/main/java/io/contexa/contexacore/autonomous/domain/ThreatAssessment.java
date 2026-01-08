package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Threat Assessment
 *
 * 위협 평가 결과를 나타내는 도메인 객체
 *
 * v3.1.0 변경사항:
 * - threatLevel 필드 deprecated: riskScore + action으로 대체
 * - AI Native 원칙: LLM이 action을 직접 결정, 임계값 기반 판단 제거
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAssessment {

    private String assessmentId;
    private String eventId;

    private double riskScore;
    // AI Native v6.0: Dead Fields 정리
    // - threatType: setter 호출 코드 없음 (제거)
    // - description: AuditingHandler에서 setter 호출 (유지)
    private String description;
    private String evaluator;
    private LocalDateTime assessedAt;

    // 추가 평가 정보
    private List<String> indicators;
    // AI Native v6.0: tactics, techniques 제거 - setter 호출 코드 없음
    // AI Native v3.1: metadata 제거 - 죽은 필드 (설정 코드 없음)
    
    // 권장 조치
    private List<String> recommendedActions;
    // AI Native v3.0: mitigationStrategy 제거 - 죽은 필드 (설정 코드 없음)
    private String strategyName;
    // AI Native v3.0: priorityScore 제거 - 죽은 필드 (설정 코드 없음)

    // 평가 신뢰도
    private double confidence;
    // AI Native v3.0: confidenceReason 제거 - 죽은 필드 (설정 코드 없음)

    private String action;

    // AI Native: LLM이 에스컬레이션 필요 여부를 직접 결정
    // LLM이 현재 Layer에서 충분히 분석했다고 판단하면 false
    // LLM이 더 상위 Layer 분석이 필요하다고 판단하면 true
    @Builder.Default
    private boolean shouldEscalate = false;
    
    // AI Native v6.0: Dead Fields 제거
    // - frameworkMapping: 빈 Map 초기화만 있고 데이터 추가 없음 (제거)
    // - timestamp: assessedAt와 중복 (제거)

    // AI Native v3.1: 죽은 필드 제거
    // - patterns: 설정 코드 없음, 외부 호출 없음
    // - reason: SecurityDecision.reasoning과 중복
    
    /**
     * Get confidence score (alias for confidence field)
     */
    public double getConfidenceScore() {
        return confidence;
    }

}