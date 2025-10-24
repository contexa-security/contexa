package io.contexa.contexacore.autonomous.tiered;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * 보안 결정 도메인 객체
 * 
 * 각 계층에서 생성되는 보안 분석 결과를 담는 통합 객체입니다.
 * Layer 1, 2, 3 모두에서 사용되며, 계층이 올라갈수록 더 상세한 정보가 추가됩니다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityDecision {
    
    /**
     * 보안 액션
     */
    public enum Action {
        ALLOW,           // 허용
        BLOCK,           // 차단
        MONITOR,         // 모니터링
        ESCALATE,        // 상위 계층으로 에스컬레이션
        MITIGATE,        // 완화 조치
        INVESTIGATE      // 조사 필요
    }
    
    /**
     * 기본 필드 (모든 계층에서 사용)
     */
    private Action action;                    // 보안 액션
    private double riskScore;                 // 위험 점수 (0.0 - 1.0) - 모든 Layer 통일
    private double confidence;                // 신뢰도 (0.0 - 1.0)
    private long analysisTime;                // 분석 시작 시간 (timestamp)
    private long processingTimeMs;            // 처리 시간 (milliseconds)
    private int processingLayer;              // 처리된 계층 (1, 2, 3)
    
    /**
     * Layer 1 추가 필드
     */
    private Double embeddingSimilarity;       // 임베딩 유사도 (0.0 - 1.0)
    private String matchedPattern;            // 매칭된 패턴
    private boolean knownThreat;              // 알려진 위협 여부
    private String llmModel;                  // 사용된 LLM 모델
    private String layer;                     // 처리 계층 정보 (Layer1, Layer2, Layer3)
    private String modelUsed;                 // 사용된 모델명

    /**
     * Layer 2 추가 필드
     */
    private Map<String, Object> sessionContext;    // 세션 컨텍스트
    private List<String> behaviorPatterns;        // 행동 패턴
    private String threatCategory;                 // 위협 카테고리
    private List<String> mitigationActions;       // 완화 조치 목록
    private String reasoning;                      // AI 추론 과정
    
    /**
     * Layer 3 추가 필드
     */
    private String attackScenario;                 // 공격 시나리오 설명
    private String businessImpact;                 // 비즈니스 영향
    private List<String> iocIndicators;            // IOC (Indicators of Compromise)
    private Map<String, String> mitreMapping;      // MITRE ATT&CK 매핑
    private String soarPlaybook;                   // SOAR 플레이북
    private boolean requiresApproval;              // 승인 필요 여부
    private String expertRecommendation;           // 전문가 권장사항
    
    /**
     * 메타데이터
     */
    private String eventId;                        // 원본 이벤트 ID
    private String analysisId;                     // 분석 ID
    private Map<String, Object> metadata;          // 추가 메타데이터
    private Map<String, Object> analysisMetadata;  // 분석 메타데이터
    
    /**
     * 헬퍼 메서드
     */
    public boolean isHighRisk() {
        return riskScore >= 0.7;
    }

    public boolean isMediumRisk() {
        return riskScore >= 0.5 && riskScore < 0.7;
    }

    public boolean isLowRisk() {
        return riskScore < 0.5;
    }

    public boolean shouldBlock() {
        return action == Action.BLOCK || (action == Action.MITIGATE && riskScore >= 0.8);
    }
    
    public boolean shouldEscalate() {
        return action == Action.ESCALATE;
    }
    
    public boolean isConfident() {
        return confidence >= 0.8;
    }
    
    /**
     * Layer 2로의 에스컬레이션 필요 여부
     *
     * 개선된 에스컬레이션 기준:
     * 1. 명확한 위험도 기준: riskScore 0.7 ~ 0.8 (Cold Path 진입 기준과 일치)
     * 2. Layer1의 명시적 에스컬레이션: ESCALATE action + 최소 신뢰도 0.6
     * 3. 불확실하지만 위험 가능성: riskScore 0.5+ && confidence 0.3~0.5
     *
     * 신중한 접근:
     * - confidence < 0.3은 Layer1 재분석 필요 (에스컬레이션 불가)
     * - confidence >= 0.6 필요 (무분별한 전가 방지)
     */
    public boolean needsLayer2Escalation() {
        // 1. 명확한 위험도 기준 (Cold Path 진입 기준과 일치)
        boolean highRisk = riskScore >= 0.7 && riskScore < 0.8;

        // 2. Layer1의 신중한 명시적 에스컬레이션
        boolean explicitEscalation = (action == Action.ESCALATE &&
                                      confidence >= 0.6 &&
                                      processingLayer == 1);

        // 3. 불확실성이 높지만 위험 가능성 있음
        boolean uncertainButRisky = (riskScore >= 0.5 &&
                                     riskScore < 0.7 &&
                                     confidence >= 0.3 &&
                                     confidence < 0.5);

        return highRisk || explicitEscalation || uncertainButRisky;
    }

    /**
     * Layer 3로의 에스컬레이션 필요 여부
     *
     * 개선된 에스컬레이션 기준:
     * 1. 고위험 확실: riskScore >= 0.8 + confidence >= 0.7
     * 2. Layer2의 명시적 에스컬레이션: ESCALATE + confidence >= 0.6
     * 3. 전문가 분석 필요: 승인 필요 또는 미지의 고위험 패턴
     */
    public boolean needsLayer3Escalation() {
        // 1. 고위험 확실 (Cold Path 최상위)
        boolean criticalRisk = riskScore >= 0.8 && confidence >= 0.7;

        // 2. Layer2의 신중한 명시적 에스컬레이션
        boolean layer2Escalation = (action == Action.ESCALATE &&
                                    processingLayer == 2 &&
                                    confidence >= 0.6);

        // 3. 승인 필요 또는 미지의 패턴 (전문가 분석 필수)
        boolean requiresExpert = requiresApproval ||
                                 (riskScore >= 0.75 && confidence < 0.4);

        return criticalRisk || layer2Escalation || requiresExpert;
    }
    
    /**
     * 처리 시간 계산
     */
    public void calculateProcessingTime() {
        if (analysisTime > 0) {
            this.processingTimeMs = System.currentTimeMillis() - analysisTime;
        }
    }
    
    /**
     * 정적 빌더 메서드 - 허용 결정
     */
    public static SecurityDecision allow(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.ALLOW)
                .riskScore(riskScore)
                .confidence(0.9)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
    
    /**
     * 정적 빌더 메서드 - 차단 결정
     */
    public static SecurityDecision block(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.BLOCK)
                .riskScore(riskScore)
                .confidence(0.9)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
    
    /**
     * 정적 빌더 메서드 - 에스컬레이션 결정
     */
    public static SecurityDecision escalate(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.ESCALATE)
                .riskScore(riskScore)
                .confidence(0.6)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
}