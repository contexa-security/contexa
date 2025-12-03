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
     * AI Native 헬퍼 메서드
     *
     * NaN 처리 전략 (보수적 접근):
     * - NaN = LLM 판단 불가 → 고위험으로 간주
     * - action 기반 판단 우선 (riskScore는 참고용)
     */
    public boolean isHighRisk() {
        // AI Native: NaN이면 보수적으로 고위험 간주
        if (Double.isNaN(riskScore)) {
            return true;
        }
        // AI Native: action 기반 판단 우선
        if (action == Action.BLOCK || action == Action.MITIGATE) {
            return true;
        }
        // riskScore는 참고용으로만 사용 (감사 로그, 모니터링)
        return riskScore >= 0.7;
    }

    public boolean isMediumRisk() {
        // AI Native: NaN이면 보수적으로 고위험 간주 (isMediumRisk는 false)
        if (Double.isNaN(riskScore)) {
            return false;
        }
        return riskScore >= 0.5 && riskScore < 0.7;
    }

    public boolean isLowRisk() {
        // AI Native: NaN이면 보수적으로 고위험 간주 (isLowRisk는 false)
        if (Double.isNaN(riskScore)) {
            return false;
        }
        // AI Native: ALLOW action이면 저위험
        if (action == Action.ALLOW) {
            return true;
        }
        return riskScore < 0.5;
    }

    public boolean shouldBlock() {
        // AI Native: NaN이면 Fail-Safe로 차단
        if (Double.isNaN(riskScore) || action == null) {
            return true;
        }
        // AI Native: LLM action 기반 판단
        return action == Action.BLOCK;
    }

    public boolean shouldEscalate() {
        return action == Action.ESCALATE;
    }

    public boolean isConfident() {
        // AI Native: NaN이면 저신뢰도
        if (Double.isNaN(confidence)) {
            return false;
        }
        return confidence >= 0.8;
    }
    
    /**
     * Layer 2로의 에스컬레이션 필요 여부
     *
     * AI Native 원칙:
     * - LLM이 ESCALATE action을 직접 결정
     * - NaN = LLM 판단 불가 → 에스컬레이션 (보수적)
     */
    public boolean needsLayer2Escalation() {
        // AI Native: NaN이면 에스컬레이션 (LLM 판단 불가)
        if (Double.isNaN(riskScore) || Double.isNaN(confidence)) {
            return true;
        }

        // AI Native: LLM이 ESCALATE를 직접 결정
        boolean explicitEscalation = (action == Action.ESCALATE && processingLayer == 1);

        // riskScore 기반 조건은 참고용으로만 유지
        boolean highRisk = riskScore >= 0.7 && riskScore < 0.8;
        boolean uncertainButRisky = (riskScore >= 0.5 && riskScore < 0.7 &&
                                     confidence >= 0.3 && confidence < 0.5);

        return explicitEscalation || highRisk || uncertainButRisky;
    }

    /**
     * Layer 3로의 에스컬레이션 필요 여부
     *
     * AI Native 원칙:
     * - NaN = LLM 판단 불가 → Layer3 에스컬레이션 (전문가 분석 필요)
     * - LLM이 ESCALATE action을 직접 결정
     * - riskScore 기반 조건은 참고용으로 유지
     */
    public boolean needsLayer3Escalation() {
        // AI Native: NaN이면 Layer3 에스컬레이션 (전문가 분석 필요)
        if (Double.isNaN(riskScore) || Double.isNaN(confidence)) {
            return true;
        }

        // AI Native: Layer2의 명시적 에스컬레이션 (LLM 직접 결정)
        boolean layer2Escalation = (action == Action.ESCALATE && processingLayer == 2);

        // 승인 필요 플래그 (LLM이 설정)
        boolean requiresExpert = requiresApproval;

        // riskScore 기반 조건은 참고용으로만 유지
        boolean criticalRisk = riskScore >= 0.8 && confidence >= 0.7;

        return layer2Escalation || requiresExpert || criticalRisk;
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