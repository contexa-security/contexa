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
     * Action 기반 판단 (점수 기반 메서드 제거):
     * - isHighRisk(), isMediumRisk(), isLowRisk() 제거
     * - Action(BLOCK/MITIGATE/ESCALATE/ALLOW)으로만 판단
     * - riskScore는 메타데이터(감사 로그, 모니터링)용
     */
    public boolean shouldBlock() {
        // AI Native: action이 null이면 Fail-Safe로 차단
        if (action == null) {
            return true;
        }
        // AI Native: LLM action 기반 판단 (riskScore 불사용)
        return action == Action.BLOCK;
    }

    public boolean shouldEscalate() {
        return action == Action.ESCALATE;
    }

    public boolean isConfident() {
        // AI Native: 임계값 기반 판단 제거
        // 플랫폼은 confidence 값의 존재 여부만 확인
        // LLM이 confidence 값을 해석하여 신뢰도를 직접 판단
        return !Double.isNaN(confidence);
    }

    // AI Native: needsLayer2Escalation(), needsLayer3Escalation() 제거
    // - 임계값 기반 에스컬레이션 판단은 AI Native 원칙 위반
    // - 각 Layer 전략에서 action == Action.ESCALATE로 직접 판단
    // - Dead Code (호출처 0개)

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
     *
     * AI Native: confidence를 NaN으로 설정
     * - 플랫폼이 신뢰도를 결정하지 않음
     * - LLM이 직접 confidence 값을 설정해야 함
     */
    public static SecurityDecision allow(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.ALLOW)
                .riskScore(riskScore)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
    
    /**
     * 정적 빌더 메서드 - 차단 결정
     *
     * AI Native: confidence를 NaN으로 설정
     * - 플랫폼이 신뢰도를 결정하지 않음
     * - LLM이 직접 confidence 값을 설정해야 함
     */
    public static SecurityDecision block(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.BLOCK)
                .riskScore(riskScore)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
    
    /**
     * 정적 빌더 메서드 - 에스컬레이션 결정
     *
     * AI Native: confidence를 NaN으로 설정
     * - 플랫폼이 신뢰도를 결정하지 않음
     * - LLM이 직접 confidence 값을 설정해야 함
     */
    public static SecurityDecision escalate(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.ESCALATE)
                .riskScore(riskScore)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
}