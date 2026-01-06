package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

/**
 * Layer 2: 전문가 분석 응답 모델
 *
 * AI Native v5.1.0: LLM이 실제로 반환하는 필드만 유지
 * 프롬프트 응답 형식:
 * {"riskScore", "confidence", "action", "reasoning", "mitre", "recommendation"}
 *
 * 삭제된 필드 (프롬프트에서 요청하지 않음):
 * - classification, scenario, stage: LLM 응답에 없음
 * - tactics, techniques, iocIndicators: MITRE 상세 분석 불필요 (mitre 문자열로 충분)
 * - threatActor, campaignId: 익명 공격자 탐지용 (플랫폼 역할 아님)
 * - businessImpact, playbookId, requiresApproval: 프롬프트에서 요청 안함
 * - expertRecommendation: recommendation으로 통합
 * - mitreMapping: mitre 문자열로 충분
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Layer2SecurityResponse {

    /**
     * 위험 점수 (0.0 ~ 1.0)
     */
    private Double riskScore;

    /**
     * 신뢰도 (0.0 ~ 1.0)
     */
    private Double confidence;

    /**
     * 액션 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     */
    private String action;

    /**
     * 분석 근거 (max 50 tokens)
     */
    private String reasoning;

    /**
     * MITRE ATT&CK 기법 (예: T1078, T1566)
     */
    private String mitre;

    /**
     * SOC 권고사항 (max 20 tokens)
     */
    private String recommendation;
}
