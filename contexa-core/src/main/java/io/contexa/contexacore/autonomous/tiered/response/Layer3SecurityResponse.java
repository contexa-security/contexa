package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Layer 3: 전문가 분석 응답 모델
 *
 * Spring AI BeanOutputConverter를 위한 구조화된 응답
 * Layer 3에서 1-5초 내에 처리되는 전문가 수준의 위협 분석 결과
 *
 * Layer3ExpertStrategy의 기존 private static class SecurityDecisionResponse를 대체
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Layer3SecurityResponse {

    private Double riskScore;

    private Double confidence;

    private String action;

    private String classification;

    private String scenario;

    private String stage;

    private List<String> tactics;

    private List<String> techniques;

    private List<String> iocIndicators;

    private String threatActor;

    private String campaignId;

    private String businessImpact;

    private String playbookId;

    private Boolean requiresApproval;

    private String reasoning;

    private String expertRecommendation;

    private Map<String, Object> mitreMapping;
}