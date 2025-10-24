package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Layer 2: 컨텍스트 분석 응답 모델
 *
 * Spring AI BeanOutputConverter를 위한 구조화된 응답
 * Layer 2에서 100-300ms 내에 처리되는 컨텍스트 기반 위협 분석 결과
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Layer2SecurityResponse {

    private Double riskScore;

    private Double confidence;

    private String action;

    private String reasoning;

    private List<String> behaviorPatterns;

    private String threatCategory;

    private List<String> mitigationActions;

    private Map<String, Object> sessionAnalysis;

    private List<String> relatedEvents;

    private String recommendation;
}