package io.contexa.contexacore.autonomous.tiered.response;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

/**
 * Layer 1: 초고속 필터링 응답 모델
 *
 * Spring AI BeanOutputConverter를 위한 구조화된 응답
 * Layer 1에서 20-50ms 내에 처리되는 빠른 위협 필터링 결과
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Layer1SecurityResponse {

    private Double riskScore;

    private Double confidence;

    private String category;

    private String action;

    private String reasoning;

    private Double embeddingSimilarity;

    private String matchedPattern;

    private Boolean knownThreat;
}