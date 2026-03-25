package io.contexa.contexacore.autonomous.context;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContextFieldTrustRecord {

    private String fieldPath;

    private String semanticMeaning;

    private String intendedUse;

    private String provenanceSummary;

    private Integer observationCount;

    private Integer daysCovered;

    private Double fallbackRate;

    private Double unknownRate;

    private ContextQualityGrade qualityGrade;

    private Integer qualityScore;

    private String qualitySummary;

    @Builder.Default
    private List<String> sourceKeys = new ArrayList<>();

    @Builder.Default
    private List<String> fallbackSourceKeys = new ArrayList<>();

    @Builder.Default
    private List<String> evidenceIds = new ArrayList<>();
}
