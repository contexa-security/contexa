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
/**
 * Field-level evidence lineage and coverage metadata. This record packages provenance and evidence
 * sufficiency only; it is not a semantic legitimacy, abuse, or intent verdict.
 */
public class ContextFieldTrustRecord {

    private String fieldPath;

    private String semanticMeaning;

    private String intendedUse;

    private String provenanceSummary;

    private Integer observationCount;

    private Integer daysCovered;

    private Double fallbackRate;

    private Double unknownRate;

    /**
     * Audit-only evidence sufficiency grade. Never expose this as a semantic conclusion.
     */
    private ContextQualityGrade qualityGrade;

    /**
     * Audit-only evidence sufficiency score. Never expose this as a semantic conclusion.
     */
    private Integer qualityScore;

    private String qualitySummary;

    @Builder.Default
    private List<String> sourceKeys = new ArrayList<>();

    @Builder.Default
    private List<String> fallbackSourceKeys = new ArrayList<>();

    @Builder.Default
    private List<String> evidenceIds = new ArrayList<>();
}
