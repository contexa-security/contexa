package io.contexa.contexacore.autonomous.context.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import io.contexa.contexacore.autonomous.context.model.ContextEvidenceRecord;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContextTrustProfile {

    private String profileKey;

    private String collectorId;

    private String summary;

    private String provenanceSummary;

    private ContextQualityGrade overallQualityGrade;

    private Integer overallQualityScore;

    @Builder.Default
    private List<String> scopeLimitations = new ArrayList<>();

    @Builder.Default
    private List<String> qualityWarnings = new ArrayList<>();

    @Builder.Default
    private List<ContextFieldTrustRecord> fieldRecords = new ArrayList<>();

    @Builder.Default
    private List<ContextEvidenceRecord> evidenceRecords = new ArrayList<>();
}
