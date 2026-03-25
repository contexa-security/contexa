package io.contexa.contexacore.autonomous.context;

import lombok.Builder;
import lombok.Value;

import java.util.List;

@Value
@Builder
public class ProtectableWorkProfileSnapshot {
    String tenantId;
    String userId;
    Integer observationCount;
    Integer windowDays;
    List<String> frequentProtectableResources;
    List<String> frequentActionFamilies;
    List<Integer> normalAccessHours;
    List<Integer> normalAccessDays;
    Double normalRequestRate;
    Double protectableInvocationDensity;
    List<String> protectableResourceHeatmap;
    List<String> frequentSensitiveResourceCategories;
    String normalReadWriteExportRatio;
    String summary;
    ContextTrustProfile trustProfile;
}
