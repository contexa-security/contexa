package io.contexa.contexacore.autonomous.context.collector;

import lombok.Builder;
import lombok.Value;

import java.util.List;
import io.contexa.contexacore.autonomous.context.collector.ContextSnapshot;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

@Value
@Builder
public class ProtectableWorkProfileSnapshot implements ContextSnapshot {
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
