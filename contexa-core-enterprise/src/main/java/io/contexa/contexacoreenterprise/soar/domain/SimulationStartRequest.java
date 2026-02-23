package io.contexa.contexacoreenterprise.soar.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SimulationStartRequest {
    private String incidentId;
    private String threatType;
    private String description;
    private List<String> affectedAssets;
    private String detectedSource;
    private String severity;
    private String organizationId;
    private String userQuery;
    private String executionMode;
    private Map<String, Object> metadata;
}
