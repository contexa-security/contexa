package io.contexa.contexaiam.admin.web.studio.dto;

import java.util.List;

public record SimulationResultDto(
        String summary, 
        List<ImpactDetail> impactDetails 
) {
    public record ImpactDetail(
            String subjectName,    
            String subjectType,
            String permissionName, 
            String permissionDescription,
            ImpactType impactType, 
            String reason          
    ) {}

    public enum ImpactType {
        PERMISSION_GAINED,
        PERMISSION_LOST
    }
}