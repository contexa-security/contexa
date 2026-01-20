package io.contexa.contexaiam.admin.support.visualization.service;

import io.contexa.contexaiam.admin.support.visualization.dto.GraphDataDto;

public interface VisualizationService {
    
    GraphDataDto generatePermissionGraphForUser(Long userId);
}
