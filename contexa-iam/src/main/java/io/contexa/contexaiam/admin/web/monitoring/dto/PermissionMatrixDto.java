package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;
import java.util.Map;


public record PermissionMatrixDto(
        List<String> subjects, 
        List<String> permissions, 
        Map<String, Map<String, String>> matrixData 
) {}
