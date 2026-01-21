package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.Map;
import java.util.Set;

public record SimulationContext(
        Set<Long> userIds, 
        Set<Long> permissionIds, 
        Map<String, Object> environmentAttributes 
) {}
