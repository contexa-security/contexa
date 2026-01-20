package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.Set;


public record PolicyContext(
        String userDepartment,
        Set<String> userRoles
) {}
