package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.Set;


public record MatrixFilter(Set<Long> subjectIds, Set<Long> permissionIds, String subjectType) {}