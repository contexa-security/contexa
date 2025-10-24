package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import java.util.Set;

public record SavePermissionsRequest(Set<Long> permissionIds) {}
