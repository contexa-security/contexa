package io.contexa.contexaiam.admin.web.studio.dto;

import java.util.List;

public record PolicyImpactDto(List<ExplorerItemDto> affectedSubjects, List<ExplorerItemDto> affectedResources) {}
