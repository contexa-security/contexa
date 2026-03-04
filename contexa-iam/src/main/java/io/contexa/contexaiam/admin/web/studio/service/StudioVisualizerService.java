package io.contexa.contexaiam.admin.web.studio.service;

import io.contexa.contexaiam.admin.web.studio.dto.AccessPathDto;
import io.contexa.contexaiam.admin.web.studio.dto.EffectivePermissionDto;
import io.contexa.contexaiam.admin.support.context.dto.GraphDataDto;

import io.contexa.contexaiam.admin.web.workflow.wizard.dto.VirtualSubject;

import java.util.List;
import java.util.Map;

public interface StudioVisualizerService {

    AccessPathDto analyzeAccessPath(Long subjectId, String subjectType, Long permissionId);

    GraphDataDto analyzeAccessPathAsGraph(Long subjectId, String subjectType, Long permissionId);

    List<EffectivePermissionDto> getEffectivePermissionsForSubject(Long subjectId, String subjectType);

    List<EffectivePermissionDto> getEffectivePermissionsForSubject(VirtualSubject subject);

    Map<String, Object> getSubjectDetails(Long subjectId, String subjectType);

}