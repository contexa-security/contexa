package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.monitoring.dto.MatrixFilter;
import io.contexa.contexaiam.admin.web.monitoring.dto.PermissionMatrixDto;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.repository.GroupRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class PermissionMatrixServiceImpl implements PermissionMatrixService {

    private final GroupRepository groupRepository;
    private final PermissionCatalogService permissionCatalogService;

    @Override
    @Transactional(readOnly = true)
    public PermissionMatrixDto getPermissionMatrix() {
        return getPermissionMatrix(new MatrixFilter(null, null, null));
    }

    @Override
    @Transactional(readOnly = true)
    public PermissionMatrixDto getPermissionMatrix(MatrixFilter filter) {
        List<Group> subjects = (filter != null && !CollectionUtils.isEmpty(filter.subjectIds()))
                ? groupRepository.findAllById(filter.subjectIds())
                : groupRepository.findAllWithRolesAndPermissions();

        List<PermissionDto> permissions = permissionCatalogService.getAvailablePermissions();

        List<String> subjectNames = subjects.stream().map(Group::getName).collect(Collectors.toList());
        List<String> permissionDescriptions = permissions.stream().map(PermissionDto::getFriendlyName).collect(Collectors.toList());

        Map<String, Map<String, String>> matrixData = new HashMap<>();
        for (Group group : subjects) {
            Map<String, String> rowData = new HashMap<>();
            Set<String> groupPermissions = group.getGroupRoles().stream()
                    .flatMap(gr -> gr.getRole().getRolePermissions().stream())
                    .map(rp -> rp.getPermission().getFriendlyName())
                    .collect(Collectors.toSet());

            for (PermissionDto perm : permissions) {
                rowData.put(perm.getFriendlyName(), groupPermissions.contains(perm.getFriendlyName()) ? "GRANT" : "NONE");
            }
            matrixData.put(group.getName(), rowData);
        }

        return new PermissionMatrixDto(subjectNames, permissionDescriptions, matrixData);
    }
}
