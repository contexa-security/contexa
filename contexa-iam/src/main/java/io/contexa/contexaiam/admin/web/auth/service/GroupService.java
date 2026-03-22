package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Group;

import java.util.List;
import java.util.Optional;

public interface GroupService {
    Group createGroup(Group group, List<Long> selectedRoleIds);
    Optional<Group> getGroup(Long id);
    List<Group> getAllGroups();
    void deleteGroup(Long id);
    Group updateGroup(Group group, List<Long> selectedRoleIds);
    List<String> checkHierarchyWarnings(List<Long> roleIds);
}
