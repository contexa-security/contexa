package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GroupDto {
    private Long id;
    private String name;
    private String description;
    private List<Long> selectedRoleIds;
    private int roleCount;
    private int userCount;
    private List<RoleDto> roles;
//    private Set<UserGroup> userGroups = new HashSet<>();
//    private Set<GroupRole> groupRoles = new HashSet<>();
}
