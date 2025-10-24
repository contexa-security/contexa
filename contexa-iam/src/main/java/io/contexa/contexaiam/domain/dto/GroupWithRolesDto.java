package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GroupWithRolesDto {
    private Long groupId;
    private String groupName;
    private String groupDescription;
    private List<RoleDetailDto> roles;
}

