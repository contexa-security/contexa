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
public class RoleDto{
    private Long id;
    private String roleName;
    private String roleDesc;
    private boolean isExpression;
    private List<Long> permissionIds;
    private int permissionCount;
}
