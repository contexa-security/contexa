package io.contexa.contexaiam.admin.web.center.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Data
@Builder
public class PolicySummaryDto {
    private Long id;
    private String name;
    private String effect;
    private Set<Long> roleIds;
    private Set<Long> permissionIds;
}
