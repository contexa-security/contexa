package io.contexa.contexaiam.admin.web.studio.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;


@Data
@NoArgsConstructor
public class InitiateGrantRequestDto {
    private Set<Long> userIds;
    private Set<Long> groupIds;
    private Set<Long> permissionIds;
}