package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RoleMetadataDto {
    private Long id;
    private String roleName;
    private String roleDesc;
}