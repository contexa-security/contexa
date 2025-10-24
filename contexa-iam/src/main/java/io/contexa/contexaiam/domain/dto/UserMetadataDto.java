package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserMetadataDto {
    private Long id;
    private String username;
    private String name;
}
