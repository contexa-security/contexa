package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BusinessActionDto {
    private Long id;
    private String name;
    private String actionType;
}
