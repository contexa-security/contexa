package io.contexa.contexaiam.admin.web.center.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ConditionTemplateDto {
    private Long id;
    private String name;
    private String description;
    private String category;
}
