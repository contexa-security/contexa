package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TargetDto {
    private String targetType;
    private String targetIdentifier;
    private String httpMethod;
    @Builder.Default
    private int targetOrder = 0;
    @Builder.Default
    private String sourceType = "RESOURCE";
} 