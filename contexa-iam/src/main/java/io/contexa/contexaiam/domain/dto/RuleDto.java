package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * 정책 규칙 DTO
 * SRP 준수: 정책 규칙 데이터만 담당
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RuleDto {
    private String description;

    @Builder.Default
    private List<ConditionDto> conditions = new ArrayList<>();
} 