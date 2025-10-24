package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 권한 할당 정보
 * SRP 준수: 할당 정보만 담당
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Assignment {
    @NotNull
    private Long targetId;
    @NotBlank
    private String targetType;
    private LocalDateTime validUntil;
} 