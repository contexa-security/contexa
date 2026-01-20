package io.contexa.contexaiam.admin.web.workflow.wizard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


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