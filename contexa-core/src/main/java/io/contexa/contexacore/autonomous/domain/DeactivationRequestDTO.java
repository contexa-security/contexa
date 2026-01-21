package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeactivationRequestDTO {
    
    @NotBlank(message = "Deactivated by is required")
    private String deactivatedBy;
    
    @NotBlank(message = "Reason is required")
    private String reason;
}