package io.contexa.demo.scenario.dto;

import jakarta.validation.constraints.NotBlank;

public record ScenarioConditions(
        @NotBlank String provenance,
        @NotBlank String approval,
        @NotBlank String purpose,
        @NotBlank String scope,
        @NotBlank String pace,
        @NotBlank String evidenceAvailability,
        String untrustedDocumentText
) {

}
