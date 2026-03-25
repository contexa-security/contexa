package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.autonomous.domain.SecurityResponse;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class SecurityDecisionResponse extends AIResponse {

    private Double riskScore;
    private Double confidence;
    private String action;
    private String reasoning;
    private String mitre;

    public SecurityResponse toSecurityResponse() {
        return SecurityResponse.builder()
                .riskScore(riskScore)
                .confidence(confidence)
                .action(action)
                .reasoning(reasoning)
                .mitre(mitre)
                .build();
    }

    public static SecurityDecisionResponse fromSecurityResponse(SecurityResponse response) {
        SecurityDecisionResponse decisionResponse = new SecurityDecisionResponse();
        if (response == null) {
            return decisionResponse;
        }
        decisionResponse.setRiskScore(response.getRiskScore());
        decisionResponse.setConfidence(response.getConfidence());
        decisionResponse.setAction(response.getAction());
        decisionResponse.setReasoning(response.getReasoning());
        decisionResponse.setMitre(response.getMitre());
        return decisionResponse;
    }
}
