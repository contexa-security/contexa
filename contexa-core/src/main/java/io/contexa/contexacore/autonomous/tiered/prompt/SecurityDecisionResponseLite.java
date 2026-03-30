package io.contexa.contexacore.autonomous.tiered.prompt;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class SecurityDecisionResponseLite {

    private Double riskScore;
    private Double confidence;
    private String action;
    private String reasoning;
    private String mitre;
}
