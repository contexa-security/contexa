package io.contexa.contexacore.verification.runtime;

import java.util.List;

public class OfficialVerificationScenarioCatalog {

    public List<OfficialVerificationScenarioDefinition> scenarios(
            boolean eirReady,
            boolean ccrReady,
            boolean ccsrReady,
            boolean pfrReady,
            boolean mtrReady,
            boolean corReady,
            boolean rapReady,
            boolean rpiReady,
            boolean bmaReady,
            boolean usnsReady,
            boolean bsrReady,
            boolean cdcReady,
            boolean eraReady,
            boolean suhrReady,
            boolean preReady
    ) {
        return List.of(
                new OfficialVerificationScenarioDefinition("EIR", "Event Integrity Rate", "OFFICIAL_RUNTIME_EIR", eirReady, "Calls the protected enterprise probe and verifies that request, event, prompt, and decision linkage stay aligned."),
                new OfficialVerificationScenarioDefinition("CCR", "Context Completeness Rate", "OFFICIAL_RUNTIME_CCR", ccrReady, "Reads enterprise evidence and verifies that required session, behavior, retrieval, and prompt fields are populated."),
                new OfficialVerificationScenarioDefinition("CCSR", "Context Consistency and Synchronization Rate", "OFFICIAL_RUNTIME_CCSR", ccsrReady, "Verifies that request, event, prompt, and decision facts remain consistent across the enterprise evidence path."),
                new OfficialVerificationScenarioDefinition("PFR", "Prompt Fidelity Rate", "OFFICIAL_RUNTIME_PFR", pfrReady, "Verifies that prompt telemetry remains complete, traceable, and synchronized across the enterprise evidence path."),
                new OfficialVerificationScenarioDefinition("MTR", "Metadata Traceability Rate", "OFFICIAL_RUNTIME_MTR", mtrReady, "Verifies that requestId, evidence, and prompt governance linkage remain traceable end-to-end across the enterprise evidence path."),
                new OfficialVerificationScenarioDefinition("CoR", "Context Contamination Rate", "OFFICIAL_RUNTIME_COR", corReady, "Verifies that foreign-user, wrong-purpose, and unauthorized-scope documents never contaminate the enterprise context path."),
                new OfficialVerificationScenarioDefinition("RAP", "RAG Authorization Precision", "OFFICIAL_RUNTIME_RAP", rapReady, "Verifies that only authorized retrieved documents survive into the final enterprise prompt context."),
                new OfficialVerificationScenarioDefinition("RPI", "Round Progression Integrity", "OFFICIAL_RUNTIME_RPI", rpiReady, "Verifies that repeated enterprise rounds accumulate retrieval and baseline evidence without regression."),
                new OfficialVerificationScenarioDefinition("BMA", "Baseline Maturity Accuracy", "OFFICIAL_RUNTIME_BMA", bmaReady, "Verifies that baseline evidence starts provisional and matures into observed work pattern context across repeated enterprise rounds."),
                new OfficialVerificationScenarioDefinition("USNS", "User-Specific Novelty Sensitivity", "OFFICIAL_RUNTIME_USNS", usnsReady, "Verifies that user-specific novelty remains visible even when device and network signals stay stable across enterprise rounds."),
                new OfficialVerificationScenarioDefinition("BSR", "Behavioral Surprise Resolution", "OFFICIAL_RUNTIME_BSR", bsrReady, "Verifies that anomaly and recovery rounds preserve sequence history, cadence evidence, and observed work pattern context."),
                new OfficialVerificationScenarioDefinition("CDC", "Context-to-Decision Calibration", "OFFICIAL_RUNTIME_CDC", cdcReady, "Replays long-horizon decision scenarios and verifies that confidence, action, and risk remain calibrated to enterprise context quality."),
                new OfficialVerificationScenarioDefinition("ERA", "Evidence-Reason Alignment", "OFFICIAL_RUNTIME_ERA", eraReady, "Replays decision scenarios and verifies that reasoning claims remain grounded in evidence and prompt lineage."),
                new OfficialVerificationScenarioDefinition("SUHR", "Safe-Uncertainty Handling Rate", "OFFICIAL_RUNTIME_SUHR", suhrReady, "Replays ambiguity-heavy decision scenarios and verifies that uncertain cases resolve through safe challenge or escalation paths."),
                new OfficialVerificationScenarioDefinition("PRE", "Protectable Resource Eligibility", "OFFICIAL_RUNTIME_PRE", preReady, "Verifies that a target URL has @Protectable resource metadata and can receive a prompt quality certificate before Zero Trust enablement.")
        );
    }
}
