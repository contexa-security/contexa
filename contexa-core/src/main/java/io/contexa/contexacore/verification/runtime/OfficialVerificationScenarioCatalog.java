package io.contexa.contexacore.verification.runtime;

import java.util.ArrayList;
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
            boolean preReady
    ) {
        List<OfficialVerificationScenarioDefinition> scenarios = new ArrayList<>();
        scenarios.add(new OfficialVerificationScenarioDefinition("EIR", "Event Integrity Rate", "OFFICIAL_RUNTIME_EIR", eirReady, "Calls the protected enterprise probe and verifies that request, event, prompt, and decision linkage stay aligned."));
        scenarios.add(new OfficialVerificationScenarioDefinition("CCR", "Context Completeness Rate", "OFFICIAL_RUNTIME_CCR", ccrReady, "Reads enterprise evidence and verifies that required session, behavior, retrieval, and prompt fields are populated."));
        scenarios.add(new OfficialVerificationScenarioDefinition("CCSR", "Context Consistency and Synchronization Rate", "OFFICIAL_RUNTIME_CCSR", ccsrReady, "Verifies that request, event, prompt, and decision facts remain consistent across the enterprise evidence path."));
        scenarios.add(new OfficialVerificationScenarioDefinition("PFR", "Prompt Fidelity Rate", "OFFICIAL_RUNTIME_PFR", pfrReady, "Verifies that prompt telemetry remains complete, traceable, and synchronized across the enterprise evidence path."));
        scenarios.add(new OfficialVerificationScenarioDefinition("MTR", "Metadata Traceability Rate", "OFFICIAL_RUNTIME_MTR", mtrReady, "Verifies that requestId, evidence, and prompt governance linkage remain traceable end-to-end across the enterprise evidence path."));
        scenarios.add(new OfficialVerificationScenarioDefinition("CoR", "Context Contamination Rate", "OFFICIAL_RUNTIME_COR", corReady, "Verifies that foreign-user, wrong-purpose, and unauthorized-scope documents never contaminate the enterprise context path."));
        scenarios.add(new OfficialVerificationScenarioDefinition("RAP", "RAG Authorization Precision", "OFFICIAL_RUNTIME_RAP", rapReady, "Verifies that only authorized retrieved documents survive into the final enterprise prompt context."));
        scenarios.add(new OfficialVerificationScenarioDefinition("RPI", "Round Progression Integrity", "OFFICIAL_RUNTIME_RPI", rpiReady, "Verifies that repeated enterprise rounds accumulate retrieval and baseline evidence without regression."));
        scenarios.add(new OfficialVerificationScenarioDefinition("BMA", "Baseline Maturity Accuracy", "OFFICIAL_RUNTIME_BMA", bmaReady, "Verifies that baseline evidence starts provisional and matures into observed work pattern context across repeated enterprise rounds."));
        scenarios.add(new OfficialVerificationScenarioDefinition("USNS", "User-Specific Novelty Sensitivity", "OFFICIAL_RUNTIME_USNS", usnsReady, "Verifies that user-specific novelty remains visible even when device and network signals stay stable across enterprise rounds."));
        scenarios.add(new OfficialVerificationScenarioDefinition("BSR", "Behavioral Surprise Resolution", "OFFICIAL_RUNTIME_BSR", bsrReady, "Verifies that anomaly and recovery rounds preserve sequence history, cadence evidence, and observed work pattern context."));
        scenarios.add(new OfficialVerificationScenarioDefinition("PRE", "Protectable Resource Eligibility", "OFFICIAL_RUNTIME_PRE", preReady, "Verifies that a target URL has protectable resource metadata and can receive a prompt quality certificate before Zero Trust enablement."));

        return List.copyOf(scenarios);
    }
}