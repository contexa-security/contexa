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
            boolean decisionCalibrationRuntimeReady,
            boolean decisionReasoningRuntimeReady,
            boolean decisionUncertaintyRuntimeReady,
            boolean preReady
    ) {
        List<OfficialVerificationScenarioDefinition> scenarios = new ArrayList<>();
        scenarios.add(new OfficialVerificationScenarioDefinition("EIR", "Event Integrity Rate", "OFFICIAL_RUNTIME_EIR", eirReady, "Verifies that request, event, prompt, and decision linkage stay aligned."));
        scenarios.add(new OfficialVerificationScenarioDefinition("CCR", "Context Completeness Rate", "OFFICIAL_RUNTIME_CCR", ccrReady, "Verifies that required session, behavior, retrieval, and prompt fields are represented in the sealed prompt input."));
        scenarios.add(new OfficialVerificationScenarioDefinition("CCSR", "Context Consistency and Synchronization Rate", "OFFICIAL_RUNTIME_CCSR", ccsrReady, "Verifies that request, event, prompt, and decision facts remain internally consistent."));
        scenarios.add(new OfficialVerificationScenarioDefinition("PFR", "Prompt Fidelity Rate", "OFFICIAL_RUNTIME_PFR", pfrReady, "Verifies that prompt telemetry remains complete, traceable, and synchronized."));
        scenarios.add(new OfficialVerificationScenarioDefinition("MTR", "Metadata Traceability Rate", "OFFICIAL_RUNTIME_MTR", mtrReady, "Verifies that requestId, evidence, and prompt governance linkage remain traceable end-to-end."));
        scenarios.add(new OfficialVerificationScenarioDefinition("CoR", "Context Contamination Rate", "OFFICIAL_RUNTIME_COR", corReady, "Verifies that foreign-user, wrong-purpose, and unauthorized-scope context does not contaminate the prompt."));
        scenarios.add(new OfficialVerificationScenarioDefinition("RAP", "RAG Authorization Precision", "OFFICIAL_RUNTIME_RAP", rapReady, "Verifies that only authorized retrieved documents survive into the final prompt context."));
        scenarios.add(new OfficialVerificationScenarioDefinition("RPI", "Round Progression Integrity", "OFFICIAL_RUNTIME_RPI", rpiReady, "Verifies that repeated rounds accumulate retrieval and baseline evidence without regression."));
        scenarios.add(new OfficialVerificationScenarioDefinition("BMA", "Baseline Maturity Accuracy", "OFFICIAL_RUNTIME_BMA", bmaReady, "Verifies that baseline evidence starts provisional and matures into observed work pattern context."));
        scenarios.add(new OfficialVerificationScenarioDefinition("USNS", "User-Specific Novelty Sensitivity", "OFFICIAL_RUNTIME_USNS", usnsReady, "Verifies that user-specific novelty remains visible when stable device and network signals hide subtle behavior changes."));
        scenarios.add(new OfficialVerificationScenarioDefinition("BSR", "Behavioral Surprise Resolution", "OFFICIAL_RUNTIME_BSR", bsrReady, "Verifies that anomaly and recovery rounds preserve sequence history, cadence evidence, and observed work pattern context."));
        scenarios.add(new OfficialVerificationScenarioDefinition("PRE", "Protectable Resource Eligibility", "OFFICIAL_RUNTIME_PRE", preReady, "Verifies that the target URL can receive a prompt quality certificate before Zero Trust enablement."));

        boolean decisionRuntimeReady = decisionCalibrationRuntimeReady || decisionReasoningRuntimeReady || decisionUncertaintyRuntimeReady;
        addDecisionScenarios(scenarios, decisionRuntimeReady);
        return List.copyOf(scenarios);
    }

    private void addDecisionScenarios(List<OfficialVerificationScenarioDefinition> scenarios, boolean ready) {
        scenarios.add(new OfficialVerificationScenarioDefinition("G01", "Official Action Contract Gate", "OFFICIAL_RUNTIME_G01", ready, "Checks whether the LLM decision action belongs to the official action contract."));
        scenarios.add(new OfficialVerificationScenarioDefinition("G02", "Decision Payload Parse Gate", "OFFICIAL_RUNTIME_G02", ready, "Checks whether the stored LLM decision can be parsed as an official decision payload."));
        scenarios.add(new OfficialVerificationScenarioDefinition("G03", "Sealed Evidence Linkage Gate", "OFFICIAL_RUNTIME_G03", ready, "Checks whether the LLM decision is linked to the same sealed evidence and prompt lineage."));
        scenarios.add(new OfficialVerificationScenarioDefinition("G04", "Execution Failure Absence Gate", "OFFICIAL_RUNTIME_G04", ready, "Checks whether the LLM decision completed without timeout, parser failure, or provider failure."));
        for (int i = 1; i <= 24; i++) {
            String code = "M" + String.format("%02d", i);
            scenarios.add(new OfficialVerificationScenarioDefinition(code, "LLM Decision Operational Metric " + code, "OFFICIAL_RUNTIME_" + code, ready, "Checks LLM contextual understanding, inference, and decision correctness for operational scenario " + code + "."));
        }
    }
}