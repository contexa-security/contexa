package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenario;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenarioCatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class OfficialVerificationContractMetadataSupport {

    public static final String TDD_CONTRACT_SOURCE = "contexa-official-verification-contract";
    public static final String CONTRACT_VERSION = "2026-04-05";

    private OfficialVerificationContractMetadataSupport() {
    }

    public static ContractStatus rpiStructureMismatch() {
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                false,
                false,
                "HTTP RPI runtime still uses a simplified three-round progression adapter while the starter TDD source of truth uses the EXTENDED long-horizon scenario catalog with 24 rounds, session-mode transitions, cooldown, and observedAt progression.",
                "io.contexa.contexacore.verification.runtime.OfficialVerificationRpiExecutionService",
                "executeRun / buildRequestFacts / buildRawEvidence",
                "progressionRoundCount"
        );
    }

    public static ContractStatus rpiStructureAligned(String scenarioSelector, int scenarioCount, int roundCountPerScenario) {
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                true,
                true,
                "Aligned with shared starter TDD contract selector "
                        + scenarioSelector
                        + " across "
                        + scenarioCount
                        + " scenarios and "
                        + roundCountPerScenario
                        + " rounds per scenario.",
                "io.contexa.contexacore.verification.runtime.OfficialVerificationRpiExecutionService",
                "executeRun / buildScenarioPlan / forwardHeaders / buildRawEvidence",
                "scenarioSelector"
        );
    }

    public static ContractStatus rpiStructureAligned(String scenarioSelector, List<OfficialVerificationPromptContractScenario> contracts) {
        List<OfficialVerificationPromptContractScenario> expectedContracts =
                OfficialVerificationPromptContractScenarioCatalog.extendedScenarioSet();
        String normalizedSelector = scenarioSelector == null ? "" : scenarioSelector.trim().toUpperCase(Locale.ROOT);
        String producerClass = "io.contexa.contexacore.verification.runtime.OfficialVerificationRpiExecutionService";
        String producerMethod = "executeRun / buildAlignedRoundPlans / buildRequestFacts / buildRawEvidence";
        if (!"EXTENDED".equals(normalizedSelector)) {
            return provisional(
                    "RPI",
                    "RPI official scoring must execute the EXTENDED long-horizon starter TDD contract, but the live runtime used selector "
                            + normalizedSelector + ".",
                    producerClass,
                    producerMethod,
                    "scenarioSelector");
        }
        if (contracts == null || contracts.isEmpty()) {
            return provisional(
                    "RPI",
                    "RPI official scoring did not resolve any live contract scenarios.",
                    producerClass,
                    producerMethod,
                    "scenarioSelector");
        }
        if (contracts.size() != expectedContracts.size()) {
            return provisional(
                    "RPI",
                    "RPI official scoring must execute "
                            + expectedContracts.size()
                            + " EXTENDED long-horizon scenarios, but the live runtime resolved "
                            + contracts.size()
                            + ".",
                    producerClass,
                    producerMethod,
                    "scenarioCount");
        }
        for (int index = 0; index < expectedContracts.size(); index++) {
            OfficialVerificationPromptContractScenario expected = expectedContracts.get(index);
            OfficialVerificationPromptContractScenario actual = contracts.get(index);
            if (!expected.scenarioKey().equals(actual.scenarioKey())) {
                return provisional(
                        "RPI",
                        "RPI official scoring must preserve the EXTENDED scenario order from starter TDD, but scenario index "
                                + (index + 1)
                                + " was "
                                + actual.scenarioKey()
                                + " instead of "
                                + expected.scenarioKey()
                                + ".",
                        producerClass,
                        producerMethod,
                        "scenarioKey");
            }
            if (expected.roundCount() != actual.roundCount()) {
                return provisional(
                        "RPI",
                        "RPI official scoring must preserve the full starter TDD round count for scenario "
                                + expected.scenarioKey()
                                + ", but the live runtime executed "
                                + actual.roundCount()
                                + " instead of "
                                + expected.roundCount()
                                + ".",
                        producerClass,
                        producerMethod,
                        "progressionRoundCount");
            }
        }
        int roundCountPerScenario = expectedContracts.stream()
                .mapToInt(OfficialVerificationPromptContractScenario::roundCount)
                .max()
                .orElse(0);
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                true,
                true,
                "Aligned with the shared starter TDD EXTENDED long-horizon contract across "
                        + expectedContracts.size()
                        + " scenarios and "
                        + roundCountPerScenario
                        + " rounds per scenario.",
                producerClass,
                producerMethod,
                "scenarioSelector");
    }

    public static ContractStatus promptScenarioAligned(
            String metricCode,
            String scenarioSelector,
            int scenarioCount,
            int roundCountPerScenario,
            String producerClass,
            String producerMethod,
            String producerField) {
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                true,
                true,
                "HTTP runtime is aligned with the shared starter TDD prompt replay contract selector "
                        + scenarioSelector
                        + " across "
                        + scenarioCount
                        + " scenarios and "
                        + roundCountPerScenario
                        + " rounds per scenario for official metric "
                        + metricCode
                        + ".",
                producerClass,
                producerMethod,
                producerField
        );
    }
    public static ContractStatus aligned(String metricCode, String producerClass, String producerMethod, String producerField) {
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                true,
                true,
                "HTTP runtime remains structurally aligned with the current starter TDD source of truth for official metric "
                        + metricCode
                        + ".",
                producerClass,
                producerMethod,
                producerField
        );
    }


    public static ContractStatus benchmarkArtifactAligned(
            String metricCode,
            String producerClass,
            String producerMethod,
            String producerField
    ) {
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                true,
                true,
                "Backfilled from an official benchmark publication artifact that already satisfied the shared starter TDD contract for official metric "
                        + metricCode
                        + ".",
                producerClass,
                producerMethod,
                producerField
        );
    }

    public static ContractStatus provisional(String metricCode, String reason, String producerClass, String producerMethod, String producerField) {
        return new ContractStatus(
                TDD_CONTRACT_SOURCE,
                CONTRACT_VERSION,
                false,
                false,
                reason,
                producerClass,
                producerMethod,
                producerField
        );
    }

    public static Map<String, String> withRequestFacts(Map<String, String> facts, ContractStatus status) {
        Map<String, String> mutable = facts == null ? new LinkedHashMap<>() : new LinkedHashMap<>(facts);
        if (status != null) {
            mutable.put("contractSource", status.contractSource());
            mutable.put("contractVersion", status.contractVersion());
            mutable.put("contractStructureAligned", Boolean.toString(status.structureAligned()));
            mutable.put("liveScoreFinalized", Boolean.toString(status.liveScoreFinalized()));
            mutable.put("structureMismatchReason", status.structureMismatchReason());
            mutable.put("contractMismatchProducerClass", status.producerClass());
            mutable.put("contractMismatchProducerMethod", status.producerMethod());
            mutable.put("contractMismatchProducerField", status.producerField());
        }
        return Map.copyOf(mutable);
    }

    public static Map<String, Object> withRawEvidence(Map<String, Object> evidence, ContractStatus status) {
        Map<String, Object> mutable = evidence == null ? new LinkedHashMap<>() : new LinkedHashMap<>(evidence);
        if (status != null) {
            Map<String, Object> contract = new LinkedHashMap<>();
            contract.put("contractSource", status.contractSource());
            contract.put("contractVersion", status.contractVersion());
            contract.put("structureAligned", status.structureAligned());
            contract.put("liveScoreFinalized", status.liveScoreFinalized());
            contract.put("structureMismatchReason", status.structureMismatchReason());
            contract.put("producerClass", status.producerClass());
            contract.put("producerMethod", status.producerMethod());
            contract.put("producerField", status.producerField());
            mutable.put("contract", Map.copyOf(contract));
        }
        return Map.copyOf(mutable);
    }

    public record ContractStatus(
            String contractSource,
            String contractVersion,
            boolean structureAligned,
            boolean liveScoreFinalized,
            String structureMismatchReason,
            String producerClass,
            String producerMethod,
            String producerField) {
    }
}
