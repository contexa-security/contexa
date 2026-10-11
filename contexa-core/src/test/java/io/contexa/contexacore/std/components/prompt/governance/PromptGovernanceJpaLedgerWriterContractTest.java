package io.contexa.contexacore.std.components.prompt.governance;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class PromptGovernanceJpaLedgerWriterContractTest {

    @Test
    void coreLedgerWritesUseJpaRepositories() throws Exception {
        String writer = Files.readString(Path.of(
                "src/main/java/io/contexa/contexacore/std/components/prompt/governance/PromptGovernanceJpaLedgerWriter.java"),
                StandardCharsets.UTF_8);

        assertThat(writer)
                .contains("PromptGovernanceRegistryRepository")
                .contains("PromptGovernanceChangeRecordRepository")
                .contains("PromptGovernanceEvaluationRecordRepository")
                .contains("PromptGovernanceReleaseApprovalRepository")
                .contains("PromptGovernanceReleaseWorkflowRepository")
                .contains(".saveAndFlush(record)");
    }
}
