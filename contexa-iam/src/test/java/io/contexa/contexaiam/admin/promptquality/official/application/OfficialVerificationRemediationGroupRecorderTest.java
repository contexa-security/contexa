package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractWriter;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OfficialVerificationRemediationGroupRecorderTest {

    private OfficialVerificationRemediationGroupWriter writer;
    private OfficialVerificationRemediationGroupRecorder recorder;

    @BeforeEach
    void setUp() {
        writer = mock(OfficialVerificationRemediationGroupWriter.class);
        OfficialActualPromptProblemNarrative problemNarrative = mock(OfficialActualPromptProblemNarrative.class);
        OfficialVerificationMetricNarrative metricNarrative = mock(OfficialVerificationMetricNarrative.class);
        OfficialVerificationCustomerTextPolicy customerText = mock(OfficialVerificationCustomerTextPolicy.class);
        when(problemNarrative.action(any())).thenAnswer(invocation -> problem(invocation).fixAction());
        when(problemNarrative.rootCause(any())).thenAnswer(invocation -> problem(invocation).whyItMatters());
        when(problemNarrative.title(any())).thenAnswer(invocation -> problem(invocation).promptLabel());
        when(problemNarrative.reverify(any())).thenAnswer(invocation -> problem(invocation).reverifyCriterionDetail());
        when(metricNarrative.ownerDisplayName(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
        when(customerText.require(anyString(), anyString())).thenAnswer(invocation -> invocation.getArgument(1));
        recorder = new OfficialVerificationRemediationGroupRecorder(
                writer, problemNarrative, metricNarrative, customerText);
    }

    @Test
    void sameCauseEvidenceAndFixTargetProducesOneOperatorRemediationGroup() {
        recorder.record("run-1", "package-1", "certificate-1", "case-1", List.of(
                problem("cor-problem", "COR", "First action wording."),
                problem("rap-problem", "RAP", "Different action wording.")));

        ArgumentCaptor<OfficialVerificationRemediationGroupWriter.RemediationGroupCommand> captor =
                ArgumentCaptor.forClass(OfficialVerificationRemediationGroupWriter.RemediationGroupCommand.class);
        verify(writer).insert(captor.capture());

        OfficialVerificationRemediationGroupWriter.GroupClassification classification =
                captor.getValue().classification();
        assertThat(classification.rootCauseKey()).isEqualTo("FINAL_PROMPT_RAG_RETRIEVAL_FAILED");
        assertThat(classification.affectedMetricCodes()).isEqualTo("COR,RAP");
        assertThat(classification.findingCount()).isEqualTo(2);
    }

    @Test
    void differentEvidenceAndFixTargetsRemainSeparateGroups() {
        OfficialActualPromptProblem retrieval = problem("retrieval-problem", "COR", "Same action wording.");
        OfficialActualPromptProblem projection = new OfficialActualPromptProblem(
                "projection-problem", "package-1", "run-1",
                "finalUserPrompt.ragEvidence.projection", "FINAL_PROMPT_RAG_RETRIEVAL_FAILED",
                "finalUserPrompt.ragEvidence.projection", "RAG projection", "Projection failed.",
                "finalUserPrompt.ragEvidence.projection", "sealedEvidence.ragProjection",
                "Projected", "Missing", "BLOCKING", List.of("RAP"), "RAG_CONTEXT_PRODUCER",
                "Is RAG projected?", "Projection evidence is required.", "Same action wording.",
                "Projection must pass.", List.of(), List.of());

        recorder.record("run-1", "package-1", "certificate-1", "case-1", List.of(retrieval, projection));

        verify(writer, times(2)).insert(any());
    }

    @Test
    void commonCorAndRapFailureProducesOneProblemWithBothMetricAttributions() {
        ObjectMapper objectMapper = new ObjectMapper();
        OfficialFinalPromptMetricContractRegistry contractRegistry = new OfficialFinalPromptMetricContractRegistry(
                objectMapper,
                mock(OfficialMetricPurposeContractWriter.class),
                mock(OfficialVerificationSnapshotQueryService.class));
        OfficialMetricPurposeNarrative purposeNarrative = mock(OfficialMetricPurposeNarrative.class);
        when(purposeNarrative.actualProblemState(any(), any())).thenReturn("RAG retrieval is not available.");
        OfficialActualPromptProblemCollector collector = new OfficialActualPromptProblemCollector(
                contractRegistry,
                purposeNarrative,
                new OfficialRuntimeEvidenceCheckInterpreter(objectMapper),
                new OfficialActualPromptProblemNarrative(mock(OfficialPromptEvidenceFormatter.class)));

        List<OfficialActualPromptProblem> problems = collector.collect(
                "run-1", "package-1", List.of(metric("COR"), metric("RAP")), List.of());

        assertThat(problems).singleElement().satisfies(problem -> {
            assertThat(problem.fieldKey()).isEqualTo("finalUserPrompt.ragEvidence.retrievalState");
            assertThat(problem.problemType()).isEqualTo("FINAL_PROMPT_RAG_RETRIEVAL_FAILED");
            assertThat(problem.metricCodes()).containsExactly("COR", "RAP");
        });
    }

    private OfficialActualPromptProblem problem(String problemId, String metricCode, String fixAction) {
        return new OfficialActualPromptProblem(
                problemId, "package-1", "run-1",
                "finalUserPrompt.ragEvidence.retrievalState", "FINAL_PROMPT_RAG_RETRIEVAL_FAILED",
                "finalUserPrompt.ragEvidence.retrievalState", "RAG retrieval", "Retrieval failed.",
                "finalUserPrompt.ragEvidence.retrievalState", "sealedEvidence.ragRetrieval",
                "Retrieval available", "Retrieval failed", "BLOCKING", List.of(metricCode), "RAG_RETRIEVER",
                "Did retrieval succeed?", "Retrieval evidence is required.", fixAction,
                "Retrieval must pass.", List.of(), List.of());
    }

    private RuntimeEvidenceMetricResult metric(String metricCode) {
        RuntimeEvidenceCheckResult check = new RuntimeEvidenceCheckResult(
                metricCode,
                metricCode + "_RAG_RETRIEVAL_NOT_FAILED",
                "RAG retrieval",
                "Retrieval must not fail.",
                "Retrieval failed.",
                false,
                "finalUserPrompt.ragEvidence.retrievalState",
                "BLOCKING",
                "FINAL_PROMPT_RAG_RETRIEVAL_FAILED",
                "RAG_RETRIEVER",
                "Retrieval failed.",
                "Fix retrieval.",
                "Retrieval must pass.",
                "finalUserPrompt.ragEvidence.retrievalState",
                true,
                "CUSTOMER_PROMPT_QUALITY",
                "final-user-prompt.v1",
                "READY",
                "PURPOSE_FAILED",
                "[]",
                "[]",
                "Did retrieval succeed?",
                "Retrieval evidence is required.");
        return new RuntimeEvidenceMetricResult(
                metricCode, "run-" + metricCode, metricCode, "RAG", 0.0,
                "threshold_failed", "Failed", 0, 1, List.of(check));
    }

    private OfficialActualPromptProblem problem(InvocationOnMock invocation) {
        return invocation.getArgument(0);
    }
}
