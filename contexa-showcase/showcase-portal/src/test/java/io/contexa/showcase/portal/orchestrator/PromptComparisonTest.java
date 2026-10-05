package io.contexa.showcase.portal.orchestrator;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PromptComparisonTest {

    private static final String FIRST = String.join("\n",
            "UserId: <RUN>-eng-k",
            "HistoricalComparableSummary: Records=3 | Paths=/a, /b, /c | Days=3, 2, 1",
            "RagDocument1: [Doc1|path=/a|hour=10]",
            "RagDocument2: [Doc2|path=/b|hour=14]",
            "RagDocument3: [Doc3|path=/c|hour=13]");

    @Test
    void identicalPromptsAreIdenticalAndTheSameEvidence() {
        PromptComparison.Result result = PromptComparison.compare(FIRST, FIRST);

        assertThat(result.identical()).isTrue();
        assertThat(result.sameEvidenceSet()).isTrue();
        assertThat(result.differingLabels()).isEmpty();
    }

    @Test
    void theSameDocumentsInAnotherOrderAreTheSameEvidenceButNotIdentical() {
        String reordered = String.join("\n",
                "UserId: <RUN>-eng-k",
                "HistoricalComparableSummary: Records=3 | Paths=/a, /c, /b | Days=3, 1, 2",
                "RagDocument1: [Doc1|path=/a|hour=10]",
                "RagDocument2: [Doc2|path=/c|hour=13]",
                "RagDocument3: [Doc3|path=/b|hour=14]");

        PromptComparison.Result result = PromptComparison.compare(FIRST, reordered);

        assertThat(result.identical()).isFalse();
        assertThat(result.sameEvidenceSet()).isTrue();
        assertThat(result.differingLabels())
                .containsExactly("HistoricalComparableSummary", "RagDocument2", "RagDocument3");
    }

    @Test
    void aSummaryShowingOtherLeadingItemsIsDifferentEvidenceFromTheSameDocuments() {
        String first = FIRST.replace("Paths=/a, /b, /c", "Paths=/a, /b");
        String other = FIRST.replace("Paths=/a, /b, /c", "Paths=/a, /c")
                .replace("RagDocument2: [Doc2|path=/b|hour=14]", "RagDocument2: [Doc2|path=/c|hour=13]")
                .replace("RagDocument3: [Doc3|path=/c|hour=13]", "RagDocument3: [Doc3|path=/b|hour=14]");

        PromptComparison.Result result = PromptComparison.compare(first, other);

        assertThat(result.sameEvidenceSet()).isFalse();
        assertThat(result.sameRetrievedDocuments()).isTrue();
    }

    @Test
    void anotherDocumentIsDifferentEvidence() {
        String other = FIRST.replace("path=/c|hour=13", "path=/d|hour=13");

        PromptComparison.Result result = PromptComparison.compare(FIRST, other);

        assertThat(result.identical()).isFalse();
        assertThat(result.sameEvidenceSet()).isFalse();
        assertThat(result.sameRetrievedDocuments()).isFalse();
        assertThat(result.differingLabels()).containsExactly("RagDocument3");
    }
}
