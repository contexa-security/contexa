package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One vocabulary for what a request does (W2-1): every word list of the engine's classifiers maps onto the same
 * families, by whole words, so one request has one action family wherever it is read.
 */
class ActionFamilyTest {

    @Test
    void verbsAndHttpMethodsMapOntoOneVocabulary() {
        assertThat(ActionFamily.of("GET")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("HEAD")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("POST")).isEqualTo(ActionFamily.WRITE);
        assertThat(ActionFamily.of("PATCH")).isEqualTo(ActionFamily.WRITE);
        assertThat(ActionFamily.of("CREATE")).isEqualTo(ActionFamily.WRITE);
        assertThat(ActionFamily.of("update")).isEqualTo(ActionFamily.WRITE);
        assertThat(ActionFamily.of("DELETE")).isEqualTo(ActionFamily.DELETE);
        assertThat(ActionFamily.of("EXPORT")).isEqualTo(ActionFamily.EXPORT);
        assertThat(ActionFamily.of("APPROVE")).isEqualTo(ActionFamily.ADMIN);
        assertThat(ActionFamily.of("INVOKE")).isEqualTo(ActionFamily.EXECUTE);
        assertThat(ActionFamily.of("UNKNOWN")).isEqualTo(ActionFamily.UNKNOWN);
    }

    @Test
    void aDownloadIsARead() {
        assertThat(ActionFamily.of("DOWNLOAD")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("downloadDocument")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("DOCUMENT_DOWNLOAD")).isEqualTo(ActionFamily.READ);
    }

    @Test
    void methodNamesAndOperationNamesAreReadByTheirWords() {
        assertThat(ActionFamily.of("exportDocuments")).isEqualTo(ActionFamily.EXPORT);
        assertThat(ActionFamily.of("exportDocumentsAsync")).isEqualTo(ActionFamily.EXPORT);
        assertThat(ActionFamily.of("openExportStream")).isEqualTo(ActionFamily.EXPORT);
        assertThat(ActionFamily.of("readDocument")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("readCustomer")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("grantRole")).isEqualTo(ActionFamily.ADMIN);
        assertThat(ActionFamily.of("DOCUMENT_READ")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.of("PROJECT_EXPORT")).isEqualTo(ActionFamily.EXPORT);
        assertThat(ActionFamily.of("/api/projects/ /exports")).isEqualTo(ActionFamily.EXPORT);
        assertThat(ActionFamily.of("role-grants")).isEqualTo(ActionFamily.ADMIN);
    }

    @Test
    void aVerbInsideAnotherWordIsNotAnAction() {
        assertThat(ActionFamily.of("TARGET")).isNull();
        assertThat(ActionFamily.of("thread")).isNull();
        assertThat(ActionFamily.of("RUNTIME")).isNull();
        assertThat(ActionFamily.of("budgetReport")).isNull();
        assertThat(ActionFamily.of("documents")).isNull();
        assertThat(ActionFamily.of("")).isNull();
        assertThat(ActionFamily.of(null)).isNull();
    }

    @Test
    void wordsOfSeveralFamiliesNameTheRiskiestOne() {
        assertThat(ActionFamily.of("readAndDelete")).isEqualTo(ActionFamily.DELETE);
        assertThat(ActionFamily.of("readRoles")).isEqualTo(ActionFamily.ADMIN);
        assertThat(ActionFamily.of("listExports")).isEqualTo(ActionFamily.EXPORT);
    }

    @Test
    void theFirstValueThatNamesAFamilyWinsAndUnnamedValuesStayAsStated() {
        assertThat(ActionFamily.firstOf(null, "budget", "GET")).isEqualTo(ActionFamily.READ);
        assertThat(ActionFamily.firstOf("budget", "report")).isNull();
        assertThat(ActionFamily.nameOrRaw("create")).isEqualTo("WRITE");
        assertThat(ActionFamily.nameOrRaw("custom_step")).isEqualTo("CUSTOM_STEP");
        assertThat(ActionFamily.nameOrRaw(" ")).isNull();
    }

    @Test
    void theNormalizerReadsTheSameVocabulary() {
        assertThat(SecuritySemanticNormalizer.normalizeActionFamily("CREATE")).isEqualTo("WRITE");
        assertThat(SecuritySemanticNormalizer.normalizeActionFamily("TARGET", "GET")).isEqualTo("READ");
        assertThat(SecuritySemanticNormalizer.normalizeActionFamily("DOWNLOAD")).isEqualTo("READ");
        assertThat(SecuritySemanticNormalizer.normalizeActionFamily("thread")).isNull();
    }
}
