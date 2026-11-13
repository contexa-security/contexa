package io.contexa.contexaiam.admin.promptquality.official.state;

import io.contexa.contexaiam.admin.promptquality.official.common.DefaultPromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IAM-D30: a state catalog that holds its labels in one language (the enterprise catalog's table, seeded in Korean)
 * answers in the language of the screen: the label and the next action come from the messages by dimension and code.
 */
class LocalizedPromptQualityStateCatalogTest {

    private static final PromptQualityStateDescriptor STORED_IN_KOREAN = new PromptQualityStateDescriptor(
            "RUNTIME_EVIDENCE", "RUNTIME_EVIDENCE", "READY_FOR_INSPECTION", "검사 가능", "ready", "READY",
            List.of("RUN_OFFICIAL_VERIFICATION"), "이 실제 요청 증거 packageId를 공식 검사에 사용할 수 있습니다.", 1);

    private final PromptQualityMessageResolver messages = new DefaultPromptQualityMessageResolver(messageSource());
    private final PromptQualityStateCatalog catalog = LocalizedPromptQualityStateCatalog.of(new StoredCatalog(), () -> messages);

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void anEnglishScreenGetsTheEnglishLabelAndNextAction() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        PromptQualityStateDescriptor ready = catalog.runtimeEvidence(true, true, false);

        assertThat(ready.label()).isEqualTo("Ready for verification");
        assertThat(ready.nextAction()).isEqualTo("This real request evidence packageId can be used for an official verification.");
        assertThat(ready.code()).isEqualTo("READY_FOR_INSPECTION");
        assertThat(ready.tone()).isEqualTo("ready");
        assertThat(ready.allowedActions()).containsExactly("RUN_OFFICIAL_VERIFICATION");
        assertThat(catalog.descriptors()).extracting(PromptQualityStateDescriptor::label)
                .containsExactly("Ready for verification");
    }

    @Test
    void aKoreanScreenGetsTheKoreanLabel() {
        LocaleContextHolder.setLocale(Locale.KOREAN);

        assertThat(catalog.runtimeEvidence(true, true, false).label()).isEqualTo("검사 가능");
    }

    @Test
    void aStateTheMessagesDoNotNameKeepsTheCatalogsText() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        PromptQualityStateDescriptor other = catalog.describe(PromptQualityStateDimension.RUNTIME_EVIDENCE, "SOMETHING_NEW");

        assertThat(other.label()).isEqualTo("SOMETHING_NEW");
        assertThat(LocalizedPromptQualityStateCatalog.of(catalog, () -> messages)).isSameAs(catalog);
    }

    private static ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("contexa.i18n.messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return source;
    }

    /** A catalog whose texts are stored in Korean, as the enterprise catalog's table holds them. */
    private static final class StoredCatalog implements PromptQualityStateCatalog {

        @Override
        public List<PromptQualityStateDescriptor> descriptors() {
            return List.of(STORED_IN_KOREAN);
        }

        @Override
        public PromptQualityStateDescriptor describe(PromptQualityStateDimension dimension, String code) {
            return new PromptQualityStateDescriptor(dimension.name(), "RUNTIME_EVIDENCE", code, code, "neutral",
                    code, List.of(), "", 0);
        }

        @Override
        public PromptQualityStateDescriptor resourceRequestObservation(boolean evidenceObserved, boolean decisionRecorded) {
            return STORED_IN_KOREAN;
        }

        @Override
        public PromptQualityStateDescriptor runtimeEvidence(boolean sealed, boolean integrityValid, boolean warningSignals) {
            return STORED_IN_KOREAN;
        }

        @Override
        public List<String> resourceOperationalActions(String operationalState, boolean promotable) {
            return List.of();
        }
    }
}
