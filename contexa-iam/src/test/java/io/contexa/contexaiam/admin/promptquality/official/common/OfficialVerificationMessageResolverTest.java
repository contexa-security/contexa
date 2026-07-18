package io.contexa.contexaiam.admin.promptquality.official.common;

import static org.assertj.core.api.Assertions.assertThat;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Properties;

class OfficialVerificationMessageResolverTest {

    private static final String EN_BUNDLE = "i18n/messages.properties";
    private static final String KO_BUNDLE = "i18n/messages_ko.properties";

    @Test
    void resolvesEnglishAndKoreanMessagesWithArguments() {
        OfficialVerificationMessageResolver english = OfficialVerificationMessageResolver.classpath(Locale.ENGLISH);
        OfficialVerificationMessageResolver korean = OfficialVerificationMessageResolver.classpath(Locale.KOREAN);

        assertThat(english.resolve("verification.finalPrompt.value.named", "field", "actual"))
                .isEqualTo("field value is actual");
        assertThat(korean.resolve("verification.finalPrompt.value.named", "필드", "실제값"))
                .isEqualTo("필드 값은 실제값");
    }

    @Test
    void bundlesHaveIdenticalKeysAndValidUtf8Text() throws IOException {
        Properties english = load(EN_BUNDLE);
        Properties korean = load(KO_BUNDLE);

        var englishKeys = english.stringPropertyNames().stream()
                .filter(key -> key.startsWith("verification.finalPrompt."))
                .sorted()
                .toList();
        var koreanKeys = korean.stringPropertyNames().stream()
                .filter(key -> key.startsWith("verification.finalPrompt."))
                .sorted()
                .toList();

        assertThat(englishKeys).hasSize(24);
        assertThat(koreanKeys).containsExactlyElementsOf(englishKeys);
        assertThat(String.join("\n", englishKeys)).doesNotContain("\\u");
        assertThat(String.join("\n", koreanKeys.stream().map(korean::getProperty).toList()))
                .doesNotContain("\\u", String.valueOf((char) 0xFFFD));
    }

    @Test
    void officialNarrativeCatalogUsesMatchingEnglishAndKoreanBundleContracts() throws IOException {
        OfficialPromptQualityNarrativeCatalog englishCatalog = new OfficialPromptQualityNarrativeCatalog(
                OfficialVerificationMessageResolver.classpath(Locale.ENGLISH));
        OfficialPromptQualityNarrativeCatalog koreanCatalog = new OfficialPromptQualityNarrativeCatalog(
                OfficialVerificationMessageResolver.classpath(Locale.KOREAN));

        assertThat(englishCatalog.metricName("EIR")).isEqualTo("request-fact preservation");
        assertThat(koreanCatalog.metricName("EIR")).isEqualTo("요청 사실 보존");

        Properties english = load(EN_BUNDLE);
        Properties korean = load(KO_BUNDLE);
        var englishKeys = english.stringPropertyNames().stream()
                .filter(key -> key.startsWith("enterprise.pqa.officialNarrative."))
                .sorted()
                .toList();
        var koreanKeys = korean.stringPropertyNames().stream()
                .filter(key -> key.startsWith("enterprise.pqa.officialNarrative."))
                .sorted()
                .toList();

        assertThat(englishKeys).isNotEmpty();
        assertThat(koreanKeys).containsExactlyElementsOf(englishKeys);
        assertThat(englishKeys).allSatisfy(key -> {
            assertThat(english.getProperty(key)).isNotBlank().isNotEqualTo(key);
            assertThat(korean.getProperty(key)).isNotBlank().isNotEqualTo(key);
        });
    }
    private Properties load(String resourceName) throws IOException {
        Properties properties = new Properties();
        try (InputStreamReader reader = new InputStreamReader(
                getClass().getClassLoader().getResourceAsStream(resourceName),
                StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }
}