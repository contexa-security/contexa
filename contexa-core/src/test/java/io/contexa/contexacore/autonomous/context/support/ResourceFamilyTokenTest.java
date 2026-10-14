package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The resource class is read from whole classification words, with one vocabulary for the class and the sensitivity
 * scales; a word that only contains a level name inside it is not a classification (I-2).
 */
class ResourceFamilyTokenTest {

    @Test
    void classificationWordsMapOntoOneVocabulary() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("RESTRICTED")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("critical")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("CONFIDENTIAL")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("SECRET")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("HIGH")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("highly-confidential")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("INTERNAL")).isEqualTo("NORMAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("PUBLIC")).isEqualTo("PUBLIC");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("UNKNOWN")).isEqualTo("UNKNOWN");
    }

    @Test
    void aLevelNameInsideAnotherWordIsNotAClassification() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("ALLOW")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("Workflow guide")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("follow-up")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("highway")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("ALLOW")).isNull();
    }

    @Test
    void theFirstValueThatNamesAClassWins() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("REPORT", "RESTRICTED")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass(null, "  ", "CONFIDENTIAL")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceClass("REPORT", "DOCUMENT")).isNull();
    }

    @Test
    void bothScalesReadTheSameWords() {
        for (String word : new String[] {"RESTRICTED", "CRITICAL", "CONFIDENTIAL", "SECRET", "SENSITIVE", "HIGH",
                "INTERNAL", "STANDARD", "NORMAL", "MEDIUM", "PUBLIC", "LOW"}) {
            String resourceClass = SecuritySemanticNormalizer.normalizeResourceClass(word);
            String sensitivity = SecuritySemanticNormalizer.normalizeSensitivity(word);
            assertThat(sensitivity).as(word).isEqualTo(switch (resourceClass) {
                case "SENSITIVE" -> "HIGH";
                case "NORMAL" -> "MEDIUM";
                case "PUBLIC" -> "LOW";
                default -> resourceClass;
            });
        }
    }
}
