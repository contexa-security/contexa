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
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("RESTRICTED")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("critical")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("CONFIDENTIAL")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("SECRET")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("HIGH")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("highly-confidential")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("INTERNAL")).isEqualTo("NORMAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("PUBLIC")).isEqualTo("PUBLIC");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("UNKNOWN")).isEqualTo("UNKNOWN");
    }

    @Test
    void aLevelNameInsideAnotherWordIsNotAClassification() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("ALLOW")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("Workflow guide")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("follow-up")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("highway")).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("ALLOW")).isNull();
    }

    @Test
    void theFirstValueThatNamesAClassWins() {
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("REPORT", "RESTRICTED")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily(null, "  ", "CONFIDENTIAL")).isEqualTo("SENSITIVE");
        assertThat(SecuritySemanticNormalizer.normalizeResourceFamily("REPORT", "DOCUMENT")).isNull();
    }

    @Test
    void bothScalesReadTheSameWords() {
        for (String word : new String[] {"RESTRICTED", "CRITICAL", "CONFIDENTIAL", "SECRET", "SENSITIVE", "HIGH",
                "INTERNAL", "STANDARD", "NORMAL", "MEDIUM", "PUBLIC", "LOW"}) {
            String resourceClass = SecuritySemanticNormalizer.normalizeResourceFamily(word);
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
