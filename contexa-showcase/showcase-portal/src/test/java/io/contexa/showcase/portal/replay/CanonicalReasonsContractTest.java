package io.contexa.showcase.portal.replay;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every sentence the core's decision rules fix ("reasoning must be exactly ...") has a code the screens translate,
 * read from the core source in this repository. When the core adds or rewords a fixed sentence, this test fails
 * instead of the screen showing an untranslated engine sentence.
 */
class CanonicalReasonsContractTest {

    private static final Path PROMPT_SECTIONS = Path.of("..", "..", "contexa-core", "src", "main", "java", "io",
            "contexa", "contexacore", "autonomous", "tiered", "prompt", "SecurityDecisionPromptSections.java");

    @Test
    void everyFixedSentenceOfTheCoreHasACode() throws IOException {
        String source = Files.readString(PROMPT_SECTIONS, StandardCharsets.UTF_8);
        Set<String> fixed = new LinkedHashSet<>();
        Matcher exactly = Pattern.compile("reasoning must be exactly \"([^\"]+)\"").matcher(source);
        while (exactly.find()) {
            fixed.add(exactly.group(1));
        }

        assertThat(fixed).as("the core still fixes sentences where the demo reads them").isNotEmpty();
        assertThat(ReplayViews.CANONICAL_REASONS.keySet()).containsExactlyInAnyOrderElementsOf(fixed);
        assertThat(ReplayViews.CANONICAL_REASONS.values()).doesNotHaveDuplicates();
    }

    @Test
    void aSentenceTheModelWroteHasNoCode() {
        assertThat(ReplayViews.canonicalCode("Critical resource sensitivity with established baseline mismatch; "
                + "challenge preserves safety.")).isNull();
        assertThat(ReplayViews.canonicalCode(" High-sensitivity access departs from the established personal baseline "
                + "without a required approval; challenge is required. ")).isEqualTo("CHALLENGE_ELEVATED_RISK_BOUNDARY");
    }
}
