package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 * W4-3: every reason code of the core's output contract v3 has a fixed Korean and English meaning on the screens, and
 * the screens name no code the core does not have. SC-5 (변경 6 of docs/showcase/프롬프트-v21-구현계획.md): the codes
 * of the output contract v4 (a v21 decision) have meanings of their own, since its judgment codes say what the model
 * judged where codes of the same name in the contract v3 stated the core's facts.
 */
class ReasonCodesContractTest {

    private static final Path PROMPT = Path.of("..", "..", "contexa-core", "src", "main", "java", "io", "contexa",
            "contexacore", "autonomous", "tiered", "prompt");
    private static final Path WEB_I18N = Path.of("..", "web", "src", "i18n");

    @Test
    void everyReasonCodeOfTheCoreHasAMeaningInBothLanguages() throws IOException {
        Set<String> codes = codes("SecurityDecisionOutputContract.java");

        assertThat(codes).as("the core's reason codes").hasSize(53);
        for (String language : new String[]{"ko", "en"}) {
            assertThat(meanings(language, "reasonCode.")).as(language).containsExactlyInAnyOrderElementsOf(codes);
        }
    }

    @Test
    void everyReasonCodeOfTheOutputContractV4HasAMeaningOfItsOwnInBothLanguages() throws IOException {
        Set<String> codes = codes("SecurityDecisionOutputContractV4.java");

        assertThat(codes).as("the reason codes of the output contract v4").hasSize(49);
        for (String language : new String[]{"ko", "en"}) {
            assertThat(meanings(language, "reasonCodeV4.")).as(language).containsExactlyInAnyOrderElementsOf(codes);
        }
    }

    private static Set<String> codes(String contract) throws IOException {
        String source = Files.readString(PROMPT.resolve(contract), StandardCharsets.UTF_8);
        Set<String> codes = new LinkedHashSet<>();
        Matcher code = Pattern.compile("code\\(Group\\.[A-Z_]+, \"([A-Z0-9_]+)\"").matcher(source);
        while (code.find()) {
            codes.add(code.group(1));
        }
        return codes;
    }

    private static Set<String> meanings(String language, String prefix) throws IOException {
        JsonNode dictionary = new ObjectMapper().readTree(WEB_I18N.resolve(language + ".json").toFile());
        Set<String> codes = new LinkedHashSet<>();
        dictionary.fieldNames().forEachRemaining(key -> {
            if (key.startsWith(prefix) && !dictionary.path(key).asText().isBlank()) {
                codes.add(key.substring(prefix.length()));
            }
        });
        return codes;
    }
}
