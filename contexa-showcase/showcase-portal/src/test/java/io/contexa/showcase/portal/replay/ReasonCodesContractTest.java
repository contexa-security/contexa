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
 * the screens name no code the core does not have.
 */
class ReasonCodesContractTest {

    private static final Path OUTPUT_CONTRACT = Path.of("..", "..", "contexa-core", "src", "main", "java", "io",
            "contexa", "contexacore", "autonomous", "tiered", "prompt", "SecurityDecisionOutputContract.java");
    private static final Path WEB_I18N = Path.of("..", "web", "src", "i18n");
    private static final String PREFIX = "reasonCode.";

    @Test
    void everyReasonCodeOfTheCoreHasAMeaningInBothLanguages() throws IOException {
        String source = Files.readString(OUTPUT_CONTRACT, StandardCharsets.UTF_8);
        Set<String> codes = new LinkedHashSet<>();
        Matcher code = Pattern.compile("code\\(Group\\.[A-Z_]+, \"([A-Z0-9_]+)\"").matcher(source);
        while (code.find()) {
            codes.add(code.group(1));
        }

        assertThat(codes).as("the core's reason codes").hasSize(53);
        for (String language : new String[]{"ko", "en"}) {
            assertThat(meanings(language)).as(language).containsExactlyInAnyOrderElementsOf(codes);
        }
    }

    private static Set<String> meanings(String language) throws IOException {
        JsonNode dictionary = new ObjectMapper().readTree(WEB_I18N.resolve(language + ".json").toFile());
        Set<String> codes = new LinkedHashSet<>();
        dictionary.fieldNames().forEachRemaining(key -> {
            if (key.startsWith(PREFIX) && !dictionary.path(key).asText().isBlank()) {
                codes.add(key.substring(PREFIX.length()));
            }
        });
        return codes;
    }
}
