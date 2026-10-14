package io.contexa.contexaiam.admin.promptquality.inspection;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every word the inspection screens draw is in both the English and the Korean messages: the keys of the templates,
 * the script words and the menu rows.
 */
class PromptInspectionMessagesTest {

    private static final Pattern TEMPLATE_KEY = Pattern.compile("#\\{([A-Za-z0-9_.]+)}");
    private static final List<String> TEMPLATES = List.of("fragments", "overview", "packages", "detail");

    @Test
    void everyKeyOfTheScreensIsInBothLanguages() throws IOException {
        Set<String> keys = new LinkedHashSet<>(PromptInspectionPageController.SCRIPT_KEYS);
        for (String template : TEMPLATES) {
            Matcher matcher = TEMPLATE_KEY.matcher(read("templates/contexa/admin/prompt-inspection/" + template + ".html"));
            while (matcher.find()) {
                keys.add(matcher.group(1));
            }
        }
        keys.add("menu.pqa.inspection.overview");
        keys.add("menu.pqa.inspection.packages");

        Properties english = properties("i18n/messages.properties");
        Properties korean = properties("i18n/messages_ko.properties");
        assertThat(keys).allMatch(english::containsKey, "in the English messages");
        assertThat(keys).allMatch(korean::containsKey, "in the Korean messages");
        assertThat(keys.stream().filter(key -> english.getProperty(key).equals(korean.getProperty(key))).toList())
                .as("translated").isEmpty();
    }

    private static String read(String resource) throws IOException {
        try (InputStream input = PromptInspectionMessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Properties properties(String resource) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = PromptInspectionMessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            properties.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
