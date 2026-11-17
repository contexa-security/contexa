/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.dashboard;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan step 9: the dashboard's words in both languages, every key its page and its script read, and none of the old
 * dashboard's or of the prompt quality card on hold left behind.
 */
class DashboardMessagesTest {

    private static final String PREFIX = "dashboard.ui.";
    private static Properties en;
    private static Properties ko;
    private static String script;
    private static String template;

    @BeforeAll
    static void read() throws IOException {
        en = properties("contexa/i18n/messages.properties");
        ko = properties("contexa/i18n/messages_ko.properties");
        script = new ClassPathResource("static/contexa/js/admin/dashboard.js").getContentAsString(StandardCharsets.UTF_8);
        template = new ClassPathResource("templates/contexa/admin/dashboard.html")
                .getContentAsString(StandardCharsets.UTF_8);
    }

    @Test
    void bothLanguagesHaveTheSameDashboardWordsAndNoneIsEmpty() {
        Set<String> english = keys(en);
        assertThat(english).hasSizeGreaterThan(200).isEqualTo(keys(ko));
        english.forEach(key -> {
            assertThat(en.getProperty(key)).as(key).isNotBlank();
            assertThat(ko.getProperty(key)).as(key).isNotBlank();
        });
    }

    @Test
    void everyWordThePageAndTheScriptNameIsThere() {
        List<String> missing = new ArrayList<>();
        for (String key : used()) {
            if (!en.containsKey(key) || !ko.containsKey(key)) {
                missing.add(key);
            }
        }
        assertThat(missing).isEmpty();
    }

    @Test
    void theOldDashboardsWordsAndThePromptQualityOnesOnHoldAreGone() {
        Set<String> old = new TreeSet<>();
        for (Properties messages : List.of(en, ko)) {
            messages.stringPropertyNames().stream().filter(key -> key.startsWith("admin.dashboard.")).forEach(old::add);
        }
        // The policy center still names roles, permissions and policies with the old dashboard's three words.
        assertThat(old).containsExactly("admin.dashboard.permissions", "admin.dashboard.policies",
                "admin.dashboard.roles");
        for (String held : List.of("band.prompt", "todo.inspectionFailed", "todo.uninspected", "todo.newProduct",
                "prompt.verdict.PASS", "prompt.noPackages", "prompt.versions", "prompt.state.USED", "prompt.counts",
                "prompt.total", "prompt.inspectionPeriod", "prompt.link.versions", "prompt.link.inspection")) {
            assertThat(en).doesNotContainKey(PREFIX + held);
            assertThat(ko).doesNotContainKey(PREFIX + held);
        }
        assertThat(en).containsKey(PREFIX + "prompt.pending");
        assertThat(template).doesNotContain("admin.dashboard.").doesNotContain("dashboardData");
        assertThat(script).doesNotContain("promptVersion").doesNotContain("inspection");
    }

    /** The keys the page and the script read: each literal key, and each family a key is made from. */
    private static Set<String> used() {
        Set<String> keys = new TreeSet<>();
        Matcher literal = Pattern.compile("\\bd\\('([\\w.]+)'\\s*[,)]").matcher(script);
        while (literal.find()) {
            keys.add(PREFIX + literal.group(1));
        }
        Matcher console = Pattern.compile("\\bt\\('((?:zt\\.console|admin\\.system)\\.[\\w.]+)'\\s*[,)]").matcher(script);
        while (console.find()) {
            keys.add(console.group(1));
        }
        Matcher page = Pattern.compile("#\\{([\\w.]+)}").matcher(template);
        while (page.find()) {
            keys.add(page.group(1));
        }
        family(keys, "area.", "iam", "policy", "security", "agents", "zeroTrust", "prompt", "system");
        family(keys, "areas.status.", "OFF", "NONE", "SHADOW");
        family(keys, "blocks.status.", "BLOCKED", "UNBLOCK_REQUESTED", "MFA_FAILED", "TIMEOUT_RESPONDED");
        family(keys, "agents.status.", "ACTIVE", "SUSPENDED", "DEREGISTERED");
        family(keys, "agents.", "callLimit", "denialAlarm", "narrowed", "stoppedDelegations");
        family(keys, "system.decision.", "PERMIT", "DENY", "AUTHENTICATED");
        family(keys, "attention.signal.", "BLOCKED", "UNBLOCK_REQUESTED", "MFA_FAILED", "TIMEOUT_RESPONDED",
                "ADMIN_NO_MFA", "LOCKED", "LOGIN_FAILURES", "CHALLENGES", "REPEATED");
        family(keys, "changes.kind.", "POLICY", "USER", "ROLE", "PROMPT", "MODE", "OVERRIDE", "AGENT");
        family(keys, "changes.action.", DashboardServiceImpl.NAMED_ACTIONS.toArray(String[]::new));
        for (String period : List.of("day", "week", "month", "quarter")) {
            keys.add("zt.console.ui.period." + period);
        }
        for (String mode : List.of("ENFORCE", "SHADOW", "DISABLED")) {
            keys.add("zt.console.ui.mode." + mode);
        }
        for (String algorithm : List.of("first_applicable", "deny_overrides", "permit_overrides", "deny_unless_permit")) {
            keys.add("admin.system.settings.combining.algorithm." + algorithm);
        }
        return keys;
    }

    private static void family(Set<String> keys, String prefix, String... members) {
        for (String member : members) {
            keys.add(PREFIX + prefix + member);
        }
    }

    private static Set<String> keys(Properties messages) {
        Set<String> keys = new TreeSet<>();
        messages.stringPropertyNames().stream().filter(key -> key.startsWith(PREFIX)).forEach(keys::add);
        return keys;
    }

    private static Properties properties(String name) throws IOException {
        Properties properties = new Properties();
        try (Reader reader = new InputStreamReader(new ClassPathResource(name).getInputStream(), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }
}
