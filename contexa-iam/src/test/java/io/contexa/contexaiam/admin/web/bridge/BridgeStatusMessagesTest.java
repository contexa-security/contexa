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
package io.contexa.contexaiam.admin.web.bridge;

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import io.contexa.contexaiam.admin.web.bridge.BridgeStatus.Effect;
import io.contexa.contexaiam.admin.web.bridge.BridgeStatus.Problem;
import io.contexa.contexaiam.admin.web.bridge.BridgeStatus.Share;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("사용자 연동 상태 화면 문구")
class BridgeStatusMessagesTest {

    private static final String MENU_KEY = "menu.zerotrust.bridge";
    private static final String TEMPLATE = "templates/contexa/admin/zero-trust/bridge.html";
    private static final Pattern LITERAL_KEY = Pattern.compile("#\\{([A-Za-z0-9_.-]+)\\s*[(}]");
    private static final Pattern MODEL_CALL = Pattern.compile("\\b(b|row|problem)\\.(\\w+)\\(\\)");
    private static final Pattern EFFECT_CALL = Pattern.compile("effect\\(\\)\\.(\\w+)\\(\\)");
    private static final Map<String, Class<?>> MODEL_VARIABLES = Map.<String, Class<?>>of(
            "b", BridgeStatus.class, "row", Share.class, "problem", Problem.class);
    private static final List<String> INTERNAL_TERMS = List.of("갈래", "B3", "B4", "bridge v2", "Step ");

    private static Properties english;
    private static Properties korean;
    private static String template;

    @BeforeAll
    static void read() throws IOException {
        english = properties("contexa/i18n/messages.properties");
        korean = properties("contexa/i18n/messages_ko.properties");
        template = new ClassPathResource(TEMPLATE).getContentAsString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("화면 문구 키는 한국어와 영어 번들에 똑같이 있고 비어 있지 않다")
    void bothLanguagesHoldTheSameWordsAndNoneIsBlank() {
        Set<String> englishKeys = screenKeys(english);

        assertThat(englishKeys).hasSizeGreaterThan(100).isEqualTo(screenKeys(korean));
        assertThat(english).containsKey(MENU_KEY);
        assertThat(korean).containsKey(MENU_KEY);
        for (String key : englishKeys) {
            assertThat(english.getProperty(key)).as(key).isNotBlank();
            assertThat(korean.getProperty(key)).as(key).isNotBlank();
        }
    }

    @Test
    @DisplayName("모든 결과, 경로, 문제, 영향의 문구가 두 언어에 있고 쓰이지 않는 키는 없다")
    void everyWordTheScreenCanNameIsThereAndNoneIsLeftOver() {
        Set<String> used = new TreeSet<>(modelKeys());
        used.addAll(templateKeys());
        used.removeIf(key -> !key.startsWith(BridgeStatus.PREFIX));

        List<String> missing = new ArrayList<>();
        for (String key : used) {
            if (!english.containsKey(key) || !korean.containsKey(key)) {
                missing.add(key + (english.containsKey(key) ? "" : " [en]") + (korean.containsKey(key) ? "" : " [ko]"));
            }
        }
        assertThat(missing).isEmpty();
        assertThat(screenKeys(english)).isEqualTo(used);
    }

    @Test
    @DisplayName("템플릿이 부르는 모든 키는 두 번들에 있다")
    void everyKeyTheTemplateNamesIsInBothBundles() {
        Set<String> keys = templateKeys();

        assertThat(keys).contains("admin.bridge.status.title", "admin.bridge.status.count",
                "admin.bridge.status.attention", "admin.bridge.status.off.title");
        assertThat(keys).allSatisfy(key -> {
            assertThat(english).as(key).containsKey(key);
            assertThat(korean).as(key).containsKey(key);
        });
    }

    @Test
    @DisplayName("템플릿이 부르는 모델 메서드는 모두 화면 값에 있다")
    void everyMethodTheTemplateCallsIsOnTheModel() {
        assertThat(template).contains("th:with=\"b=${bridge}\"");
        List<String> unknown = new ArrayList<>();
        Matcher call = MODEL_CALL.matcher(template);
        int calls = 0;
        while (call.find()) {
            calls++;
            if (!hasPublicMethod(MODEL_VARIABLES.get(call.group(1)), call.group(2))) {
                unknown.add(call.group(1) + "." + call.group(2) + "()");
            }
        }
        Matcher effect = EFFECT_CALL.matcher(template);
        while (effect.find()) {
            calls++;
            if (!hasPublicMethod(Effect.class, effect.group(1))) {
                unknown.add("effect()." + effect.group(1) + "()");
            }
        }

        assertThat(calls).isGreaterThan(30);
        assertThat(unknown).isEmpty();
    }

    @Test
    @DisplayName("값을 넣는 문구는 그 값으로 서식이 끝나고 값이 없는 문구에는 자리 표시가 없다")
    void theWordsWithValuesAreFormattedAndTheOthersHaveNoPlaceholder() {
        List<String> broken = new ArrayList<>();
        for (SubjectProblem kind : SubjectProblem.values()) {
            Problem problem = new Problem(kind, 1);
            Set<Integer> placed = new TreeSet<>();
            for (String key : List.of(problem.nameKey(), problem.meaningKey(), problem.actionKey())) {
                check(key, problem.args(), placed, broken);
            }
            for (int index = 0; index < problem.args().length; index++) {
                if (!placed.contains(index)) {
                    broken.add(kind + " does not use value {" + index + "}");
                }
            }
        }
        for (Share share : List.of(new Share(BridgeStatus.SOURCE, ContexaIdentity.Source.REQUEST_ATTRIBUTE.name(), 1,
                1.0, false), new Share(BridgeStatus.OUTCOME, ContexaIdentity.Outcome.INVALID.name(), 1, 1.0, true))) {
            check(share.descriptionKey(), share.args(), new TreeSet<>(), broken);
        }
        for (Map.Entry<String, Object[]> literal : Map.<String, Object[]>of(
                "admin.bridge.status.attention", new Object[] {2L, 3L},
                "admin.bridge.status.count", new Object[] {1234L},
                "admin.bridge.status.outcomes.total", new Object[] {10L},
                "admin.bridge.status.sources.total", new Object[] {8L},
                "admin.bridge.status.problems.total", new Object[] {2},
                "admin.bridge.status.problems.quiet", new Object[] {18},
                "admin.bridge.status.split.total", new Object[] {3},
                "admin.bridge.status.split.copies", new Object[] {2L},
                "admin.bridge.status.split.more", new Object[] {50}).entrySet()) {
            check(literal.getKey(), literal.getValue(), new TreeSet<>(), broken);
        }

        assertThat(broken).isEmpty();
    }

    @Test
    @DisplayName("합치지 못한 사용자 수는 영어에서 한 명이면 단수, 여럿이면 복수로 보인다")
    void theCountOfUsersWithSplitCopiesIsSingularForOne() {
        String value = english.getProperty("admin.bridge.status.split.total");

        assertThat(new MessageFormat(value, Locale.ENGLISH).format(new Object[] {1})).isEqualTo("1 user");
        assertThat(new MessageFormat(value, Locale.ENGLISH).format(new Object[] {3})).isEqualTo("3 users");
    }

    @Test
    @DisplayName("화면 문구에 작은따옴표와 내부 설계 용어가 없다")
    void theWordsHoldNoApostropheAndNoInternalTerm() {
        List<String> found = new ArrayList<>();
        for (Properties bundle : List.of(english, korean)) {
            for (String key : screenKeysWithMenu(bundle)) {
                String value = bundle.getProperty(key);
                if (value.contains("'")) {
                    found.add(key + " holds an apostrophe, which a formatted message drops");
                }
                INTERNAL_TERMS.stream().filter(value::contains).forEach(term -> found.add(key + " names " + term));
            }
        }

        assertThat(found).isEmpty();
    }

    private static void check(String key, Object[] args, Set<Integer> placed, List<String> broken) {
        for (Map.Entry<Locale, Properties> bundle : Map.<Locale, Properties>of(Locale.ENGLISH, english, Locale.KOREAN,
                korean).entrySet()) {
            String value = bundle.getValue().getProperty(key);
            if (value == null) {
                broken.add(key + " is missing in " + bundle.getKey());
                continue;
            }
            for (int index = 0; index < args.length; index++) {
                if (value.contains("{" + index + "}")) {
                    placed.add(index);
                }
            }
            String shown = args.length == 0 ? value : new MessageFormat(value, bundle.getKey()).format(args);
            if (shown.contains("{") || shown.contains("}")) {
                broken.add(key + " [" + bundle.getKey() + "] keeps a placeholder: " + shown);
            }
        }
    }

    private static Set<String> modelKeys() {
        Set<String> keys = new TreeSet<>();
        for (ContexaIdentity.Outcome outcome : ContexaIdentity.Outcome.values()) {
            Share share = new Share(BridgeStatus.OUTCOME, outcome.name(), 0, 0.0, false);
            keys.add(share.nameKey());
            keys.add(share.descriptionKey());
        }
        for (ContexaIdentity.Source source : ContexaIdentity.Source.values()) {
            Share share = new Share(BridgeStatus.SOURCE, source.name(), 0, 0.0, false);
            keys.add(share.nameKey());
            keys.add(share.descriptionKey());
        }
        for (SubjectProblem kind : SubjectProblem.values()) {
            Problem problem = new Problem(kind, 0);
            keys.add(problem.nameKey());
            keys.add(problem.meaningKey());
            keys.add(problem.actionKey());
        }
        for (Effect effect : Effect.values()) {
            keys.add(effect.key());
        }
        return keys;
    }

    private static Set<String> templateKeys() {
        Set<String> keys = new TreeSet<>();
        Matcher matcher = LITERAL_KEY.matcher(template);
        while (matcher.find()) {
            keys.add(matcher.group(1));
        }
        return keys;
    }

    private static boolean hasPublicMethod(Class<?> type, String name) {
        for (Method method : type.getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 0
                    && Modifier.isPublic(method.getModifiers())) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> screenKeys(Properties bundle) {
        Set<String> keys = new TreeSet<>();
        bundle.stringPropertyNames().stream().filter(key -> key.startsWith(BridgeStatus.PREFIX)).forEach(keys::add);
        return keys;
    }

    private static Set<String> screenKeysWithMenu(Properties bundle) {
        Set<String> keys = screenKeys(bundle);
        keys.add(MENU_KEY);
        return keys;
    }

    private static Properties properties(String path) throws IOException {
        Properties properties = new Properties();
        try (Reader reader = new InputStreamReader(new ClassPathResource(path).getInputStream(), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }
}
