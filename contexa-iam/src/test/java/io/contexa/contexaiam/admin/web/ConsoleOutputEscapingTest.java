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
package io.contexa.contexaiam.admin.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The console builds much of its markup in script, and this repository has no script test runner. These checks read the
 * shipped scripts and templates as text and hold the rules that keep a stored name from being read as markup or code. A
 * name of a role, a permission or a user may hold a quote, an angle bracket or an ampersand and has to stay a name.
 */
class ConsoleOutputEscapingTest {

    private static final String SCRIPTS = "classpath*:static/contexa/js/**/*.js";
    private static final String TEMPLATES = "classpath*:templates/contexa/**/*.html";

    private static final Pattern SCRIPT_ELEMENT = Pattern.compile(
            "<script\\b([^>]*)>(.*?)</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    /** A handler attribute written in a script whose text is cut open to splice a value in. */
    private static final Pattern HANDLER_BUILT_FROM_A_VALUE = Pattern.compile(
            "\\bon[a-z]+=\\\\?\"(?:[^\"\\\\]|\\\\.)*?(?:(?<!\\\\)'\\s*\\+|\"\\s*\\+|\\$\\{)");

    /** Escaping for a page, undone by the browser, followed by a quote replacement that finds nothing left to replace. */
    private static final Pattern QUOTE_REPLACED_AFTER_ESCAPING = Pattern.compile("\\.replace\\(/'/g,\\s*\"\\\\\\\\'\"\\)");

    /** The text node trick, which leaves both quotes as they are and so cannot serve an attribute. */
    private static final Pattern ESCAPE_BY_TEXT_NODE = Pattern.compile(
            "\\.textContent\\s*=\\s*\\w+;\\s*return\\s+\\w+\\.innerHTML");

    /** A field of a record added to a string of markup. */
    private static final Pattern FIELD_ADDED_TO_MARKUP = Pattern.compile(
            "'((?:[^'\\\\\\n]|\\\\.)*)'\\s*\\+\\s*([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)+)\\s*(?=\\+|;|\\)|$)",
            Pattern.MULTILINE);

    /** A field of a record placed into a template string of markup. */
    private static final Pattern FIELD_IN_MARKUP_TEMPLATE = Pattern.compile(
            "\\$\\{([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)+)}");

    /** Fields that hold a number the server counted or generated. */
    private static final Set<String> NUMBER_FIELDS = Set.of(
            "id", "length", "size", "memberCount", "permCount", "totalRoles", "gained", "lost", "unchanged");

    /** Objects that hold the wording of the page, which comes from the message bundles. */
    private static final Pattern MESSAGE_HOLDER = Pattern.compile("^(?:_i18n|_\\w+I18n|PD_I18N)\\..*");

    /** The screens whose scripts write stored names through template strings. */
    private static final List<String> SCREENS_WITH_TEMPLATE_STRINGS = List.of(
            "policydetails.html", "role-hierarchy-details.html", "delete-policy-modal.html", "menu-management.html",
            "policy-center.js", "access-center.js");

    private static final Pattern RAW_OUTPUT = Pattern.compile("th:utext=\"([^\"]*)\"");

    /** The raw outputs that are known to be safe: the two script payloads and the menu icons checked on the server. */
    private static final Set<String> CHECKED_RAW_OUTPUTS = Set.of(
            "${scriptMessagesJson}", "${screenSettingsJson}", "${node.icon()}", "${menu.icon}");

    private static final Pattern UNESCAPED_INLINING = Pattern.compile("\\[\\(\\s*[$#*@]\\{");

    @Test
    @DisplayName("a value reaches a handler through a data attribute, never through the handler's text")
    void noHandlerIsBuiltFromAValue() throws IOException {
        assertThat(findIn(scripts(), HANDLER_BUILT_FROM_A_VALUE)).isEmpty();
    }

    @Test
    @DisplayName("no script replaces quotes after escaping, which protects nothing")
    void noQuoteIsReplacedAfterEscaping() throws IOException {
        assertThat(findIn(scripts(), QUOTE_REPLACED_AFTER_ESCAPING)).isEmpty();
    }

    @Test
    @DisplayName("every escape helper of the console also escapes quotes")
    void everyEscapeHelperEscapesQuotes() throws IOException {
        assertThat(findIn(scripts(), ESCAPE_BY_TEXT_NODE)).isEmpty();
    }

    @Test
    @DisplayName("a stored field enters markup only through an escape helper")
    void aStoredFieldIsEscapedInMarkup() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Script script : scripts()) {
            Matcher added = FIELD_ADDED_TO_MARKUP.matcher(script.code());
            while (added.find()) {
                if (isMarkup(added.group(1)) && !isPlainValue(added.group(2))) {
                    offenders.add(script.at(added.start()) + " " + added.group(2));
                }
            }
            if (SCREENS_WITH_TEMPLATE_STRINGS.stream().noneMatch(script.file()::endsWith)) {
                continue;
            }
            Matcher placed = FIELD_IN_MARKUP_TEMPLATE.matcher(script.code());
            while (placed.find()) {
                if (script.lineAround(placed.start()).contains("<") && !isPlainValue(placed.group(1))) {
                    offenders.add(script.at(placed.start()) + " " + placed.group(1));
                }
            }
        }
        assertThat(offenders).isEmpty();
    }

    @Test
    @DisplayName("raw output takes wording from the bundles or a value the server checked, nothing else")
    void rawOutputTakesOnlyCheckedValues() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Resource template : resources(TEMPLATES)) {
            Matcher raw = RAW_OUTPUT.matcher(template.getContentAsString(StandardCharsets.UTF_8));
            while (raw.find()) {
                String expression = raw.group(1);
                if (!expression.startsWith("#{") && !CHECKED_RAW_OUTPUTS.contains(expression)) {
                    offenders.add(template.getFilename() + " " + expression);
                }
            }
        }
        assertThat(offenders).isEmpty();
    }

    @Test
    @DisplayName("no template inlines an expression without escaping")
    void noTemplateInlinesWithoutEscaping() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Resource template : resources(TEMPLATES)) {
            if (UNESCAPED_INLINING.matcher(template.getContentAsString(StandardCharsets.UTF_8)).find()) {
                offenders.add(template.getFilename());
            }
        }
        assertThat(offenders).isEmpty();
    }

    @Test
    @DisplayName("the hierarchy diagram runs strict, with labels as text and names kept inside their label")
    void theHierarchyDiagramKeepsNamesAsText() throws IOException {
        String screen = template("admin/role-hierarchy-details.html");

        assertThat(screen).contains("securityLevel: 'strict'", "htmlLabels: false", "function mermaidLabel(");
        assertThat(screen).doesNotContain("securityLevel: 'loose'", "htmlLabels: true",
                "[\"${rel.parent}\"]", "[\"${rel.child}\"]",
                "const parentLabel = rel.parent;", "const childLabel = rel.child;");
    }

    @Test
    @DisplayName("every diagram is drawn from stand-in labels and then shows each role's own name as text")
    void everyDiagramShowsEachRolesOwnName() throws IOException {
        String screen = template("admin/role-hierarchy-details.html");
        String draw = functionText(screen, "function drawDiagram(");
        String label = functionText(screen, "function mermaidLabel(");
        String restore = functionText(screen, "function restoreDiagramNames(");

        assertThat(screen.split("mermaid\\.init\\(", -1)).as("mermaid is started in one place").hasSize(2);
        assertThat(draw).contains("mermaid.init(", "restoreDiagramNames(");
        assertThat(screen.split("drawDiagram\\(", -1)).as("the main, full-screen and confirm diagrams").hasSize(5);
        assertThat(label).doesNotContain("#quot;");
        assertThat(restore).contains(".textContent = ").doesNotContain("innerHTML");
        assertThat(screen).doesNotContain(".replace(/[^a-zA-Z0-9]/g, '_')");
    }

    @Test
    @DisplayName("the hierarchy screen writes role names and messages as text")
    void theHierarchyScreenWritesNamesAsText() throws IOException {
        String screen = template("admin/role-hierarchy-details.html");

        assertThat(screen).contains(
                "<strong>${escapeHtml(role)}</strong><br/>${escapeHtml(desc)}",
                "'<option value=\"' + escapeHtml(role.roleName) + '\">' + escapeHtml(displayText) + '</option>'",
                "document.createTextNode(message)");
        assertThat(screen).doesNotContain("(icons[type] || icons.info) + message");
    }

    @Test
    @DisplayName("the delete dialog writes a policy as text")
    void theDeleteDialogWritesAPolicyAsText() throws IOException {
        String dialog = template("fragments/delete-policy-modal.html");

        assertThat(dialog).contains(".textContent = p.name", ".textContent = p.effect");
        assertThat(dialog).doesNotContain("p.name + ' <span");
    }

    @Test
    @DisplayName("the menu screen previews an icon class without writing markup")
    void theMenuScreenPreviewsAClassWithoutMarkup() throws IOException {
        String screen = template("admin/menu-management.html");

        assertThat(screen).doesNotContain("'<i class=\"' + m.icon", "'<i class=\"' + cls");
    }

    @Test
    @DisplayName("the confirm dialog falls back to a list of the relations it was handed")
    void theConfirmDialogFallsBackToTheRelationsItWasHanded() throws IOException {
        String screen = template("admin/role-hierarchy-details.html");
        String renderer = functionText(screen, "function renderConfirmDiagram(");

        assertThat(renderer).contains("relations.map(");
        assertThat(renderer).startsWith("function renderConfirmDiagram(mermaidCode, relations, nodes)");
        assertThat(screen).contains("renderConfirmDiagram(mermaidCode, relations, nodes);");
    }

    @Test
    @DisplayName("a snapshot that fails to load says so, its wording declared before the request that may fail")
    void aSnapshotThatFailsToLoadSaysSo() throws IOException {
        String viewer = functionText(template("admin/policydetails.html"), "viewSnapshot: function(");

        assertThat(viewer.indexOf("var _snapI18n")).isNotNegative().isLessThan(viewer.indexOf("PolicyVersionUI.json("));
        assertThat(viewer).containsOnlyOnce("var _snapI18n");
    }

    /** The text of a function, from its signature to the brace that closes its body. */
    private static String functionText(String source, String signature) {
        int start = source.indexOf(signature);
        assertThat(start).as(signature).isNotNegative();
        int depth = 0;
        for (int i = source.indexOf('{', start); i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return source.substring(start, i + 1);
            }
        }
        throw new AssertionError("no end of " + signature);
    }

    /** Markup opens a tag, closes an attribute or opens one; a lone {@code >} joins a parent and a child role. */
    private static boolean isMarkup(String literal) {
        return literal.contains("<") || literal.contains("\">") || literal.endsWith("=\"");
    }

    private static boolean isPlainValue(String expression) {
        String field = expression.substring(expression.lastIndexOf('.') + 1);
        return NUMBER_FIELDS.contains(field) || MESSAGE_HOLDER.matcher(expression).matches();
    }

    private static String template(String path) throws IOException {
        return new ClassPathResource("templates/contexa/" + path).getContentAsString(StandardCharsets.UTF_8);
    }

    private static List<String> findIn(List<Script> scripts, Pattern pattern) {
        List<String> found = new ArrayList<>();
        for (Script script : scripts) {
            Matcher matcher = pattern.matcher(script.code());
            while (matcher.find()) {
                found.add(script.at(matcher.start()));
            }
        }
        return found;
    }

    /** Every script file of the console except the vendored ones, and every inline script of its templates. */
    private static List<Script> scripts() throws IOException {
        List<Script> scripts = new ArrayList<>();
        for (Resource file : resources(SCRIPTS)) {
            if (!file.getURI().toString().contains("/vendor/")) {
                String text = file.getContentAsString(StandardCharsets.UTF_8);
                scripts.add(new Script(file.getFilename(), text, 0, text));
            }
        }
        for (Resource template : resources(TEMPLATES)) {
            String text = template.getContentAsString(StandardCharsets.UTF_8);
            Matcher element = SCRIPT_ELEMENT.matcher(text);
            while (element.find()) {
                String attributes = element.group(1);
                if (!attributes.contains("src=") && !attributes.contains("application/json")) {
                    scripts.add(new Script(template.getFilename(), text, element.start(2), element.group(2)));
                }
            }
        }
        assertThat(scripts).hasSizeGreaterThan(20);
        return scripts;
    }

    private static Resource[] resources(String pattern) throws IOException {
        return new PathMatchingResourcePatternResolver().getResources(pattern);
    }

    private record Script(String file, String text, int start, String code) {

        String at(int index) {
            int line = 1;
            for (int i = 0; i < start + index; i++) {
                if (text.charAt(i) == '\n') {
                    line++;
                }
            }
            return file + ":" + line;
        }

        String lineAround(int index) {
            int from = code.lastIndexOf('\n', index) + 1;
            int to = code.indexOf('\n', index);
            return code.substring(from, to < 0 ? code.length() : to);
        }
    }
}
