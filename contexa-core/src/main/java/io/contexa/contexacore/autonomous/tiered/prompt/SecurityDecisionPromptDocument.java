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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The product prompt document of the security decision (plan 6-1): the sentences of the v1.0 prompt, read from
 * {@code prompt-versions/cortex.security-decision/{release}.yaml}, and the drawing of the parts that hold values the
 * engine fills in. The code keeps the values, the answer schema, the response check and the reason code identifiers;
 * the start of the engine fails when the document's reason codes or user lines are not the engine's.
 */
public final class SecurityDecisionPromptDocument {

    /** The prompt key of the security decision. */
    public static final String PROMPT = "cortex.security-decision";
    /** The product releases this build ships, the latest last; the latest is the product version. */
    public static final List<String> RELEASES = List.of("2026.11.16");
    /** The condition of the parts drawn when the host enforces the minimum action floors (K32, decision D10). */
    public static final String MINIMUM_ACTION_ENFORCE = "minimum-action-enforce";
    /** The condition of the texts an agent's request is drawn with. */
    public static final String AGENT_REQUEST = "agent-request";

    static final String REASON_CODES_PART = "reason-codes";
    static final String MINIMUM_ACTION_PART = "minimum-action-floors";
    static final String OUTPUT_FORMAT_PART = "output-format";
    static final String OUTPUT_GROUP = "output";
    static final String FORMAT_GROUP = "format";
    /** The correction keys: the output contract (K31), a minimum action floor (K32), a decision rule (D6). */
    public static final String CORRECTION_CONTRACT = "contract";
    public static final String CORRECTION_MINIMUM_ACTION = "minimum-action";
    public static final String CORRECTION_RULES = "rules";

    private SecurityDecisionPromptDocument() {
    }

    /**
     * The request parameter of the version a decision's model call runs (plan 3.4): the correction that asks the model
     * again is the one of that version, the version fixed on the event when the decision started
     * ({@link SecurityDecisionPromptSections#EVENT_BUNDLE_VERSION}). Without it the product version's runs.
     */
    public static final String VERSION_PARAMETER = "securityDecisionPromptVersion";

    /** The product version of the latest release this build ships. */
    public static AssembledPrompt product() {
        return Holder.PRODUCT;
    }

    /** The product documents of the security decision this build ships, oldest first (plan 6-3, 3.3). */
    public static List<ProductPromptRelease> productReleases() {
        List<ProductPromptRelease> releases = new ArrayList<>();
        for (String release : RELEASES) {
            String text = resource(release);
            PromptVersionDocument document = new PromptVersionDocumentReader().read(text);
            releases.add(new ProductPromptRelease(PROMPT, document.release(), text));
        }
        return List.copyOf(releases);
    }

    /** The store of the product versions this build ships, named by their release. */
    public static PromptVersionStore productStore() {
        return (prompt, version) -> PROMPT.equals(prompt) && product().release().equals(version)
                ? Optional.of(product()) : Optional.empty();
    }

    /**
     * A conclusion line the decision rules read (plan 6-2, decision D6): its meaning and use, from the items of the
     * prepared decision rules part of the version.
     */
    static PromptVersionDocument.Item conclusionLine(AssembledPrompt version, String name) {
        return version.systemPart(SecurityDecisionVersionFeatures.DECISION_RULES_PART).stream()
                .flatMap(part -> part.items().stream())
                .filter(item -> item.key().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("The prompt document " + version.release()
                        + " has no conclusion line " + name + " in its decision rules"));
    }

    /** The product document of a release, as the build ships it. */
    public static PromptVersionDocument productDocument(String release) {
        return new PromptVersionDocumentReader().read(resource(release));
    }

    /** The text of the product document of a release, as the build ships it. */
    public static String resource(String release) {
        String path = "prompt-versions/" + PROMPT + "/" + release + ".yaml";
        try (InputStream input = SecurityDecisionPromptDocument.class.getClassLoader().getResourceAsStream(path)) {
            if (input == null) {
                throw new IllegalStateException("The product prompt document is missing: " + path);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    /** The meaning of each reason code, by code, in the document's order. */
    static Map<String, String> reasonMeanings(AssembledPrompt version) {
        return version.itemTexts(REASON_CODES_PART);
    }

    /**
     * Fails when the document's reason codes are not the engine's, in its order: the console counts the codes, the
     * schema lists them and the response check reads them, so a code the document lacks or adds would draw a prompt
     * the engine does not answer to.
     */
    static void verifyReasonCodes(AssembledPrompt version, List<String> engineCodes) {
        List<String> documentCodes = List.copyOf(reasonMeanings(version).keySet());
        if (!documentCodes.equals(engineCodes)) {
            List<String> missing = new ArrayList<>(engineCodes);
            missing.removeAll(documentCodes);
            List<String> extra = new ArrayList<>(documentCodes);
            extra.removeAll(engineCodes);
            throw new IllegalStateException("The reason codes of the prompt document " + version.release()
                    + " are not the engine's: missing " + missing + ", not known " + extra
                    + (missing.isEmpty() && extra.isEmpty() ? ", in another order" : ""));
        }
        reasonMeanings(version).forEach((code, meaning) -> {
            if (meaning == null || meaning.isBlank()) {
                throw new IllegalStateException("The reason code " + code + " of the prompt document "
                        + version.release() + " has no meaning");
            }
        });
    }

    /**
     * The entries with the meanings and uses of the document's user lines; fails when the document's blocks and lines
     * are not the engine's, in its order, or a block's title is not the one the engine and the inspector read.
     */
    static List<PromptDictionaryEntry> withDocumentLines(AssembledPrompt version, List<PromptDictionaryEntry> entries) {
        List<String> documentLines = new ArrayList<>();
        Map<String, PromptVersionDocument.Item> items = new LinkedHashMap<>();
        for (PromptVersionDocument.Part block : version.user()) {
            if (block.action() == PromptVersionDocument.Action.ADD) {
                continue;
            }
            for (PromptVersionDocument.Item item : block.items()) {
                documentLines.add(block.key() + "." + item.key());
                items.put(block.key() + "." + item.key(), item);
            }
        }
        List<String> engineLines = entries.stream().map(entry -> entry.block().name() + "." + entry.name()).toList();
        if (!documentLines.equals(engineLines)) {
            List<String> missing = new ArrayList<>(engineLines);
            missing.removeAll(documentLines);
            List<String> extra = new ArrayList<>(documentLines);
            extra.removeAll(engineLines);
            throw new IllegalStateException("The user lines of the prompt document " + version.release()
                    + " are not the engine's: missing " + missing + ", not known " + extra
                    + (missing.isEmpty() && extra.isEmpty() ? ", in another order" : ""));
        }
        blockTitles(version);
        List<PromptDictionaryEntry> documented = new ArrayList<>();
        for (PromptDictionaryEntry entry : entries) {
            PromptVersionDocument.Item item = items.get(entry.block().name() + "." + entry.name());
            documented.add(new PromptDictionaryEntry(entry.block(), entry.name(), item.text(), entry.sourcePath(),
                    entry.formatPattern(), entry.formatExamples(), entry.missing(), entry.missingText(), entry.grades(),
                    item.use(), entry.conditional(), entry.priority(), entry.listCap(), entry.listOrder(),
                    entry.truncationAllowed(), entry.preservedLabels()));
        }
        return List.copyOf(documented);
    }

    /**
     * The title each product block is drawn with, from the document; fails when one is not a title the prompt
     * inspector reads the block by ({@link PromptBlock#titles()}).
     */
    static Map<PromptBlock, String> blockTitles(AssembledPrompt version) {
        Map<PromptBlock, String> titles = new EnumMap<>(PromptBlock.class);
        for (PromptVersionDocument.Part block : version.user()) {
            if (block.action() == PromptVersionDocument.Action.ADD) {
                continue;
            }
            PromptBlock engineBlock;
            try {
                engineBlock = PromptBlock.valueOf(block.key());
            }
            catch (IllegalArgumentException exception) {
                throw new IllegalStateException("The prompt document " + version.release() + " has a user block the"
                        + " engine does not draw: " + block.key(), exception);
            }
            if (!engineBlock.titles().contains(block.title())) {
                throw new IllegalStateException("The block " + block.key() + " of the prompt document "
                        + version.release() + " is titled " + block.title() + ", not one of " + engineBlock.titles());
            }
            titles.put(engineBlock, block.title());
        }
        return titles;
    }

    /**
     * The lines of the reason code part: each code with its meaning from the document and the lines it may cite, as
     * the engine names them ({@code - CODE: meaning; Line, Line}).
     *
     * @param citedLines the line names each code may cite, by code
     */
    static String reasonCodeLines(PromptVersionDocument.Part part, Map<String, List<String>> citedLines) {
        StringBuilder lines = new StringBuilder();
        for (PromptVersionDocument.Item item : part.items()) {
            lines.append("- ").append(item.key()).append(": ").append(item.text()).append("; ")
                    .append(String.join(", ", citedLines.getOrDefault(item.key(), List.of()))).append('\n');
        }
        return lines.toString();
    }

    /** The output format with the answer schema in place; null when the version has none. */
    static String outputFormat(AssembledPrompt version, String schema) {
        return version.systemPart(OUTPUT_FORMAT_PART)
                .map(part -> AssembledPrompt.fill(part.text(), Map.of("schema", schema)))
                .orElse(null);
    }

    /**
     * The minimum action rules the host turned on, in the words of the document's part, with the host's values in
     * place; null (the part is not drawn) when no rule is on.
     */
    static String minimumActionRules(PromptVersionDocument.Part part, MinimumActionRules.Settings settings) {
        MinimumActionRules.Settings rules = settings != null ? settings : MinimumActionRules.Settings.DEFAULTS;
        Map<String, String> items = new LinkedHashMap<>();
        part.items().forEach(item -> items.put(item.key(), item.text()));
        Map<String, String> values = new LinkedHashMap<>();
        values.put("resourceClasses", resourceClassesFrom(rules.identityMinResourceClass()));
        values.put("deviations", String.valueOf(rules.identityMinDeviations()));
        values.put("exportClasses", resourceClassesFrom("SENSITIVE"));
        values.put("floor", rules.policySatisfactionAction()
                + ("ESCALATE".equals(rules.policySatisfactionAction()) ? items.getOrDefault("P3-escalate", "") : ""));
        List<String> lines = new ArrayList<>();
        if (rules.identityEnabled()) {
            lines.add(items.get("P1"));
        }
        if (rules.newDeviceExportEnabled()) {
            lines.add(items.get("P2"));
        }
        if (rules.policySatisfactionEnabled()) {
            lines.add(items.get("P3"));
        }
        if (lines.isEmpty()) {
            return null;
        }
        if (rules.identityEnabled() || rules.newDeviceExportEnabled()) {
            lines.add(items.get("unexplained"));
        }
        lines.add(items.get("enforced"));
        StringBuilder text = new StringBuilder(part.text());
        for (String line : lines) {
            text.append(AssembledPrompt.fill(line, values)).append('\n');
        }
        return text.toString();
    }

    /** The resource classes at or above the minimum, in the words of the ResourceClass line. */
    private static String resourceClassesFrom(String minimum) {
        List<String> order = List.of("PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL");
        int from = minimum != null ? order.indexOf(minimum.trim().toUpperCase(Locale.ROOT)) : -1;
        List<String> classes = order.subList(from >= 0 ? from : order.indexOf("SENSITIVE"), order.size());
        return classes.size() == 1 ? classes.get(0)
                : String.join(", ", classes.subList(0, classes.size() - 1)) + " or " + classes.get(classes.size() - 1);
    }

    /**
     * The output format of the product version with the v5 answer schema in place, worked out once: a request reads it
     * and does no work for it.
     */
    static String productOutputFormat() {
        return FormatHolder.OUTPUT_FORMAT;
    }

    /** Whether the product version draws a part with its own text for an agent's request, worked out once. */
    static boolean productVariesByAgent() {
        return Holder.VARIES_BY_AGENT;
    }

    /** The product version, read, checked and assembled once: a document that cannot be read fails the start. */
    private static final class Holder {
        private static final AssembledPrompt PRODUCT = new PromptAssembler()
                .product(productDocument(RELEASES.get(RELEASES.size() - 1)));
        private static final boolean VARIES_BY_AGENT = PRODUCT
                .drawnParts(AssembledPrompt.JUDGMENT, Set.of(AGENT_REQUEST)).stream()
                .anyMatch(part -> part.whenText().containsKey(AGENT_REQUEST));
    }

    /**
     * Apart from {@link Holder}: the schema comes from the output contracts, whose meanings come from the product
     * version, so the version is read before the schema is made.
     */
    private static final class FormatHolder {
        private static final String OUTPUT_FORMAT = requiredOutputFormat();

        private static String requiredOutputFormat() {
            String format = outputFormat(product(), SecurityDecisionOutputContractV5.textSchema());
            if (format == null) {
                throw new IllegalStateException("The product prompt document has no output format part");
            }
            return format;
        }
    }
}
