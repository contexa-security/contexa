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
package io.contexa.contexacore.autonomous.context.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.SecurityPromptSectionCatalog;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

public class PromptRuntimeGovernanceRuleApplier {

    public PromptRuntimeGovernanceRuleApplicationResult apply(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules) {
        return applyInternal(userPrompt, rules, null, false);
    }

    public PromptRuntimeGovernanceRuleApplicationResult apply(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules,
            PromptSlotPlanProvider slotPlanProvider) {
        return applyInternal(
                userPrompt,
                rules,
                slotPlanProvider == null ? null : slotPlanProvider::plansForSlotKey,
                false);
    }

    public PromptRuntimeGovernanceRuleApplicationResult apply(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules,
            PromptContextComposer promptContextComposer) {
        return applyInternal(
                userPrompt,
                rules,
                promptContextComposer == null ? null : promptContextComposer::plansForSlotKey,
                false);
    }

    /**
     * Applies the rules to a v19 section prompt (W3-14). A rule whose slot key is a slot of the v20 dictionary is a rule
     * of the v20 bundle and leaves the prompt as it is, whatever plan the slot contract rows give its key (the rows of
     * the enterprise carry no dictionary entry).
     */
    public PromptRuntimeGovernanceRuleApplicationResult applyToSectionPrompt(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules,
            PromptContextComposer promptContextComposer,
            PromptDictionarySlotPlanProvider dictionaryPlans) {
        SlotPlanResolver contractPlans = promptContextComposer == null
                ? (promptKey, slotKey) -> List.of()
                : promptContextComposer::plansForSlotKey;
        SlotPlanResolver sectionPlans = dictionaryPlans == null ? contractPlans : (promptKey, slotKey) -> {
            List<PromptSlotPlan> dictionarySlots = dictionaryPlans.plansForSlotKey(promptKey, slotKey);
            return dictionarySlots.isEmpty() ? contractPlans.resolve(promptKey, slotKey) : dictionarySlots;
        };
        return applyInternal(userPrompt, rules, sectionPlans, false);
    }

    /**
     * Applies the rules to a v20 user prompt (W3-14). A rule is applied only when its slot key is a slot of the
     * dictionary, inside the block of its entry, and it writes only lines of the entry in the entry's form; a rule of
     * the v19 bundle (v19 slot key) leaves the prompt as it is.
     */
    public PromptRuntimeGovernanceRuleApplicationResult applyToDictionaryPrompt(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules,
            PromptDictionarySlotPlanProvider dictionaryPlans) {
        return applyInternal(
                userPrompt,
                rules,
                dictionaryPlans == null ? (promptKey, slotKey) -> List.of() : dictionaryPlans::plansForSlotKey,
                true);
    }

    private PromptRuntimeGovernanceRuleApplicationResult applyInternal(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules,
            SlotPlanResolver slotPlanResolver) {
        return applyInternal(userPrompt, rules, slotPlanResolver, false);
    }

    private PromptRuntimeGovernanceRuleApplicationResult applyInternal(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules,
            SlotPlanResolver slotPlanResolver,
            boolean dictionaryPrompt) {
        String currentPrompt = userPrompt == null ? "" : userPrompt;
        if (rules == null || rules.isEmpty()) {
            return new PromptRuntimeGovernanceRuleApplicationResult(currentPrompt, List.of());
        }
        List<PromptRuntimeGovernanceRuleApplication> applications = new ArrayList<>();
        List<PromptRuntimeGovernanceRule> orderedRules = rules.stream()
                .sorted(Comparator.comparingInt(PromptRuntimeGovernanceRule::priority)
                        .thenComparing(PromptRuntimeGovernanceRule::ruleId, Comparator.nullsLast(String::compareTo)))
                .toList();
        for (PromptRuntimeGovernanceRule rule : orderedRules) {
            String before = currentPrompt;
            String beforeHash = PromptGovernanceSupport.sha256(before);
            AppliedRule applied;
            if (slotPlanResolver == null) {
                applied = applyRule(currentPrompt, rule);
            }
            else {
                SlotRuleScope scope = dictionaryPrompt
                        ? validateDictionarySlotScope(currentPrompt, rule, slotPlanResolver)
                        : validateSlotRuleScope(currentPrompt, rule, slotPlanResolver);
                if (!scope.valid()) {
                    applied = new AppliedRule(currentPrompt, scope.resultState());
                }
                else {
                    String scopedPrompt = currentPrompt.substring(scope.startInclusive(), scope.endExclusive());
                    AppliedRule scopedResult = dictionaryPrompt
                            ? applyDictionaryRule(scopedPrompt, rule, scope.entry(), scope.label())
                            : applyRule(scopedPrompt, rule);
                    String updated = currentPrompt.substring(0, scope.startInclusive())
                            + scopedResult.userPrompt()
                            + currentPrompt.substring(scope.endExclusive());
                    applied = new AppliedRule(updated, scopedResult.resultState());
                }
            }
            currentPrompt = applied.userPrompt();
            boolean changed = !before.equals(currentPrompt);
            applications.add(new PromptRuntimeGovernanceRuleApplication(
                    rule.ruleId(),
                    rule.sourceActionId(),
                    rule.slotKey(),
                    rule.ruleType(),
                    operation(rule),
                    changed,
                    changed ? "APPLIED" : applied.resultState(),
                    beforeHash,
                    PromptGovernanceSupport.sha256(currentPrompt)));
        }
        return new PromptRuntimeGovernanceRuleApplicationResult(currentPrompt, List.copyOf(applications));
    }

    /**
     * The scope of a rule on a v20 prompt: the block of its dictionary entry. A slot key that is not a dictionary slot
     * (a rule of the v19 bundle) is not applied. Repeated lines of the entry are a fault of the block, which a rule that
     * writes or removes the entry's line repairs; a rule that moves or replaces one line needs exactly one.
     */
    private SlotRuleScope validateDictionarySlotScope(
            String prompt,
            PromptRuntimeGovernanceRule rule,
            SlotPlanResolver slotPlanResolver) {
        if (rule == null || !StringUtils.hasText(rule.slotKey())) {
            return SlotRuleScope.invalid("SKIPPED_SLOT_KEY_REQUIRED");
        }
        List<PromptSlotPlan> plans = slotPlanResolver.resolve(rule.promptKey(), rule.slotKey());
        if (plans == null || plans.isEmpty()) {
            return SlotRuleScope.invalid("SKIPPED_SLOT_NOT_IN_DICTIONARY");
        }
        if (plans.size() != 1) {
            return SlotRuleScope.invalid("SKIPPED_DUPLICATE_SLOT_CONTRACT");
        }
        PromptDictionaryEntry entry = plans.get(0) == null ? null : plans.get(0).dictionaryEntry();
        if (entry == null) {
            return SlotRuleScope.invalid("SKIPPED_SLOT_NOT_IN_DICTIONARY");
        }
        String requestedSection = firstText(rule, "sectionKey");
        if (StringUtils.hasText(requestedSection)
                && PromptBlock.fromSectionKey(requestedSection).filter(entry.block()::equals).isEmpty()) {
            return SlotRuleScope.invalid("SKIPPED_SECTION_MISMATCH");
        }
        List<SectionRange> blocks = blockRanges(prompt, entry.block());
        if (blocks.isEmpty()) {
            return SlotRuleScope.invalid("SKIPPED_SECTION_NOT_FOUND");
        }
        if (blocks.size() != 1) {
            return SlotRuleScope.invalid("SKIPPED_DUPLICATE_SECTION");
        }
        SectionRange block = blocks.get(0);
        String label = targetLabel(rule, entry);
        if (requiresRenderedSlot(rule.ruleType())) {
            int renderedLines = countEntryLines(
                    prompt.substring(block.startInclusive(), block.endExclusive()), entry, label);
            if (renderedLines == 0) {
                return SlotRuleScope.invalid("SKIPPED_SLOT_NOT_RENDERED");
            }
            if (renderedLines > 1 && (label == null || !mergesRepeatedLines(rule.ruleType()))) {
                return SlotRuleScope.invalid("SKIPPED_DUPLICATE_RENDERED_SLOT");
            }
        }
        return new SlotRuleScope(true, block.startInclusive(), block.endExclusive(), "VALID", entry, label);
    }

    /** The ranges of a v20 block: from its header ({@code === TITLE ===} or {@code === TITLE (...) ===}) to the next. */
    private List<SectionRange> blockRanges(String prompt, PromptBlock block) {
        if (!StringUtils.hasText(prompt)) {
            return List.of();
        }
        String[] lines = prompt.split("\\n", -1);
        List<Integer> lineStarts = new ArrayList<>();
        int offset = 0;
        for (String line : lines) {
            lineStarts.add(offset);
            offset += line.length() + 1;
        }
        String plainHeader = "=== " + block.title() + " ===";
        String qualifiedHeader = "=== " + block.title() + " (";
        List<SectionRange> ranges = new ArrayList<>();
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index];
            if (!line.equals(plainHeader) && !(line.startsWith(qualifiedHeader) && line.endsWith(") ==="))) {
                continue;
            }
            int endIndex = index + 1;
            while (endIndex < lines.length && !lines[endIndex].startsWith("=== ")) {
                endIndex++;
            }
            int end = endIndex < lineStarts.size() ? lineStarts.get(endIndex) : prompt.length();
            ranges.add(new SectionRange(lineStarts.get(index), Math.min(end, prompt.length())));
        }
        return List.copyOf(ranges);
    }

    /**
     * The line a rule targets: the numbered line its label names ({@code PastRecord2}), or the entry's one line; null
     * for a numbered entry without a numbered label (all its lines).
     */
    private String targetLabel(PromptRuntimeGovernanceRule rule, PromptDictionaryEntry entry) {
        String named = firstText(rule, "label", "contextItem");
        if (StringUtils.hasText(named) && entry.matchesLabel(named)) {
            return named;
        }
        return entry.indexed() ? null : entry.name();
    }

    private int countEntryLines(String block, PromptDictionaryEntry entry, String label) {
        int count = 0;
        for (String line : block.split("\\n", -1)) {
            if (isEntryLine(PromptDictionaryLine.parse(line), entry, label)) {
                count++;
            }
        }
        return count;
    }

    private boolean isEntryLine(PromptDictionaryLine line, PromptDictionaryEntry entry, String label) {
        return line != null && (label != null ? label.equals(line.label()) : entry.matchesLabel(line.label()));
    }

    private boolean mergesRepeatedLines(String ruleType) {
        return "UPDATE_SLOT_VALUE".equals(ruleType)
                || "SUPPRESS_SLOT".equals(ruleType)
                || "FORBID_TRUNCATION".equals(ruleType);
    }

    /**
     * A rule on the block of its entry. The v20 counterpart of {@link #applyRule}: every line of a v20 block is a
     * dictionary entry, so a rule writes only a line of its entry in the entry's form, and the official repair mends
     * the faults the v20 fault injector put into the entries without adding lines of the v19 prompt.
     */
    private AppliedRule applyDictionaryRule(
            String block,
            PromptRuntimeGovernanceRule rule,
            PromptDictionaryEntry entry,
            String label) {
        String ruleType = rule == null ? null : rule.ruleType();
        if (!StringUtils.hasText(ruleType)) {
            return new AppliedRule(block, "SKIPPED_UNSUPPORTED_RULE_TYPE");
        }
        AppliedRule applied = switch (ruleType) {
            case "SUPPRESS_SLOT" -> suppressInBlock(block, rule, entry);
            case "UPDATE_SLOT_VALUE" -> updateEntry(block, rule, entry, label);
            case "ADD_SLOT" -> addEntryLine(block, rule, entry);
            case "FORBID_TRUNCATION" -> addEntryLine(block, rule, entry);
            case "REORDER_SLOT", "RAISE_PRIORITY" -> reorder(block, rule);
            case "REPLACE_SECTION_POLICY" -> replaceWithEntryLine(block, rule, entry);
            case "RECOLLECT_INPUT" -> new AppliedRule(block, "SKIPPED_INPUT_RECOLLECTION_REQUIRED");
            case "ADD_NARRATIVE", "ADD_LIMITATION" -> addEntryLine(block, rule, entry);
            default -> new AppliedRule(block, "SKIPPED_UNSUPPORTED_RULE_TYPE");
        };
        return new AppliedRule(keepTrailingLineBreaks(block, applied.userPrompt()), applied.resultState());
    }

    private AppliedRule suppressInBlock(String block, PromptRuntimeGovernanceRule rule, PromptDictionaryEntry entry) {
        String pattern = firstText(rule, "suppressPattern", "label");
        if (!StringUtils.hasText(pattern)) {
            return new AppliedRule(block, "SKIPPED_NO_MATCH");
        }
        return removeLines(block, line -> matchesSuppression(line, pattern, entry));
    }

    private boolean matchesSuppression(String line, String pattern, PromptDictionaryEntry entry) {
        if (entry.name().equals(pattern) || entry.matchesLabel(pattern)) {
            PromptDictionaryLine entryLine = PromptDictionaryLine.parse(line);
            return entryLine != null && (entry.name().equals(pattern)
                    ? entry.matchesLabel(entryLine.label())
                    : pattern.equals(entryLine.label()));
        }
        return line.contains(pattern);
    }

    /**
     * Writes the value on the entry's line, keeping the line's fact id, and drops the entry's repeated lines in the
     * block: the v20 counterpart of writing one value on every alias line of a v19 fact (one name per fact in v20).
     */
    private AppliedRule updateEntry(
            String block,
            PromptRuntimeGovernanceRule rule,
            PromptDictionaryEntry entry,
            String label) {
        String value = firstText(rule, "renderedValue", "runtimeInstruction");
        if (!StringUtils.hasText(value)) {
            return new AppliedRule(block, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        if (isUnusablePromptValue(value)) {
            return new AppliedRule(block, "SKIPPED_UNUSABLE_RUNTIME_VALUE");
        }
        if (!acceptsEntryValue(entry, value)) {
            return new AppliedRule(block, "SKIPPED_VALUE_NOT_IN_ENTRY_FORM");
        }
        List<String> result = new ArrayList<>();
        boolean written = false;
        for (String line : block.split("\\n", -1)) {
            PromptDictionaryLine entryLine = PromptDictionaryLine.parse(line);
            if (isEntryLine(entryLine, entry, label)) {
                if (!written) {
                    result.add(entryLine.withValue(value));
                    written = true;
                }
                continue;
            }
            result.add(line);
        }
        return written
                ? new AppliedRule(String.join("\n", result), "APPLIED")
                : new AppliedRule(block, "SKIPPED_SLOT_NOT_RENDERED");
    }

    /** Adds a line of the rule's entry in the entry's form at the end of the block; free text is not a v20 line. */
    private AppliedRule addEntryLine(String block, PromptRuntimeGovernanceRule rule, PromptDictionaryEntry entry) {
        String text = firstText(
                rule, "renderedValue", "narrative", "limitation", "runtimeInstruction", "completionCriterion");
        if (!StringUtils.hasText(text)) {
            return new AppliedRule(block, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        AppliedRule invalid = invalidEntryLine(block, text, entry);
        if (invalid != null) {
            return invalid;
        }
        PromptDictionaryLine line = PromptDictionaryLine.parse(text.trim());
        if (countEntryLines(block, entry, line.label()) > 0) {
            return new AppliedRule(block, "SKIPPED_ALREADY_PRESENT");
        }
        return new AppliedRule(appendInBlock(block, line.label() + ": " + line.value()), "APPLIED");
    }

    private AppliedRule replaceWithEntryLine(String block, PromptRuntimeGovernanceRule rule, PromptDictionaryEntry entry) {
        String replacement = firstText(rule, "renderedValue", "sectionPolicy", "runtimeInstruction");
        if (StringUtils.hasText(replacement)) {
            AppliedRule invalid = invalidEntryLine(block, replacement, entry);
            if (invalid != null) {
                return invalid;
            }
        }
        return replaceSectionPolicy(block, rule);
    }

    /** Why a text is not a line of the entry in its form, or null when it is. */
    private AppliedRule invalidEntryLine(String block, String text, PromptDictionaryEntry entry) {
        PromptDictionaryLine line = PromptDictionaryLine.parse(text.trim());
        if (line == null || !line.factId().isEmpty() || !entry.matchesLabel(line.label())) {
            return new AppliedRule(block, "SKIPPED_FREE_TEXT_ON_DICTIONARY_PROMPT");
        }
        if (!acceptsEntryValue(entry, line.value())) {
            return new AppliedRule(block, "SKIPPED_VALUE_NOT_IN_ENTRY_FORM");
        }
        return null;
    }

    private boolean acceptsEntryValue(PromptDictionaryEntry entry, String value) {
        return entry.acceptsValue(value) || (entry.missingText() != null && entry.missingText().equals(value));
    }

    private AppliedRule removeLines(String block, Predicate<String> removed) {
        List<String> kept = new ArrayList<>();
        boolean changed = false;
        for (String line : block.split("\\n", -1)) {
            if (removed.test(line)) {
                changed = true;
                continue;
            }
            kept.add(line);
        }
        return changed
                ? new AppliedRule(String.join("\n", kept), "APPLIED")
                : new AppliedRule(block, "SKIPPED_NO_MATCH");
    }

    /** Adds a line after the last line of the block, before the blank line that ends it. */
    private String appendInBlock(String block, String line) {
        int end = trailingLineBreaksStart(block);
        return block.substring(0, end) + "\n" + line + block.substring(end);
    }

    /** The block's text with the line breaks that end the original block (the v19 line helpers end with one more). */
    private String keepTrailingLineBreaks(String original, String updated) {
        if (updated == null || original.equals(updated)) {
            return updated;
        }
        return updated.substring(0, trailingLineBreaksStart(updated))
                + original.substring(trailingLineBreaksStart(original));
    }

    private int trailingLineBreaksStart(String text) {
        int end = text.length();
        while (end > 0 && text.charAt(end - 1) == '\n') {
            end--;
        }
        return end;
    }

    private SlotRuleScope validateSlotRuleScope(
            String prompt,
            PromptRuntimeGovernanceRule rule,
            SlotPlanResolver slotPlanResolver) {
        if (rule == null || !StringUtils.hasText(rule.slotKey())) {
            return SlotRuleScope.invalid("SKIPPED_SLOT_KEY_REQUIRED");
        }
        List<PromptSlotPlan> plans = slotPlanResolver.resolve(rule.promptKey(), rule.slotKey());
        if (plans == null || plans.isEmpty()) {
            return SlotRuleScope.invalid("SKIPPED_SLOT_NOT_FOUND");
        }
        if (plans.size() != 1) {
            return SlotRuleScope.invalid("SKIPPED_DUPLICATE_SLOT_CONTRACT");
        }
        PromptSlotPlan plan = plans.get(0);
        if (plan == null || !StringUtils.hasText(plan.sectionKey())) {
            return SlotRuleScope.invalid("SKIPPED_INVALID_SLOT_CONTRACT");
        }
        if (plan.dictionaryEntry() != null) {
            // A rule of the v20 dictionary does not apply to a v19 section prompt (W3-14).
            return SlotRuleScope.invalid("SKIPPED_DICTIONARY_SLOT_ON_SECTION_PROMPT");
        }
        if (requiresRenderedSlot(rule.ruleType()) && !StringUtils.hasText(plan.labelKey())) {
            return SlotRuleScope.invalid("SKIPPED_INVALID_SLOT_CONTRACT");
        }
        String requestedSection = firstText(rule, "sectionKey");
        if (StringUtils.hasText(requestedSection)
                && !normalize(requestedSection).equals(normalize(plan.sectionKey()))) {
            return SlotRuleScope.invalid("SKIPPED_SECTION_MISMATCH");
        }
        List<SectionRange> sectionRanges = sectionRanges(prompt, plan.sectionKey());
        if (sectionRanges.isEmpty()) {
            if (!StringUtils.hasText(plan.labelKey())) {
                sectionRanges = List.of(new SectionRange(0, prompt.length()));
            }
            else {
                int renderedSlotCount = countExactLabel(prompt, plan.labelKey());
                if (renderedSlotCount > 1) {
                    return SlotRuleScope.invalid("SKIPPED_DUPLICATE_RENDERED_SLOT");
                }
                if (renderedSlotCount == 0) {
                    return SlotRuleScope.invalid("SKIPPED_SECTION_NOT_FOUND");
                }
                sectionRanges = sectionRangeForUniqueLabel(prompt, plan.labelKey());
                if (sectionRanges.isEmpty()) {
                    return SlotRuleScope.invalid("SKIPPED_SECTION_NOT_FOUND");
                }
            }
        }
        if (sectionRanges.size() != 1) {
            return SlotRuleScope.invalid("SKIPPED_DUPLICATE_SECTION");
        }
        SectionRange section = sectionRanges.get(0);
        String sectionText = prompt.substring(section.startInclusive(), section.endExclusive());
        int renderedSlotCount = countExactLabel(sectionText, plan.labelKey());
        if (renderedSlotCount > 1) {
            return SlotRuleScope.invalid("SKIPPED_DUPLICATE_RENDERED_SLOT");
        }
        if (requiresRenderedSlot(rule.ruleType()) && renderedSlotCount == 0) {
            return SlotRuleScope.invalid("SKIPPED_SLOT_NOT_RENDERED");
        }
        return new SlotRuleScope(true, section.startInclusive(), section.endExclusive(), "VALID", null, null);
    }

    private List<SectionRange> sectionRanges(String prompt, String sectionKey) {
        if (!StringUtils.hasText(prompt) || !StringUtils.hasText(sectionKey)) {
            return List.of();
        }
        String[] lines = prompt.split("\\n", -1);
        List<Integer> lineStarts = new ArrayList<>();
        int offset = 0;
        for (String line : lines) {
            lineStarts.add(offset);
            offset += line.length() + 1;
        }
        List<String> expectedMarkers = SecurityPromptSectionCatalog.headersFor(sectionKey.trim());
        if (expectedMarkers.isEmpty()) {
            expectedMarkers = List.of("=== " + sectionKey.trim() + " ===");
        }
        List<SectionRange> ranges = new ArrayList<>();
        for (int index = 0; index < lines.length; index++) {
            String renderedLine = lines[index].trim();
            if (!lines[index].equals(renderedLine) || !expectedMarkers.contains(renderedLine)) {
                continue;
            }
            int endIndex = index + 1;
            while (endIndex < lines.length && !lines[endIndex].startsWith("=== ")) {
                endIndex++;
            }
            int end = endIndex < lineStarts.size() ? lineStarts.get(endIndex) : prompt.length();
            ranges.add(new SectionRange(lineStarts.get(index), Math.min(end, prompt.length())));
        }
        return List.copyOf(ranges);
    }

    private List<SectionRange> sectionRangeForUniqueLabel(String prompt, String label) {
        if (!StringUtils.hasText(prompt) || !StringUtils.hasText(label)) {
            return List.of();
        }
        String[] lines = prompt.split("\\n", -1);
        List<Integer> lineStarts = new ArrayList<>();
        int offset = 0;
        int labelIndex = -1;
        for (int index = 0; index < lines.length; index++) {
            lineStarts.add(offset);
            offset += lines[index].length() + 1;
            if (isExactLabelLine(lines[index], label)) {
                if (labelIndex >= 0) {
                    return List.of();
                }
                labelIndex = index;
            }
        }
        if (labelIndex < 0) {
            return List.of();
        }
        int sectionIndex = labelIndex;
        while (sectionIndex >= 0 && !lines[sectionIndex].startsWith("=== ")) {
            sectionIndex--;
        }
        if (sectionIndex < 0) {
            return List.of();
        }
        int endIndex = labelIndex + 1;
        while (endIndex < lines.length && !lines[endIndex].startsWith("=== ")) {
            endIndex++;
        }
        int end = endIndex < lineStarts.size() ? lineStarts.get(endIndex) : prompt.length();
        return List.of(new SectionRange(lineStarts.get(sectionIndex), Math.min(end, prompt.length())));
    }

    private int countExactLabel(String sectionText, String label) {
        int count = 0;
        for (String line : sectionText.split("\\R")) {
            if (isExactLabelLine(line, label)) {
                count++;
            }
        }
        return count;
    }

    private boolean isExactLabelLine(String line, String label) {
        return line != null
                && StringUtils.hasText(label)
                && line.stripLeading().startsWith(label.trim() + ":");
    }

    private boolean requiresRenderedSlot(String ruleType) {
        return "UPDATE_SLOT_VALUE".equals(ruleType)
                || "SUPPRESS_SLOT".equals(ruleType)
                || "REORDER_SLOT".equals(ruleType)
                || "RAISE_PRIORITY".equals(ruleType)
                || "FORBID_TRUNCATION".equals(ruleType)
                || "REPLACE_SECTION_POLICY".equals(ruleType);
    }

    private AppliedRule applyRule(
            String prompt,
            PromptRuntimeGovernanceRule rule) {
        String ruleType = rule == null ? null : rule.ruleType();
        if (!StringUtils.hasText(ruleType)) {
            return new AppliedRule(prompt, "SKIPPED_UNSUPPORTED_RULE_TYPE");
        }
        if ("SUPPRESS_SLOT".equals(ruleType)) {
            return suppressExact(prompt, rule);
        }
        if ("UPDATE_SLOT_VALUE".equals(ruleType)) {
            return updateSlotValue(prompt, rule);
        }
        if ("ADD_SLOT".equals(ruleType)) {
            return appendConfiguredText(prompt, rule);
        }
        if ("FORBID_TRUNCATION".equals(ruleType)) {
            return appendConfiguredText(prompt, rule);
        }
        if ("REORDER_SLOT".equals(ruleType) || "RAISE_PRIORITY".equals(ruleType)) {
            return reorder(prompt, rule);
        }
        if ("REPLACE_SECTION_POLICY".equals(ruleType)) {
            return replaceSectionPolicy(prompt, rule);
        }
        if ("RECOLLECT_INPUT".equals(ruleType)) {
            return new AppliedRule(prompt, "SKIPPED_INPUT_RECOLLECTION_REQUIRED");
        }
        if ("ADD_NARRATIVE".equals(ruleType) || "ADD_LIMITATION".equals(ruleType)) {
            return appendConfiguredText(prompt, rule);
        }
        return new AppliedRule(prompt, "SKIPPED_UNSUPPORTED_RULE_TYPE");
    }

    private AppliedRule suppressExact(String prompt, PromptRuntimeGovernanceRule rule) {
        String pattern = firstText(rule, "suppressPattern", "label");
        if (!StringUtils.hasText(pattern) || !prompt.contains(pattern)) {
            return new AppliedRule(prompt, "SKIPPED_NO_MATCH");
        }
        StringBuilder result = new StringBuilder();
        boolean removed = false;
        for (String line : prompt.split("\\R", -1)) {
            if (line.contains(pattern)) {
                removed = true;
                continue;
            }
            result.append(line).append("\n");
        }
        return removed
                ? new AppliedRule(result.toString(), "APPLIED")
                : new AppliedRule(prompt, "SKIPPED_NO_MATCH");
    }

    private AppliedRule appendConfiguredText(String prompt, PromptRuntimeGovernanceRule rule) {
        String text = firstText(
                rule, "renderedValue", "narrative", "limitation", "runtimeInstruction", "completionCriterion");
        if (!StringUtils.hasText(text)) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        if (prompt.contains(text)) {
            return new AppliedRule(prompt, "SKIPPED_ALREADY_PRESENT");
        }
        return new AppliedRule(appendLine(prompt, text), "APPLIED");
    }

    private AppliedRule updateSlotValue(String prompt, PromptRuntimeGovernanceRule rule) {
        String label = firstText(rule, "label", "contextItem", "slotKey");
        String value = firstText(rule, "renderedValue", "runtimeInstruction");
        if (!StringUtils.hasText(label) || !StringUtils.hasText(value)) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        if (isUnusablePromptValue(value)) {
            return new AppliedRule(prompt, "SKIPPED_UNUSABLE_RUNTIME_VALUE");
        }
        List<String> labels = equivalentPromptLabels(label);
        StringBuilder result = new StringBuilder();
        boolean replaced = false;
        List<String> writtenLabels = new ArrayList<>();
        for (String line : prompt.split("\\R", -1)) {
            String matchedLabel = matchingPromptLabel(line, labels);
            if (matchedLabel != null) {
                if (!writtenLabels.contains(matchedLabel)) {
                    result.append(matchedLabel).append(": ").append(value).append("\n");
                    writtenLabels.add(matchedLabel);
                }
                replaced = true;
                continue;
            }
            result.append(line).append("\n");
        }
        if (!replaced) {
            return new AppliedRule(appendLine(prompt, label + ": " + value), "APPLIED");
        }
        return new AppliedRule(result.toString(), "APPLIED");
    }

    private boolean isUnusablePromptValue(String value) {
        if (!StringUtils.hasText(value)) {
            return true;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return "N/A".equals(normalized)
                || "NA".equals(normalized)
                || "UNKNOWN".equals(normalized)
                || "MISSING".equals(normalized)
                || "NULL".equals(normalized)
                || normalized.startsWith("UNKNOWN ")
                || normalized.contains(" NOT AVAILABLE")
                || normalized.contains(" NOT SUPPLIED")
                || normalized.contains(" NO RELIABLE")
                || normalized.contains(" DO NOT ASSUME")
                || "없음".equals(value.trim())
                || "정보 없음".equals(value.trim())
                || "데이터 없음".equals(value.trim())
                || "해당 없음".equals(value.trim());
    }

    private List<String> equivalentPromptLabels(String label) {
        if (!StringUtils.hasText(label)) {
            return List.of();
        }
        String normalized = normalize(label);
        if ("PATH".equals(normalized) || "REQUESTPATH".equals(normalized)) {
            return List.of("Path", "RequestPath");
        }
        if ("METHOD".equals(normalized) || "HTTPMETHOD".equals(normalized)) {
            return List.of("HttpMethod", "Method");
        }
        if ("ACTIONFAMILY".equals(normalized) || "CURRENTACTIONFAMILY".equals(normalized)) {
            return List.of("ActionFamily", "CurrentActionFamily");
        }
        if ("RESOURCEID".equals(normalized) || "RESOURCE ID".equals(normalized.replace("_", " "))) {
            return List.of("ResourceId", "Resource ID");
        }
        return List.of(label);
    }

    private String matchingPromptLabel(String line, List<String> labels) {
        if (!StringUtils.hasText(line) || labels == null || labels.isEmpty()) {
            return null;
        }
        String trimmed = line.stripLeading();
        for (String label : labels) {
            if (StringUtils.hasText(label) && trimmed.startsWith(label + ":")) {
                return label;
            }
        }
        return null;
    }

    private AppliedRule reorder(String prompt, PromptRuntimeGovernanceRule rule) {
        String target = firstText(rule, "label", "contextItem", "slotKey", "targetPattern");
        String anchor = firstText(rule, "anchorLabel", "anchorPattern", "beforeLabel", "afterLabel");
        if (!StringUtils.hasText(target) || !StringUtils.hasText(anchor)) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        String[] lines = prompt.split("\\R", -1);
        int targetIndex = indexOfLineContaining(lines, target);
        int anchorIndex = indexOfLineContaining(lines, anchor);
        if (targetIndex < 0 || anchorIndex < 0 || targetIndex == anchorIndex) {
            return new AppliedRule(prompt, "SKIPPED_NO_MATCH");
        }
        List<String> reordered = new ArrayList<>(List.of(lines));
        String line = reordered.remove(targetIndex);
        if (targetIndex < anchorIndex) {
            anchorIndex--;
        }
        String placement = firstText(rule, "placement");
        int insertIndex = "AFTER".equals(normalize(placement)) ? anchorIndex + 1 : anchorIndex;
        reordered.add(Math.max(0, Math.min(insertIndex, reordered.size())), line);
        return new AppliedRule(String.join("\n", reordered), "APPLIED");
    }

    private AppliedRule replaceSectionPolicy(String prompt, PromptRuntimeGovernanceRule rule) {
        String target = firstText(rule, "targetPattern", "sectionKey", "label", "contextItem", "slotKey");
        String replacement = firstText(rule, "renderedValue", "sectionPolicy", "runtimeInstruction");
        if (!StringUtils.hasText(target) || !StringUtils.hasText(replacement)) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        StringBuilder result = new StringBuilder();
        boolean replaced = false;
        for (String line : prompt.split("\\R", -1)) {
            if (!replaced && line.contains(target)) {
                result.append(replacement).append("\n");
                replaced = true;
                continue;
            }
            result.append(line).append("\n");
        }
        return replaced ? new AppliedRule(result.toString(), "APPLIED") : new AppliedRule(prompt, "SKIPPED_NO_MATCH");
    }

    private String appendLine(String prompt, String line) {
        return prompt.endsWith("\n") ? prompt + line + "\n" : prompt + "\n" + line + "\n";
    }

    private int indexOfLineContaining(String[] lines, String text) {
        if (lines == null || !StringUtils.hasText(text)) {
            return -1;
        }
        for (int index = 0; index < lines.length; index++) {
            if (lines[index] != null && lines[index].contains(text)) {
                return index;
            }
        }
        return -1;
    }

    private String firstText(PromptRuntimeGovernanceRule rule, String... keys) {
        if (rule == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = rule.payloadText(key);
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String operation(PromptRuntimeGovernanceRule rule) {
        return rule == null || !StringUtils.hasText(rule.ruleType())
                ? "UNKNOWN"
                : rule.ruleType();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private record AppliedRule(String userPrompt, String resultState) {
    }

    private record SectionRange(int startInclusive, int endExclusive) {
    }

    private record SlotRuleScope(
            boolean valid,
            int startInclusive,
            int endExclusive,
            String resultState,
            PromptDictionaryEntry entry,
            String label) {
        private static SlotRuleScope invalid(String resultState) {
            return new SlotRuleScope(false, 0, 0, resultState, null, null);
        }
    }

    @FunctionalInterface
    private interface SlotPlanResolver {
        List<PromptSlotPlan> resolve(String promptKey, String slotKey);
    }
}

