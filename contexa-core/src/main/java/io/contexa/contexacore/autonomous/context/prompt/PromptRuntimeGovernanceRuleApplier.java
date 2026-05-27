package io.contexa.contexacore.autonomous.context.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public class PromptRuntimeGovernanceRuleApplier {

    public PromptRuntimeGovernanceRuleApplicationResult apply(
            String userPrompt,
            List<PromptRuntimeGovernanceRule> rules) {
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
            AppliedRule applied = applyRule(currentPrompt, rule);
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

    private AppliedRule applyRule(String prompt, PromptRuntimeGovernanceRule rule) {
        String ruleType = rule == null ? null : rule.ruleType();
        if (!StringUtils.hasText(ruleType)) {
            return new AppliedRule(prompt, "SKIPPED_UNSUPPORTED_RULE_TYPE");
        }
        if ("SUPPRESS_SLOT".equals(ruleType)) {
            return suppress(prompt, rule);
        }
        if ("UPDATE_SLOT_VALUE".equals(ruleType)) {
            return updateSlotValue(prompt, rule);
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
        String text = firstText(rule, "renderedValue", "narrative", "limitation", "runtimeInstruction", "completionCriterion");
        if (!StringUtils.hasText(text)) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        if (prompt.contains(text)) {
            return new AppliedRule(prompt, "SKIPPED_ALREADY_PRESENT");
        }
        String updated = prompt.endsWith("\n")
                ? prompt + text + "\n"
                : prompt + "\n" + text + "\n";
        return new AppliedRule(updated, "APPLIED");
    }

    private AppliedRule suppress(String prompt, PromptRuntimeGovernanceRule rule) {
        String pattern = firstText(rule, "suppressPattern", "label", "slotKey");
        if (!StringUtils.hasText(pattern) || !prompt.contains(pattern)) {
            return new AppliedRule(prompt, "SKIPPED_NO_MATCH");
        }
        StringBuilder result = new StringBuilder();
        for (String line : prompt.split("\\R", -1)) {
            if (!line.contains(pattern)) {
                result.append(line).append("\n");
            }
        }
        return new AppliedRule(result.toString(), "APPLIED");
    }

    private AppliedRule updateSlotValue(String prompt, PromptRuntimeGovernanceRule rule) {
        String label = firstText(rule, "label", "contextItem", "slotKey");
        String value = firstText(rule, "renderedValue", "runtimeInstruction");
        if (!StringUtils.hasText(label) || !StringUtils.hasText(value)) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        String replacement = label + ": " + value;
        StringBuilder result = new StringBuilder();
        boolean replaced = false;
        for (String line : prompt.split("\\R", -1)) {
            if (!replaced && line.startsWith(label + ":")) {
                result.append(replacement).append("\n");
                replaced = true;
                continue;
            }
            result.append(line).append("\n");
        }
        return new AppliedRule(replaced ? result.toString() : appendLine(prompt, replacement), "APPLIED");
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
}
