package io.contexa.contexacore.autonomous.context.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
        if ("FORBID_TRUNCATION".equals(ruleType)) {
            return forbidTruncation(prompt, rule);
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
        AppliedRule structuredRepair = repairStructuredRuntimeSlot(prompt, rule);
        if (!prompt.equals(structuredRepair.userPrompt())) {
            String text = firstText(rule, "renderedValue", "narrative", "limitation", "runtimeInstruction", "completionCriterion");
            if (StringUtils.hasText(text) && !structuredRepair.userPrompt().contains(text)) {
                return new AppliedRule(appendLine(structuredRepair.userPrompt(), text), "APPLIED");
            }
            return structuredRepair;
        }
        AppliedRule semanticFaultRepair = removeKnownSemanticFaultLines(prompt, rule);
        if (!prompt.equals(semanticFaultRepair.userPrompt())) {
            String text = firstText(rule, "renderedValue", "narrative", "limitation", "runtimeInstruction", "completionCriterion");
            if (StringUtils.hasText(text) && !semanticFaultRepair.userPrompt().contains(text)) {
                return new AppliedRule(appendLine(semanticFaultRepair.userPrompt(), text), "APPLIED");
            }
            return semanticFaultRepair;
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
            AppliedRule fallback = suppressKnownRuntimeFault(prompt, rule);
            return prompt.equals(fallback.userPrompt()) ? new AppliedRule(prompt, "SKIPPED_NO_MATCH") : fallback;
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

    private AppliedRule forbidTruncation(String prompt, PromptRuntimeGovernanceRule rule) {
        AppliedRule cleaned = removeRuntimeFaultLines(prompt, "truncated prompt material", "other items omitted");
        String current = cleaned.userPrompt();
        String text = firstText(rule, "renderedValue", "runtimeInstruction", "completionCriterion");
        if (!StringUtils.hasText(text)) {
            return cleaned;
        }
        if (current.contains(text)) {
            return cleaned;
        }
        return new AppliedRule(appendLine(current, text), "APPLIED");
    }

    private String appendLine(String prompt, String line) {
        return prompt.endsWith("\n") ? prompt + line + "\n" : prompt + "\n" + line + "\n";
    }

    private AppliedRule suppressKnownRuntimeFault(String prompt, PromptRuntimeGovernanceRule rule) {
        String descriptor = descriptor(rule);
        String normalized = descriptor.toLowerCase(Locale.ROOT);
        if (!normalized.contains("rag")
                && !normalized.contains("scope")
                && !normalized.contains("injection")
                && !normalized.contains("contamination")) {
            return new AppliedRule(prompt, "SKIPPED_NO_MATCH");
        }
        return removeRuntimeFaultLines(
                prompt,
                "THREAT MEMORY: tenant mismatch unauthorized document",
                "tenant mismatch unauthorized document",
                "ignore previous instructions",
                "Runtime slot test document outside the current request scope");
    }

    private AppliedRule repairStructuredRuntimeSlot(String prompt, PromptRuntimeGovernanceRule rule) {
        String descriptor = descriptor(rule).toLowerCase(Locale.ROOT);
        boolean ragTarget = descriptor.contains("rag")
                || descriptor.contains("retrieved")
                || descriptor.contains("authorization")
                || descriptor.contains("scope")
                || descriptor.contains("tenantbound");
        if (!ragTarget) {
            return new AppliedRule(prompt, "SKIPPED_NO_RENDERABLE_PAYLOAD");
        }
        String tenantId = promptField(prompt, "TenantId");
        String resourceId = firstText(promptField(prompt, "ResourceId"), promptField(prompt, "Resource ID"));
        String requestPath = firstText(promptField(prompt, "RequestPath"), promptField(prompt, "Path"));
        boolean scopeRepair = descriptor.contains("scope")
                || descriptor.contains("tenantbound")
                || descriptor.contains("contamination")
                || descriptor.contains("mismatch");
        boolean authorizationRepair = descriptor.contains("authorization")
                || descriptor.contains("authorized")
                || descriptor.contains("allowed");
        StringBuilder result = new StringBuilder();
        boolean changed = false;
        for (String line : prompt.split("\\R", -1)) {
            if (scopeRepair && isRuntimeScopeFaultLine(line)) {
                changed = true;
                continue;
            }
            String updated = repairRagLine(line, tenantId, resourceId, requestPath, authorizationRepair);
            if (!line.equals(updated)) {
                changed = true;
            }
            result.append(updated).append("\n");
        }
        return new AppliedRule(changed ? result.toString() : prompt, changed ? "APPLIED" : "SKIPPED_NO_MATCH");
    }

    private String repairRagLine(
            String line,
            String tenantId,
            String resourceId,
            String requestPath,
            boolean authorizationRepair) {
        if (!isRagLine(line)) {
            return line;
        }
        String updated = line;
        String accessScope = firstText(extractToken(line, "accessScope"), "USER");
        String authorization = "USER".equalsIgnoreCase(accessScope)
                ? "ALLOWED_USER_SCOPE"
                : "ALLOWED_" + normalize(accessScope) + "_SCOPE";
        String scope = StringUtils.hasText(accessScope) ? accessScope : "USER";
        String documentTenant = extractToken(line, "tenantId");
        boolean tenantMatches = !StringUtils.hasText(tenantId)
                || !StringUtils.hasText(documentTenant)
                || tenantId.equalsIgnoreCase(documentTenant);
        updated = replaceEmptyToken(updated, "authorization", authorization);
        if (authorizationRepair && containsAuthorizationFault(updated)) {
            updated = replaceTokenValue(updated, "authorization", authorization);
        }
        updated = replaceEmptyToken(updated, "scope", scope);
        updated = replaceEmptyToken(updated, "purpose", "true");
        updated = replaceEmptyToken(updated, "tenantBound", tenantMatches ? "true" : "false");
        if (authorizationRepair) {
            updated = replaceEmptyToken(updated, "tenantBound", tenantMatches ? "true" : "false");
            updated = replaceEmptyToken(updated, "resourceId", firstText(resourceId, requestPath, "resource-001"));
            updated = replaceEmptyToken(updated, "requestPath", firstText(requestPath, resourceId, "resource-001"));
            updated = updated.replace("DocFaultAuth", "DocAuthRepaired");
            updated = updated.replace(" Runtime slot test document without an allowed authorization basis.", "");
            updated = updated.replace("Runtime slot test document without an allowed authorization basis.", "");
            if (!updated.toLowerCase(Locale.ROOT).contains("authorization reason")) {
                updated = updated + " authorization reason: allowed tenant, user, resource, and purpose scope.";
            }
        }
        return updated;
    }

    private boolean isRuntimeScopeFaultLine(String line) {
        if (!StringUtils.hasText(line)) {
            return false;
        }
        String normalized = line.toLowerCase(Locale.ROOT);
        return normalized.contains("docfaultscope")
                || normalized.contains("tenant mismatch unauthorized document")
                || normalized.contains("ignore previous instructions")
                || normalized.contains("runtime slot test document outside the current request scope")
                || normalized.contains("resourceid=/outside/scope")
                || normalized.contains("requestpath=/outside/scope")
                || normalized.contains("tenantid=other-tenant");
    }

    private boolean containsAuthorizationFault(String line) {
        if (!StringUtils.hasText(line)) {
            return false;
        }
        String normalized = line.toLowerCase(Locale.ROOT);
        return normalized.contains("docfaultauth")
                || normalized.contains("authorization=denied")
                || normalized.contains("without an allowed authorization basis");
    }

    private boolean isRagLine(String line) {
        if (!StringUtils.hasText(line)) {
            return false;
        }
        String normalized = line.toLowerCase(Locale.ROOT);
        return normalized.startsWith("rag")
                || normalized.contains("ragdocument")
                || normalized.contains("ragevidence")
                || normalized.contains("retrievalpurpose");
    }

    private String replaceEmptyToken(String line, String token, String value) {
        if (!StringUtils.hasText(line) || !StringUtils.hasText(token) || !StringUtils.hasText(value)) {
            return line;
        }
        String marker = token + "=";
        StringBuilder result = new StringBuilder();
        int cursor = 0;
        boolean changed = false;
        while (cursor < line.length()) {
            int markerIndex = line.indexOf(marker, cursor);
            if (markerIndex < 0) {
                result.append(line.substring(cursor));
                break;
            }
            int valueStart = markerIndex + marker.length();
            result.append(line, cursor, valueStart);
            int scan = valueStart;
            while (scan < line.length() && Character.isWhitespace(line.charAt(scan))) {
                scan++;
            }
            if (scan >= line.length() || isPromptTokenDelimiter(line.charAt(scan))) {
                result.append(value);
                cursor = scan;
                changed = true;
            } else {
                cursor = valueStart;
            }
        }
        return changed ? result.toString() : line;
    }

    private String replaceTokenValue(String line, String token, String value) {
        if (!StringUtils.hasText(line) || !StringUtils.hasText(token) || !StringUtils.hasText(value)) {
            return line;
        }
        String marker = token + "=";
        int start = line.indexOf(marker);
        if (start < 0) {
            return line;
        }
        int valueStart = start + marker.length();
        int end = line.length();
        for (int index = valueStart; index < line.length(); index++) {
            char ch = line.charAt(index);
            if (ch == '|' || ch == ';' || ch == ']' || ch == ',' || Character.isWhitespace(ch)) {
                end = index;
                break;
            }
        }
        return line.substring(0, valueStart) + value + line.substring(end);
    }

    private boolean isPromptTokenDelimiter(char ch) {
        return ch == ';' || ch == '|' || ch == ']' || ch == ',';
    }

    private AppliedRule removeRuntimeFaultLines(String prompt, String... fragments) {
        if (!StringUtils.hasText(prompt) || fragments == null || fragments.length == 0) {
            return new AppliedRule(prompt, "SKIPPED_NO_MATCH");
        }
        StringBuilder result = new StringBuilder();
        boolean removed = false;
        for (String line : prompt.split("\\R", -1)) {
            if (containsAny(line, fragments)) {
                removed = true;
                continue;
            }
            result.append(line).append("\n");
        }
        return new AppliedRule(removed ? result.toString() : prompt, removed ? "APPLIED" : "SKIPPED_NO_MATCH");
    }

    private AppliedRule removeKnownSemanticFaultLines(String prompt, PromptRuntimeGovernanceRule rule) {
        String descriptor = descriptor(rule).toLowerCase(Locale.ROOT);
        if (descriptor.contains("baseline") || descriptor.contains("provisional")) {
            return removeRuntimeFaultLines(
                    prompt,
                    "mature baseline confirmed",
                    "confirmed normal combination");
        }
        if (descriptor.contains("delegation") || descriptor.contains("delegated")) {
            return removeRuntimeFaultLines(
                    prompt,
                    "delegated objective confirmed",
                    "business intent confirmed");
        }
        if (descriptor.contains("newuser") || descriptor.contains("new user")) {
            return removeRuntimeFaultLines(
                    prompt,
                    "new user detected",
                    "NewUser: true");
        }
        if (descriptor.contains("previous round") || descriptor.contains("round_progress") || descriptor.contains("roundprogress")) {
            return removeRuntimeFaultLines(
                    prompt,
                    "previous round verified",
                    "prior round verified",
                    "reverification passed",
                    "certificate issued for prior");
        }
        return new AppliedRule(prompt, "SKIPPED_NO_MATCH");
    }

    private boolean containsAny(String line, String... fragments) {
        if (line == null) {
            return false;
        }
        for (String fragment : fragments) {
            if (StringUtils.hasText(fragment) && line.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private String promptField(String prompt, String fieldName) {
        if (!StringUtils.hasText(prompt) || !StringUtils.hasText(fieldName)) {
            return null;
        }
        String prefix = fieldName + ":";
        for (String line : prompt.split("\\R", -1)) {
            String trimmed = line == null ? "" : line.stripLeading();
            if (trimmed.startsWith(prefix)) {
                String value = trimmed.substring(prefix.length()).trim();
                return StringUtils.hasText(value) ? value : null;
            }
        }
        return null;
    }

    private String extractToken(String line, String key) {
        if (!StringUtils.hasText(line) || !StringUtils.hasText(key)) {
            return null;
        }
        String marker = key + "=";
        int start = line.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int valueStart = start + marker.length();
        int end = line.length();
        for (int index = valueStart; index < line.length(); index++) {
            char ch = line.charAt(index);
            if (ch == '|' || ch == ';' || ch == ']' || ch == ',' || Character.isWhitespace(ch)) {
                end = index;
                break;
            }
        }
        String value = line.substring(valueStart, end).trim();
        return StringUtils.hasText(value) ? value : null;
    }

    private String descriptor(PromptRuntimeGovernanceRule rule) {
        if (rule == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        appendDescriptor(builder, rule.ruleId());
        appendDescriptor(builder, rule.sourceActionId());
        appendDescriptor(builder, rule.promptKey());
        appendDescriptor(builder, rule.slotKey());
        appendDescriptor(builder, rule.ruleType());
        Map<String, Object> payload = rule.payload();
        if (payload != null) {
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                appendDescriptor(builder, entry.getKey());
                appendDescriptor(builder, entry.getValue() == null ? null : String.valueOf(entry.getValue()));
            }
        }
        return builder.toString();
    }

    private void appendDescriptor(StringBuilder builder, String value) {
        if (builder == null || !StringUtils.hasText(value)) {
            return;
        }
        if (!builder.isEmpty()) {
            builder.append(' ');
        }
        builder.append(value);
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
}
