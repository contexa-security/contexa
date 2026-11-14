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

import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionarySlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRule;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlan;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * v1.0 (A10): the runtime governance rules of the v19 bundle, written on its section labels, moved to the dictionary
 * slots by the label place table, so a v1.0 prompt applies them to the lines the v19 facts went to. A rule of a
 * dictionary slot stays as it is; a v19 rule whose label went to no entry of the dictionary, or to several, stays as it
 * is too, and the applier leaves it out as it leaves out every v19 rule on a dictionary prompt.
 */
final class V19RuleSlots {

    /** The payload key that keeps the v19 slot key of a moved rule. */
    static final String V19_SLOT_KEY = "v19SlotKey";
    /** The payload key that keeps the v19 section a moved rule named. */
    static final String V19_SECTION_KEY = "v19SectionKey";

    /** The payload values that name the line a rule targets; a v19 label among them becomes the entry's name. */
    private static final List<String> LABEL_KEYS = List.of("label", "contextItem", "suppressPattern");

    private V19RuleSlots() {
    }

    static List<PromptRuntimeGovernanceRule> moved(List<PromptRuntimeGovernanceRule> rules,
                                                   PromptDictionarySlotPlanProvider dictionary,
                                                   List<PromptDictionaryEntry> entries,
                                                   PromptContextComposer v19Contract) {
        if (rules == null || rules.isEmpty() || dictionary == null || v19Contract == null) {
            return rules;
        }
        Map<String, PromptDictionaryEntry> byPlace = new LinkedHashMap<>();
        for (PromptDictionaryEntry entry : entries) {
            byPlace.put(entry.block().name() + "." + entry.name(), entry);
        }
        List<PromptRuntimeGovernanceRule> moved = new ArrayList<>(rules.size());
        for (PromptRuntimeGovernanceRule rule : rules) {
            moved.add(moved(rule, dictionary, byPlace, v19Contract));
        }
        return List.copyOf(moved);
    }

    private static PromptRuntimeGovernanceRule moved(PromptRuntimeGovernanceRule rule,
                                                     PromptDictionarySlotPlanProvider dictionary,
                                                     Map<String, PromptDictionaryEntry> byPlace,
                                                     PromptContextComposer v19Contract) {
        if (rule == null || !StringUtils.hasText(rule.slotKey())
                || !dictionary.plansForSlotKey(rule.promptKey(), rule.slotKey()).isEmpty()) {
            return rule;
        }
        List<PromptSlotPlan> plans = v19Contract.plansForSlotKey(rule.promptKey(), rule.slotKey());
        if (plans == null || plans.size() != 1 || plans.get(0) == null || !StringUtils.hasText(plans.get(0).labelKey())) {
            return rule;
        }
        String label = plans.get(0).labelKey();
        List<PromptDictionaryEntry> targets = SecurityDecisionPromptLabelPlaces.placesOf(label).stream()
                .map(byPlace::get)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        if (targets.size() != 1) {
            return rule;
        }
        PromptDictionaryEntry entry = targets.get(0);
        Map<String, Object> payload = new LinkedHashMap<>(rule.payload() != null ? rule.payload() : Map.of());
        for (String key : LABEL_KEYS) {
            if (label.equals(rule.payloadText(key))) {
                payload.put(key, entry.name());
            }
        }
        // The v19 section is not the dictionary block; the moved rule keeps it apart, with the v19 slot key.
        Object section = payload.remove("sectionKey");
        if (section != null) {
            payload.put(V19_SECTION_KEY, section);
        }
        payload.put(V19_SLOT_KEY, rule.slotKey());
        return new PromptRuntimeGovernanceRule(rule.ruleId(), rule.sourceActionId(), rule.promptKey(),
                PromptDictionarySlotPlanProvider.slotKey(entry), rule.ruleType(), rule.priority(),
                Collections.unmodifiableMap(payload));
    }
}
