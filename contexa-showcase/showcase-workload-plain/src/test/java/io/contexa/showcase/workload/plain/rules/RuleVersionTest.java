package io.contexa.showcase.workload.plain.rules;

import io.contexa.showcase.business.context.AccessApprovalPolicy;
import io.contexa.showcase.business.context.ExportApprovalPolicy;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * H-21: the rule hash is taken over the description's text, so every map in it keeps a fixed order. A map whose order
 * changes with each JVM start (Map.of, HashMap) gave the same rules a new hash after every restart of the plain controls.
 */
class RuleVersionTest {

    private static final ExportApprovalPolicy EXPORT = new ExportApprovalPolicy("EXPORT_APPROVAL",
            "An export of project documents needs an approval.", 500, true);
    private static final List<AccessApprovalPolicy> ACCESS = List.of(
            new AccessApprovalPolicy("ROLE_GRANT_APPROVAL", "A role needs a change ticket.", false, false, null),
            new AccessApprovalPolicy("DOCUMENT_ACCESS_APPROVAL", "A document is read by its team.", false, true, 90));

    @Test
    void everyMapOfTheDescriptionKeepsItsOrderSoTheHashIsStable() {
        Map<String, Object> description = RuleVersion.describe(EXPORT, ACCESS);

        List<Object> maps = new ArrayList<>();
        collectMaps(description, maps);
        assertThat(maps).isNotEmpty().allSatisfy(map -> assertThat(map).isInstanceOf(LinkedHashMap.class));
        assertThat(description.get("sha256")).isEqualTo(RuleVersion.describe(EXPORT, ACCESS).get("sha256"));
        @SuppressWarnings("unchecked")
        Map<String, Object> lookups = (Map<String, Object>) description.get("c2");
        @SuppressWarnings("unchecked")
        Map<String, Object> export = (Map<String, Object>) lookups.get("exportApprovalPolicy");
        assertThat(export.keySet()).containsExactly("policyKey", "assignedExportLimit", "ticketAndOncallExempt");
    }

    private static void collectMaps(Object value, List<Object> maps) {
        if (value instanceof Map<?, ?> map) {
            maps.add(map);
            map.values().forEach(inner -> collectMaps(inner, maps));
        } else if (value instanceof List<?> list) {
            list.forEach(inner -> collectMaps(inner, maps));
        }
    }
}
