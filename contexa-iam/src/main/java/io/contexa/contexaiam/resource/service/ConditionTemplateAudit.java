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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.AdminChangeAudit;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import org.springframework.lang.Nullable;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * K130: the audit record of a classification and of a generation of the condition templates, as AdminChangeAudit
 * writes the console's other changes: a classification saved as it was records nothing.
 */
public final class ConditionTemplateAudit {

    /** Records nothing: a controller built without the audit facade. */
    public static final ConditionTemplateAudit NONE = new ConditionTemplateAudit(AdminChangeAudit.NONE);

    private final AdminChangeAudit audit;

    private ConditionTemplateAudit(AdminChangeAudit audit) {
        this.audit = audit;
    }

    public static ConditionTemplateAudit of(@Nullable CentralAuditFacade facade) {
        return facade == null ? NONE : new ConditionTemplateAudit(AdminChangeAudit.of(facade));
    }

    /** What a classification of a condition template holds. */
    public record Classification(String classification, Boolean approvalRequired, Boolean contextDependent,
                                 Integer complexityScore) {

        public static Classification of(ConditionTemplate condition) {
            return new Classification(condition.getClassification() != null ? condition.getClassification().name() : null,
                    condition.getApprovalRequired(), condition.getContextDependent(), condition.getComplexityScore());
        }

        Map<String, Object> values() {
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("classification", classification);
            values.put("approvalRequired", approvalRequired);
            values.put("contextDependent", contextDependent);
            values.put("complexityScore", complexityScore);
            return values;
        }
    }

    /** The condition's classification changed from what it was; one saved as it was records nothing. */
    public void classified(Long conditionId, Classification before, ConditionTemplate condition) {
        Classification after = Classification.of(condition);
        if (after.equals(before)) {
            return;
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("conditionId", conditionId);
        details.put("before", before.values());
        details.put("after", after.values());
        audit.record(AuditEventCategory.CONDITION_TEMPLATE_CHANGED, "CONDITION_CLASSIFIED", condition.getName(),
                details);
    }

    /** The condition templates generated, again or for the first time. */
    public void generated(String action, @Nullable List<ConditionTemplate> generated) {
        audit.record(AuditEventCategory.CONDITION_TEMPLATE_CHANGED, action, null,
                Map.of("generated", generated != null ? generated.size() : 0));
    }
}
