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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The record of what was done to a version in the console's audit log (plan 3.7, {@code ctxa_audit_log}), which the
 * history table of the version screens reads: the action is the {@link PromptVersionAudit} name, the resource is
 * {@code {prompt}@{version}}, the reason is the detail (the reason given or the document's name), and the details hold
 * the scope, the prompt, the version and the detail. The record is written apart from the action; one that cannot be
 * handed over is logged and does not undo the action.
 */
public class AuditLogPromptVersionAudit implements PromptVersionAudit {

    private static final Logger log = LoggerFactory.getLogger(AuditLogPromptVersionAudit.class);

    /** The decision and the outcome of a version record: the action was recorded, nothing was decided. */
    static final String RECORDED = "RECORDED";
    static final String SOURCE = "IAM";
    static final String SYSTEM = "system";

    private final CentralAuditFacade audit;

    public AuditLogPromptVersionAudit(CentralAuditFacade audit) {
        this.audit = Objects.requireNonNull(audit, "audit");
    }

    @Override
    public void record(String action, String scope, String prompt, String version, String actor, String detail) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("scope", scope);
        details.put("prompt", prompt);
        details.put("version", version);
        details.put("detail", detail);
        try {
            audit.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.PROMPT_VERSION_CHANGED)
                    .principalName(actor != null && !actor.isBlank() ? actor : SYSTEM)
                    .resourceIdentifier(prompt + "@" + version)
                    .eventSource(SOURCE)
                    .action(action)
                    .reason(detail)
                    .decision(RECORDED)
                    .outcome(RECORDED)
                    .details(details)
                    .build());
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersion] the audit record of {} {}@{} could not be handed over", action, prompt, version,
                    failure);
        }
    }
}
