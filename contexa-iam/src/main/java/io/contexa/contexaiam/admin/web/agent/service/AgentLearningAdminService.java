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
package io.contexa.contexaiam.admin.web.agent.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The console's and the admin API's control of what an agent learned (docs/agent A3-8): an administrator quarantines,
 * releases or removes the learning of an agent or of one of its delegations, with a reason, and every action is
 * audited. Without the autonomous security plane there is no learning to control and every action is refused.
 */
public class AgentLearningAdminService {

    /** The actions an administrator can take. */
    public enum Action {
        QUARANTINE, RELEASE, REMOVE;

        /** The action named, in any case; an unknown name is refused. */
        public static Action of(String name) {
            if (!StringUtils.hasText(name)) {
                throw new IllegalArgumentException("An action is required: quarantine, release or remove");
            }
            try {
                return valueOf(name.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unknown action " + name + ": quarantine, release or remove");
            }
        }
    }

    private final AgentLearningControl control;
    private final CentralAuditFacade auditFacade;

    public AgentLearningAdminService(@Nullable AgentLearningControl control, @Nullable CentralAuditFacade auditFacade) {
        this.control = control;
        this.auditFacade = auditFacade;
    }

    /** Whether the learning can be controlled here: the autonomous security plane runs. */
    public boolean available() {
        return control != null;
    }

    /** Whether the learning of the agent, or of the delegation when one is given, is quarantined. */
    public boolean quarantined(String agentId, @Nullable String delegationId) {
        return control != null && control.quarantined(agentId, delegationId);
    }

    /** Takes the action on the learning of the agent or of its delegation, and audits it under the administrator. */
    public AgentLearningControl.Outcome apply(Action action, String agentId, @Nullable String delegationId,
                                              String reason, String adminId) {
        if (control == null) {
            throw new IllegalStateException("Agent learning cannot be controlled: the autonomous security plane is off");
        }
        if (!StringUtils.hasText(reason)) {
            throw new IllegalArgumentException("A reason is required");
        }
        AgentLearningControl.Outcome outcome = switch (action) {
            case QUARANTINE -> control.quarantine(agentId, delegationId);
            case RELEASE -> control.release(agentId, delegationId);
            case REMOVE -> control.remove(agentId, delegationId);
        };
        audit(outcome, reason.trim(), adminId);
        return outcome;
    }

    private void audit(AgentLearningControl.Outcome outcome, String reason, String adminId) {
        if (auditFacade == null) {
            return;
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("agentId", outcome.agentId());
        details.put("delegationId", outcome.delegationId() != null ? outcome.delegationId() : "");
        details.put("records", outcome.records());
        details.put("baselines", outcome.baselines());
        details.put("observations", outcome.observations());
        auditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.AGENT_LEARNING_CONTROLLED)
                .principalName(adminId)
                .resourceIdentifier(outcome.agentId())
                .eventSource("IAM")
                .action("AGENT_LEARNING_" + outcome.action())
                .outcome(outcome.action())
                .reason(reason)
                .details(details)
                .build());
    }
}
