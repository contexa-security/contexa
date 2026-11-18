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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * K75: the audit record of an administrator's change the console made without one: the groups, the permissions, the
 * role hierarchies, the password policy, the menus, the system settings other than the Zero Trust mode (which has its
 * own record) and the role assignments of the access center. It is written as the role and user services write theirs:
 * the category, the action, who made the change and what it was made to, from the source IAM, with what changed in its
 * details. It is written once the change is committed, so a change refused or rolled back (the last administrator's
 * guard refuses after the rows were written) records nothing. Without the audit facade nothing is recorded.
 */
@Slf4j
public final class AdminChangeAudit {

    /** Records nothing: a service built without the audit facade. */
    public static final AdminChangeAudit NONE = new AdminChangeAudit(null);

    /** Who made a change no one signed in made, as the role and user services name it. */
    static final String SYSTEM = "SYSTEM";
    /** The length of the audit log's resource column. */
    private static final int TARGET_LENGTH = 512;

    private final CentralAuditFacade facade;

    private AdminChangeAudit(@Nullable CentralAuditFacade facade) {
        this.facade = facade;
    }

    public static AdminChangeAudit of(@Nullable CentralAuditFacade facade) {
        return facade == null ? NONE : new AdminChangeAudit(facade);
    }

    /**
     * Records the change; with a transaction in progress once it commits.
     *
     * @param target  what the change was made to (a name, or the settings changed); null for none
     * @param details what changed; null values are left out
     */
    public void record(AuditEventCategory category, String action, @Nullable String target,
                       @Nullable Map<String, ?> details) {
        if (facade == null) {
            return;
        }
        AuditRecord record;
        try {
            record = AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(actor())
                    .resourceIdentifier(target == null ? ""
                            : target.length() > TARGET_LENGTH ? target.substring(0, TARGET_LENGTH) : target)
                    .eventSource("IAM")
                    .action(action)
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(present(details))
                    .build();
        } catch (RuntimeException e) {
            log.error("Failed to audit the admin change {} {}", category, action, e);
            return;
        }
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    write(record);
                }
            });
        } else {
            write(record);
        }
    }

    private void write(AuditRecord record) {
        try {
            facade.recordAsync(record);
        } catch (RuntimeException e) {
            log.error("Failed to audit the admin change {} {}", record.getEventCategory(), record.getAction(), e);
        }
    }

    private static String actor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getName() != null ? authentication.getName() : SYSTEM;
    }

    private static Map<String, Object> present(@Nullable Map<String, ?> details) {
        Map<String, Object> kept = new LinkedHashMap<>();
        if (details != null) {
            details.forEach((key, value) -> {
                if (key != null && value != null) {
                    kept.put(key, value);
                }
            });
        }
        return kept;
    }
}
