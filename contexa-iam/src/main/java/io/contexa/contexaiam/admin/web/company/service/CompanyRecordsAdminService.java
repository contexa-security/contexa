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
package io.contexa.contexaiam.admin.web.company.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.company.CompanyRecordKind;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore.StoredCompanyRecord;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Puts, deletes and lists the company records for the admin API and the console (docs/agent OC-2), and audits every
 * change with who made it.
 */
public class CompanyRecordsAdminService {

    /** The most records one put may hold, and one listing may return. */
    public static final int PUT_LIMIT = 20_000;
    public static final int LIST_LIMIT = 1_000;

    /** Records that cannot be kept, each problem as a sentence. */
    public static class InvalidRecordsException extends IllegalArgumentException {

        private final List<String> problems;

        public InvalidRecordsException(List<String> problems) {
            super(String.join("; ", problems));
            this.problems = List.copyOf(problems);
        }

        public List<String> problems() {
            return problems;
        }
    }

    /** What a put kept: how many records, and the kinds the company now integrates through it. */
    public record Recorded(int records, List<String> integratedKinds) {
    }

    private final CompanyRecordStore store;
    private final CentralAuditFacade auditFacade;
    private final Clock clock;

    public CompanyRecordsAdminService(CompanyRecordStore store, @Nullable CentralAuditFacade auditFacade) {
        this(store, auditFacade, Clock.systemUTC());
    }

    public CompanyRecordsAdminService(CompanyRecordStore store, @Nullable CentralAuditFacade auditFacade, Clock clock) {
        if (store == null) {
            throw new IllegalArgumentException("A company record store is required");
        }
        this.store = store;
        this.auditFacade = auditFacade;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    public Recorded put(String actor, @Nullable String tenantId, @Nullable CompanyRecordSet records) {
        if (records == null || records.isEmpty()) {
            throw new InvalidRecordsException(List.of("no records were given"));
        }
        if (records.size() > PUT_LIMIT) {
            throw new InvalidRecordsException(List.of("at most " + PUT_LIMIT + " records may be put at once"));
        }
        List<String> problems = records.problems();
        if (!problems.isEmpty()) {
            throw new InvalidRecordsException(problems);
        }
        store.put(tenantId, records, actor, clock.instant());
        List<String> kinds = records.integratedKinds().stream().map(Enum::name).toList();
        Map<String, Object> details = counts(records);
        details.put("tenantId", tenantId != null ? tenantId : "");
        audit(AuditEventCategory.COMPANY_RECORDS_RECORDED, actor, tenantId, "RECORDED", details);
        return new Recorded(records.size(), kinds);
    }

    public int delete(String actor, @Nullable String tenantId, @Nullable String kind, @Nullable Collection<String> keys) {
        CompanyRecordKind named = CompanyRecordKind.of(kind);
        if (named == null) {
            throw new InvalidRecordsException(List.of("'" + kind + "' is not a kind of company record"));
        }
        List<String> recordKeys = keys == null ? List.of()
                : keys.stream().filter(Objects::nonNull).map(String::trim).filter(key -> !key.isEmpty()).toList();
        if (recordKeys.isEmpty()) {
            throw new InvalidRecordsException(List.of("no record keys were given"));
        }
        int removed = store.delete(tenantId, named, recordKeys);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenantId", tenantId != null ? tenantId : "");
        details.put("kind", named.name());
        details.put("keys", recordKeys);
        details.put("removed", removed);
        audit(AuditEventCategory.COMPANY_RECORDS_DELETED, actor, tenantId, "DELETED", details);
        return removed;
    }

    public List<StoredCompanyRecord> list(@Nullable String tenantId, @Nullable String kind, @Nullable String subject,
                                          @Nullable String target, int limit) {
        CompanyRecordKind named = kind == null || kind.isBlank() ? null : CompanyRecordKind.of(kind);
        if (kind != null && !kind.isBlank() && named == null) {
            throw new InvalidRecordsException(List.of("'" + kind + "' is not a kind of company record"));
        }
        return store.list(tenantId, named, subject, target, Math.max(1, Math.min(limit, LIST_LIMIT)));
    }

    private static Map<String, Object> counts(CompanyRecordSet records) {
        Map<String, Object> counts = new LinkedHashMap<>();
        put(counts, "people", records.people().size());
        put(counts, "sources", records.sources().size());
        put(counts, "assignments", records.assignments().size());
        put(counts, "approvals", records.approvals().size());
        put(counts, "tickets", records.tickets().size());
        put(counts, "onCall", records.onCall().size());
        put(counts, "travel", records.travel().size());
        put(counts, "accessDays", records.accessDays().size());
        put(counts, "usage", records.usage().size());
        put(counts, "policies", records.policies().size());
        put(counts, "networks", records.networks().size());
        return counts;
    }

    private static void put(Map<String, Object> counts, String name, int count) {
        if (count > 0) {
            counts.put(name, count);
        }
    }

    private void audit(AuditEventCategory category, String actor, @Nullable String tenantId, String outcome,
                       Map<String, Object> details) {
        if (auditFacade == null) {
            return;
        }
        auditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(category)
                .principalName(actor)
                .resourceIdentifier("company-records" + (tenantId != null ? ":" + tenantId : ""))
                .eventSource("IAM")
                .action(category.name())
                .outcome(outcome)
                .details(details)
                .build());
    }
}
