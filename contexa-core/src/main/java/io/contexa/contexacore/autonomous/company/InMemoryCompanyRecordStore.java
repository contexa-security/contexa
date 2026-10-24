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
package io.contexa.contexacore.autonomous.company;

import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The company records in memory (docs/agent OC-2): lost on restart, for a deployment without Contexa's database. */
public class InMemoryCompanyRecordStore implements CompanyRecordStore {

    private final Map<String, StoredCompanyRecord> records = new LinkedHashMap<>();

    @Override
    public synchronized void put(@Nullable String tenantId, CompanyRecordSet set, String ingestedBy,
                                 Instant ingestedAt) {
        for (StoredCompanyRecord row : CompanyRecordRows.rows(tenantId, set, ingestedBy, ingestedAt)) {
            records.put(id(row.tenantId(), row.kind(), row.key()), row);
        }
    }

    @Override
    public synchronized int delete(@Nullable String tenantId, CompanyRecordKind kind, Collection<String> keys) {
        int removed = 0;
        for (String key : keys) {
            if (key != null && records.remove(id(CompanyRecordRows.tenant(tenantId), kind, key)) != null) {
                removed++;
            }
        }
        return removed;
    }

    @Override
    public synchronized CompanyRecordSet ofSubject(@Nullable String tenantId, String subject) {
        String tenant = CompanyRecordRows.tenant(tenantId);
        return CompanyRecordRows.set(records.values().stream()
                .filter(row -> row.tenantId().equals(tenant) && CompanyRecordRows.personal(row.kind())
                        && subject != null && subject.equals(row.subject()))
                .toList());
    }

    @Override
    public synchronized CompanyRecordSet company(@Nullable String tenantId) {
        String tenant = CompanyRecordRows.tenant(tenantId);
        return CompanyRecordRows.set(records.values().stream()
                .filter(row -> row.tenantId().equals(tenant) && !CompanyRecordRows.personal(row.kind()))
                .toList());
    }

    @Override
    public synchronized List<StoredCompanyRecord> list(@Nullable String tenantId, @Nullable CompanyRecordKind kind,
                                                       @Nullable String subject, @Nullable String target,
                                                       int limit) {
        String tenant = CompanyRecordRows.tenant(tenantId);
        List<StoredCompanyRecord> found = new ArrayList<>(records.values().stream()
                .filter(row -> row.tenantId().equals(tenant) && (kind == null || row.kind() == kind)
                        && (subject == null || subject.equals(row.subject()))
                        && (target == null || target.equals(row.target())))
                .toList());
        Collections.reverse(found);
        found.sort((first, second) -> second.ingestedAt().compareTo(first.ingestedAt()));
        return found.subList(0, Math.min(found.size(), Math.max(limit, 0)));
    }

    @Override
    public synchronized int deleteSubject(String subject) {
        int removed = 0;
        Iterator<StoredCompanyRecord> rows = records.values().iterator();
        while (rows.hasNext()) {
            StoredCompanyRecord row = rows.next();
            if (subject != null && subject.equals(row.subject()) && CompanyRecordRows.personal(row.kind())) {
                rows.remove();
                removed++;
            }
        }
        return removed;
    }

    private static String id(String tenant, CompanyRecordKind kind, String key) {
        return tenant + '\u0000' + kind.name() + '\u0000' + key;
    }
}
