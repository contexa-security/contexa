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
import java.util.Collection;
import java.util.List;

/**
 * Where Contexa keeps the company's records (docs/agent OC-2). Records are kept per tenant (null for the deployment's
 * own records) and per kind under their key ({@code key()} of each record): putting a record again replaces it and
 * keeps its place. Records keep the order in which the company first gave them; among records equally close to a
 * request, the one given first is weighed first.
 * <p>
 * Contexa keeps them in its database table {@code ctxa_company_record} when it has one, in memory otherwise; an application
 * whose records live elsewhere supplies its own store.
 */
public interface CompanyRecordStore {

    /** Puts the records, replacing those with the same kind and key, and integrates the kinds they hold. */
    void put(@Nullable String tenantId, CompanyRecordSet records, String ingestedBy, Instant ingestedAt);

    /** Removes the records of the kind with the given keys; how many were removed. */
    int delete(@Nullable String tenantId, CompanyRecordKind kind, Collection<String> keys);

    /** The person's records in the tenant: the person, assignments, approvals, tickets, shifts, trips, days, usage. */
    CompanyRecordSet ofSubject(@Nullable String tenantId, String subject);

    /** The company's own records in the tenant: its rules, its networks and the kinds it integrates. */
    CompanyRecordSet company(@Nullable String tenantId);

    /** The kept records, newest put first, filtered by what is given; at most {@code limit}. */
    List<StoredCompanyRecord> list(@Nullable String tenantId, @Nullable CompanyRecordKind kind,
                                   @Nullable String subject, @Nullable String target, int limit);

    /** Removes every record of the person in every tenant (the person's account was deleted); how many. */
    int deleteSubject(String subject);

    /**
     * One kept record with who put it and when.
     *
     * @param record the record ({@link CompanyRecordSet.Person}, {@link CompanyRecordSet.Ticket}, ...), or the kind's
     *               name for {@link CompanyRecordKind#SOURCE}
     */
    record StoredCompanyRecord(@Nullable String tenantId, CompanyRecordKind kind, String key, @Nullable String subject,
                               @Nullable String target, Object record, String ingestedBy, Instant ingestedAt) {
    }
}
