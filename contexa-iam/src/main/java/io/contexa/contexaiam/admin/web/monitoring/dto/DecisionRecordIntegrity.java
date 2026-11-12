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
package io.contexa.contexaiam.admin.web.monitoring.dto;

import org.springframework.lang.Nullable;

import java.util.HashMap;
import java.util.Map;

/**
 * docs/agent A5-6: whether each decision record on a page is as it was sealed (VERIFIED, MISMATCH or UNVERIFIABLE),
 * as the security monitor reads it by record ID. Records that are no decisions have none.
 */
public final class DecisionRecordIntegrity {

    private final Map<Long, String> byRecord = new HashMap<>();

    /** Keeps what the seal check found for the record. */
    public void found(Long recordId, String status) {
        byRecord.put(recordId, status);
    }

    /** What the seal check found for the record, or null for a record that is no decision. */
    @Nullable
    public String of(@Nullable Long recordId) {
        return recordId == null ? null : byRecord.get(recordId);
    }
}
