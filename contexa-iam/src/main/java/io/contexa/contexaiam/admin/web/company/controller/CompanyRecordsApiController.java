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
package io.contexa.contexaiam.admin.web.company.controller;

import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore.StoredCompanyRecord;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService.InvalidRecordsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/**
 * The admin API of company records (docs/agent OC-2): the company's integrations and administrators put the records
 * of its systems (people, assignments, approvals, tickets, on-call shifts, trips, work days, usage, rules, networks),
 * delete them by key and list them. Every change is audited.
 */
@RestController
@RequestMapping("/contexa/admin/api/company-records")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class CompanyRecordsApiController {

    private final CompanyRecordsAdminService records;

    public CompanyRecordsApiController(CompanyRecordsAdminService records) {
        this.records = records;
    }

    @GetMapping
    public ResponseEntity<?> list(@RequestParam(value = "tenantId", required = false) String tenantId,
                                  @RequestParam(value = "kind", required = false) String kind,
                                  @RequestParam(value = "subject", required = false) String subject,
                                  @RequestParam(value = "target", required = false) String target,
                                  @RequestParam(value = "limit", defaultValue = "200") int limit) {
        try {
            return ResponseEntity.ok(records.list(blank(tenantId), blank(kind), blank(subject), blank(target), limit)
                    .stream().map(RecordView::of).toList());
        } catch (InvalidRecordsException e) {
            return invalid(e);
        }
    }

    @PostMapping
    public ResponseEntity<?> put(@RequestParam(value = "tenantId", required = false) String tenantId,
                                 @RequestBody(required = false) CompanyRecordSet body, Authentication authentication) {
        try {
            return ResponseEntity.ok(records.put(authentication.getName(), blank(tenantId), body));
        } catch (InvalidRecordsException e) {
            return invalid(e);
        }
    }

    @PostMapping("/delete")
    public ResponseEntity<?> delete(@RequestBody(required = false) DeleteBody body, Authentication authentication) {
        if (body == null) {
            return invalid(new InvalidRecordsException(List.of("the records to delete are required")));
        }
        try {
            return ResponseEntity.ok(new Removed(records.delete(authentication.getName(),
                    blank(body.tenantId()), body.kind(), body.keys())));
        } catch (InvalidRecordsException e) {
            return invalid(e);
        }
    }

    private static ResponseEntity<?> invalid(InvalidRecordsException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Invalid("The company records request is not valid",
                e.problems()));
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
