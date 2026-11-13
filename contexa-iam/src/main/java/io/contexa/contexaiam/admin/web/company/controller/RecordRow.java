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

import io.contexa.contexacore.autonomous.company.CompanyRecordKind;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.AccessDay;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Approval;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Assignment;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.NetworkZone;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.OnCall;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Person;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Policy;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Ticket;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Travel;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Usage;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore.StoredCompanyRecord;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService.InvalidRecordsException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/** One record on the console: its kind, key, person, target and its values in one line. */
public record RecordRow(String kind, String key, String subject, String target, String summary,
                        String ingestedBy, Instant ingestedAt) {
}
