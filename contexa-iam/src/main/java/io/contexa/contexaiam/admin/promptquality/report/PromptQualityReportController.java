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
package io.contexa.contexaiam.admin.promptquality.report;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Objects;

/**
 * Quality plan 3.7, 5 step 8: the quality report of a scope over a period, downloaded as its bundle (a zip of
 * {@code report.json}, {@code report-ko.md} and {@code report-en.md}, masked as it is read). The button on the head of
 * the state of quality asks for it with the days of the period; the period is of whole days in UTC, the last day in
 * it. An administrator's export, as every screen of the group.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityReportController {

    public static final String API = "/contexa/admin/api/prompt-quality/report";
    static final MediaType ZIP = MediaType.parseMediaType("application/zip");

    private final PromptQualityReports reports;

    public PromptQualityReportController(PromptQualityReports reports) {
        this.reports = Objects.requireNonNull(reports, "reports");
    }

    /**
     * The report as a download.
     *
     * @param scope the scope of the prompt versions, or none for the platform's
     * @param from  the first day of the period (UTC), or none for 90 days before its end
     * @param to    the last day of the period (UTC), or none for up to now
     */
    @GetMapping(API)
    public ResponseEntity<byte[]> export(@RequestParam(required = false) String scope,
                                         @RequestParam(required = false)
                                         @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
                                         @RequestParam(required = false)
                                         @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
                                         Authentication authentication) {
        requireAdmin(authentication);
        Instant start = from != null ? from.atStartOfDay(ZoneOffset.UTC).toInstant() : null;
        Instant end = to != null ? to.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant() : null;
        PromptQualityReports.Export export;
        try {
            export = reports.export(new PromptQualityReports.Request(scope, start, end, authentication.getName()));
        }
        catch (IllegalArgumentException refused) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, refused.getMessage());
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(export.fileName(), StandardCharsets.UTF_8).build().toString())
                .contentType(ZIP)
                .body(export.bytes());
    }

    private static void requireAdmin(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        boolean admin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
        if (!admin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}
