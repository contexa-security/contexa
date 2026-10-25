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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionarySlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptListOrder;
import io.contexa.contexacore.autonomous.context.prompt.PromptMissingNotation;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import io.contexa.contexacore.autonomous.context.prompt.PromptSourceGrade;
import io.contexa.contexacore.autonomous.context.prompt.PromptUnknownKind;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The v20 dictionary of the security decision prompt: every line the v20 user blocks may write, with its meaning,
 * source, value form, missing notation, source grades, decision use and shortening rules. The code is the source of
 * the dictionary; slot contract rows are copies written at start. Format examples marked with angle brackets are
 * forms the measured run did not have a value for.
 */
public final class SecurityDecisionPromptDictionary {

    public static final String VERSION = "v20";

    public static final List<PromptDictionaryEntry> ENTRIES = List.of(
            entry(PromptBlock.USER_BASELINE, "Evidence",
                    "How sufficient the block evidence is and where it comes from (dictionary 1.3): the baseline view's evidence and the trust profiles' facts, their usage notes and the instructions after a fact left out (TO-1); the baseline state is BaselineStatus's only (Q-79 A1), and without any evidence the line is not drawn",
                    "trust profile audits; BaselineView (W2-3)",
                    "collector [A-Z_]+, window \\d+ days( \\(\\d{2}-\\d{2}\\.\\.\\d{2}-\\d{2}\\))?, observations \\d+ over \\d+ days, fallback (\\d+%|not audited), unknown (\\d+%|not audited), evidence (STRONG|LIMITED|WEAK), scope personal(; .+)?|collector [A-Za-z_]+(, .+)?",
                    List.of("collector PERSONAL_WORK_PROFILE, window 7 days (09-23..09-29), observations 25 over 5 days, fallback 100%, unknown 0%, evidence LIMITED, scope personal", "collector ROLE_SCOPE_PROFILE, provenance 〈출처 요약〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "limits of any comparison claim",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("Context", "ContextEvidenceLimitation", "ContextTrustLimitation", "ContextTrustWarning", "ObservedPatternEvidenceScope", "ObservedScopeSummary", "ProfileSource")),
            entry(PromptBlock.USER_BASELINE, "BaselineStatus",
                    "State of the personal baseline and why; the number of personal past records is PastRecordCounts's (Q-79 A3)",
                    "baseline learning count against its thresholds (20 learned requests, 5 learned dates, at most 2 new "
                            + "values in the last 10 learnings, W5-10 D4); baseline support state",
                    "(ESTABLISHED|PROVISIONAL|SPARSE_PERSONAL_HISTORY|NONE|NEW_USER|NOT_LOADED|SERVICE_UNAVAILABLE|MISSING_USER_ID|ANALYSIS_UNAVAILABLE)( \\(.+\\))?",
                    List.of("ESTABLISHED (25 learned requests, personal baseline AVAILABLE)", "SPARSE_PERSONAL_HISTORY (0 learned requests, personal baseline NO_DATA)", "NONE (no learned requests, no observations, personal baseline NO_DATA)"),
                    PromptMissingNotation.RENDERED_VALUE, "NONE",
                    Set.of(PromptSourceGrade.LEARNED), "BASELINE_NOT_ESTABLISHED; differences are unknown without a baseline",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("Baseline", "BaselineSupportSummary")),
            entry(PromptBlock.USER_BASELINE, "UsualHours",
                    "Usual access hours (one line per dimension)",
                    "BaselineView (W2-3)",
                    "\\d{2}(-\\d{2})?(, \\d{2}(-\\d{2})?)*( \\(seen \\d{1,2}(,\\d{1,2})*\\))?|seen \\d{1,2}(,\\d{1,2})*",
                    List.of("09-11, 13-14, 17 (seen 9,10,11,12,13,14,16,17)"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.ASCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualDays",
                    "Usual days of the week",
                    "BaselineView (W2-3)",
                    "(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(-(Mon|Tue|Wed|Thu|Fri|Sat|Sun))?(, (Mon|Tue|Wed|Thu|Fri|Sat|Sun)(-(Mon|Tue|Wed|Thu|Fri|Sat|Sun))?)*( \\(seen (Mon|Tue|Wed|Thu|Fri|Sat|Sun)(-(Mon|Tue|Wed|Thu|Fri|Sat|Sun))?(, (Mon|Tue|Wed|Thu|Fri|Sat|Sun)(-(Mon|Tue|Wed|Thu|Fri|Sat|Sun))?)*\\))?|seen (Mon|Tue|Wed|Thu|Fri|Sat|Sun)(-(Mon|Tue|Wed|Thu|Fri|Sat|Sun))?(, (Mon|Tue|Wed|Thu|Fri|Sat|Sun)(-(Mon|Tue|Wed|Thu|Fri|Sat|Sun))?)*",
                    List.of("Mon-Fri", "Mon-Fri (seen Mon-Sat)"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.WEEKDAY, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualNetworks",
                    "Usual networks (band and zone)",
                    "BaselineView (W2-3)",
                    "[0-9a-f:.]+/\\d{1,3}(, [0-9a-f:.]+/\\d{1,3})*",
                    List.of("10.40.12.0/24"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualDevices",
                    "Usual devices (browser and operating system)",
                    "BaselineView (W2-3)",
                    "\\S+ on \\S+(, \\S+ on \\S+)*|browsers .+(; systems .+)?|systems .+",
                    List.of("Chrome/140 on WINDOWS", "browsers Edge/140; systems WINDOWS"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualLoginMethods",
                    "Usual login methods",
                    "BaselineView (W2-3)",
                    "[A-Za-z][A-Za-z_ -]*(\\+[A-Za-z][A-Za-z_ -]*)*(, [A-Za-z][A-Za-z_ -]*(\\+[A-Za-z][A-Za-z_ -]*)*)*",
                    List.of("MFA", "PASSWORD+ONE_TIME_CODE"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualTargets",
                    "Usual targets",
                    "BaselineView (W2-3)",
                    "\\S+=\\S+(, \\S+=\\S+)*",
                    List.of("projectKey=PLM-OPS"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualActions",
                    "Usual actions with their counts",
                    "BaselineView (W2-3)",
                    "[A-Z_]+ \\d+(, [A-Z_]+ \\d+)*( \\(evidence (LIMITED|WEAK): .+\\))?",
                    List.of("READ 20, EXPORT 5", "READ 20, EXPORT 5 (evidence LIMITED: action family inferred from protectableMethod in 25 of 25 observations)"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.FREQUENCY_DESCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualResourceClass",
                    "Usual resource classes",
                    "BaselineView (W2-3)",
                    "[A-Z_]+ \\d+(, [A-Z_]+ \\d+)*",
                    List.of("NORMAL 25"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualExportSize",
                    "Usual size of one export",
                    "BaselineView (W2-3)",
                    "up to [\\d,]+ items per export \\(median [\\d,]+, \\d+ exports?\\)",
                    List.of("up to 29 items per export (median 17, 5 exports)"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualRequestRate",
                    "Usual request rate",
                    "BaselineView (W2-3)",
                    "median \\d+, 95th percentile \\d+ requests in the 60 min up to a request \\(\\d+ requests?\\)",
                    List.of("median 〈m〉, 95th percentile 〈p〉 requests in the 60 min up to a request (〈n〉 requests)"),
                    PromptMissingNotation.RENDERED_VALUE, "not learned",
                    Set.of(PromptSourceGrade.LEARNED), "reference for the differences from the usual",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("Normal", "Observed")),
            entry(PromptBlock.USER_BASELINE, "UsualSessionLength",
                    "Usual session length",
                    "work profile (when it has a value)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "explains a difference",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.USER_BASELINE, "UsualPrivilegedActions",
                    "Usual privileged actions",
                    "work profile (when it has a value)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "explains a difference",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.USER_BASELINE, "SeasonalPattern",
                    "Seasonal work",
                    "work profile (when it has a value)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "explains a difference",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.USER_BASELINE, "KnownRareTasks",
                    "Rare but legitimate tasks",
                    "work profile (when it has a value)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "explains a difference",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.USER_BASELINE, "WorkProfile",
                    "Work profile observations and the density of protected calls",
                    "DefaultProtectableWorkProfileCollector (recorded after the decision, W2-7)",
                    "\\d+ protected requests in the last \\d+ days(; protectable share \\d+\\.\\d{2})?",
                    List.of("25 protected requests in the last 7 days; protectable share 1.00"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "sufficiency of the evidence",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("ProtectableInvocationDensity", "WorkProfileSummary")),
            entry(PromptBlock.USER_BASELINE, "PeerReference",
                    "Organisation or cohort baseline (whether or not a personal baseline exists), the cohort seed's facts without its instruction sentences (TO-2); reference only",
                    "organisation baseline, cohort seed",
                    "cohort organization(: .+)?; status [A-Z_]+( \\(\\d+ updates\\))?(; .+)?; reference only|.+; reference only",
                    List.of("cohort organization: hours 9,10,11,12,13,14,16,17, days Mon-Fri; status AVAILABLE (25 updates); summary organization baseline available | organization baseline established; reference only"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "comparison when no personal baseline exists (reference only)",
                    true, PromptDictionaryEntry.PRIORITY_SUPPORTING, null, PromptListOrder.NONE, false,
                    List.of("PeerCohortId", "PeerCohortSummary", "Runtime", "Seed", "SupportingBaselineStatus", "SupportingBaselineSummary", "Use")),
            entry(PromptBlock.SESSION, "SessionAge",
                    "Time from the session start (or authentication) to this request, with its basis",
                    "session creation and authentication time (W1-10)",
                    "\\d+ min since (login|session start|authentication)",
                    List.of("0 min since login"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "session context",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("NewSession")),
            entry(PromptBlock.SESSION, "LoginMethod",
                    "Login method of this session: assurance, authentication time, time since MFA, source",
                    "bridge authentication stamp (W1-4)",
                    "[^;]+; source host( \\([A-Z_]+\\))?",
                    List.of("PASSWORD+ONE_TIME_CODE (PASSWORD) (assurance AAL2), 2 min before this request, MFA verified, last MFA 2 min before this request; source host (SECURITY_CONTEXT)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "DEVIATION_LOGIN_METHOD; verification facts",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("AuthMethod", "AuthenticationType", "BridgeAuthenticationSource", "CurrentAuthenticationType", "MfaVerified", "SessionAuthMethod")),
            entry(PromptBlock.SESSION, "ChallengeVerified",
                    "Zero Trust step-up passed in this session",
                    "challenge completion record (W1-5)",
                    "none|at \\d{2}:\\d{2}( for [A-Z]+ \\S+)? \\(\\d+ (min|h|days) before this request\\)",
                    List.of("none", "at 14:23 (1 min before this request)"),
                    PromptMissingNotation.RENDERED_VALUE, "none",
                    Set.of(PromptSourceGrade.COMPUTED), "CHALLENGE_VERIFIED_IN_SESSION",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("COMPLETED", "MFA")),
            entry(PromptBlock.SESSION, "RecentMfaElsewhere",
                    "The same user finished MFA in another session recently (user-wide one-hour mark)",
                    "SecurityContextDataStore.isMfaVerified (split from the session in W1-5)",
                    "MFA completed in another session \\d+ (min|h|days) before this request",
                    List.of("MFA completed in another session 12 min before this request"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "makes clear the MFA was not this session",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("MfaVerified")),
            entry(PromptBlock.SESSION, "FailedLogins",
                    "Recent failed logins (window stated)",
                    "failure records (W1-9)",
                    "\\d+ in last \\d+ min|\\d+ recent failed logins \\(window not stated\\)",
                    List.of("0 in last 5 min", "0 recent failed logins (window not stated)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "FAILED_LOGINS, MFA_FAILURES",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("FailedLoginAttempts")),
            entry(PromptBlock.SESSION, "MfaFailures",
                    "Recent failed MFA attempts (window stated)",
                    "failure records (W1-9)",
                    "\\d+ in last \\d+ min|\\d+ recent MFA failures \\(window not stated\\)",
                    List.of("1 recent MFA failures (window not stated)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "FAILED_LOGINS, MFA_FAILURES",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("FailedLoginAttempts")),
            entry(PromptBlock.SESSION, "RequestsInSession",
                    "Protected requests of this session in time order (latest N, repeats and decisions) and their count; a request's target is 'this target' or 'another target' (the paths are an untrusted text, N-INJ-1)",
                    "session decision history (W1-11)",
                    "\\d+ so far: .+",
                    List.of("1 so far: 03:17 (〈n〉 min before this request) EXPORT this target 4,831 items -> CHALLENGE"),
                    PromptMissingNotation.RENDERED_VALUE, "this is the first",
                    Set.of(PromptSourceGrade.COMPUTED), "REPEAT_IN_SESSION, PRIOR_CHALLENGE_IN_SESSION",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.TIME, false,
                    List.of("RecentSessionActionCount", "RecentSessionActionSample")),
            entry(PromptBlock.SESSION, "RecentRequests",
                    "Recent request count with window and unit",
                    "official fields, session records (W1-7)",
                    "(\\d+ requests in last \\d+ min \\(\\d+(\\.\\d+)? per min\\)(; host count \\d+, window not stated)?|host count \\d+, window not stated)",
                    List.of("14 requests in last 10 min (1.4 per min)"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "DEVIATION_RATE",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("SessionRequestsPerMinute")),
            entry(PromptBlock.SESSION, "ConcurrentSessions",
                    "Concurrent sessions",
                    "official fields, observed scope",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED, PromptSourceGrade.HOST), "session context",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.SESSION, "PasswordAge",
                    "Time since the password changed",
                    "official fields, observed scope",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED, PromptSourceGrade.HOST), "session context",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.SESSION, "RecentSensitiveAccess",
                    "Recent access to sensitive resources",
                    "official fields, observed scope",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED, PromptSourceGrade.HOST), "session context",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.SESSION, "RecentDenied",
                    "Recent authorization denials (real denials only, W1-6)",
                    "session records",
                    "\\d+ denied in last \\d+ min \\(.+\\)",
                    List.of("2 denied in last 30 min (403 customer CUS-0001)"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "PAST_DENIED_SAME_ACTION",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("RecentDeniedAuthorizations")),
            entry(PromptBlock.REQUEST, "Subject",
                    "Subject: account kind, account age, department, title, tenant (and organisation when different)",
                    "execution subject, account (Users.createdAt, W1-10), bridge stamp, official fields tenantId and organizationId",
                    "\\S+ \\([A-Z_]+, account .+\\)",
                    List.of("v…-adm-a (HUMAN_USER, account 〈계정 나이〉, dept 〈부서〉, tenant tenant-…)"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.HOST), "identity context",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("BridgeSubjectKey", "ExternalSubjectId", "OrganizationId", "TenantId")),
            entry(PromptBlock.REQUEST, "Roles",
                    "Roles, scope tags, privilege flow, with source",
                    "authorization stamp",
                    ".+; source host( \\([A-Z_]+\\))?",
                    List.of("SC_ADMIN; source host (SECURITY_CONTEXT)"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.HOST), "context of ROLE_SCOPE_OUTSIDE",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("BridgeAuthorizationSource")),
            entry(PromptBlock.REQUEST, "Permissions",
                    "Permission summary with source",
                    "authorization stamp",
                    ".+; source host( \\([A-Z_]+\\))?",
                    List.of("REPORT_READ; source host (SECURITY_CONTEXT)"),
                    // N-DIC-1: a host that hands over no permissions leaves them unknown (not integrated).
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "context of ROLE_SCOPE_OUTSIDE",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("BridgeAuthorizationSource")),
            entry(PromptBlock.REQUEST, "Time",
                    "Request time",
                    "event time in the company time zone (W1-7)",
                    "(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \\d{2}:\\d{2}",
                    List.of("Wed 03:17"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.COMPUTED), "DEVIATION_TIME, DEVIATION_DAY",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("EventId", "Timestamp", "User")),
            entry(PromptBlock.REQUEST, "Action",
                    "Action with its source grade, method, URL template and protected method name (the request path is an untrusted text, N-INJ-1)",
                    "ActionFamily (W2-1), resource registry (W2-11), official fields",
                    "[A-Z]+ \\([a-zA-Z ]+\\) [A-Z]+( \\((template \\S+(, method \\S+)?|method \\S+)\\))?",
                    List.of("EXPORT (declared) POST (template /api/projects/{projectKey}/exports, method ContexaBusinessOperations.exportDocuments)"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.HOST, PromptSourceGrade.INFERRED), "DEVIATION_ACTION",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("ResourceId")),
            entry(PromptBlock.REQUEST, "Target",
                    "Target: the URL template's variables (their values are in the request path, an untrusted text, N-INJ-1) or the resource, whether it has a business label (its text is an untrusted text, N-INJ-3), and the category as a token (a category of other text is an untrusted text, N-INJ-4)",
                    "business provider, resource registry",
                    "(\\S+(, \\S+)* from the request path|resource)( \\(" + SecurityDecisionPromptValues.TARGET_LABEL_NOTE
                            + "\\))?(, category (" + SecurityDecisionPromptValues.CATEGORY_TOKEN_FORM + "|"
                            + SecurityDecisionPromptValues.TARGET_CATEGORY_NOTE + "))?",
                    List.of("projectKey from the request path (" + SecurityDecisionPromptValues.TARGET_LABEL_NOTE
                            + "), category 〈업무 범주〉", "documentId from the request path"),
                    PromptMissingNotation.RENDERED_VALUE, "path template variable",
                    Set.of(PromptSourceGrade.HOST), "DEVIATION_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.REQUEST, "Size",
                    "Request size",
                    "business provider, request rules",
                    "\\d[\\d,]* items",
                    List.of("4,831 items"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.HOST), "DEVIATION_SIZE",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.REQUEST, "ResourceClass",
                    "Resource class (with the raw value), sensitive-resource, export-sensitive and privileged marks; the prompt-quality verification mark left out (W3-5, Q-73)",
                    "single vocabulary (W1-2, W2-10), resource registry",
                    "[A-Z]+( \\(.+\\))?",
                    List.of("CRITICAL (sensitivity RESTRICTED, sensitive-resource flag, export-sensitive)"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.HOST), "DEVIATION_RESOURCE_CLASS; conditions of P1 and P2",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("SensitiveResource")),
            entry(PromptBlock.REQUEST, "Network",
                    "IP, band, zone, country, city, ASN",
                    "sensor, official fields, business provider (W2-4)",
                    "[0-9a-f:.]+ \\([0-9a-f:.]+/\\d{1,3}(, .+)?\\)",
                    List.of("10.40.12.160 (10.40.12.0/24, company office)"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.COMPUTED), "DEVIATION_NETWORK; P1, P2",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("CurrentNetwork", "CurrentOS", "CurrentUA")),
            entry(PromptBlock.REQUEST, "Device",
                    "Device, whether it was seen before when the host declared it or only the past records hold it (the engine's baseline comparison is the decision facts' only, Q-79 A2), language, fingerprint match, screen (when present); 'unparsed user agent' when the user agent cannot be parsed (its text is an untrusted text, N-INJ-1)",
                    "user agent parsing and baseline comparison (W2-4)",
                    "(.+ on .+|unparsed user agent)( \\(((known|new) device per host|(not )?seen in past records)(, [^)]+)?\\))?",
                    List.of("Chrome 140 on Windows", "Safari 18 on Windows (seen in past records)", "Chrome 140 on Windows (new device per host)", "unparsed user agent"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.COMPUTED), "DEVIATION_DEVICE; P1, P2",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("CurrentBrowser", "CurrentOperatingSystem", "DeviceScreenResolution")),
            entry(PromptBlock.DECISION_FACTS, "DeviationsFromBaseline",
                    "Differences from the usual: per dimension, frequency, whether each is explained, dimensions compared, overlap of the closest past record read for this action on time, login method and browser",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "\\d+ of \\d+ compared( -> .+?)?(; not compared: .+?)?(; closest of the past records read for this action matches \\d+ of \\d+ on time, login method and browser)?",
                    List.of("3 of 8 compared -> time 03 seen 0 of 25 (unexplained); target projectKey seen 0 of 25 (unexplained); class CRITICAL seen 0 of 25 (unexplained); closest of the past records read for this action matches 2 of 3 on time, login method and browser", "0 of 8 compared; closest of the past records read for this action matches 3 of 3 on time, login method and browser", "time 03 seen 0 of 25 (explained by APR-…)", "1 of 8 compared -> rate 〈n〉 requests in the last 60 min, usual median 〈m〉, 95th percentile 〈p〉 in the 60 min up to a request (baseline not established)"),
                    // N-DIC-1: '0 of 8 compared' is a value (no compared dimension differs), not a missing text;
                    // without a comparison the fact is unknown (dictionary 1.4: no learned baseline, no dimension
                    // compared).
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "DEVIATION_*; conditions of P1 and P2",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.DIMENSION_ORDER, false,
                    List.of("CurrentRequestClosestObservedOverlap", "CurrentRequestCombinationComparedDimensions", "CurrentRequestCombinationEvidenceScope", "CurrentRequestCombinationSeenCount", "StrongestCurrentRequestCombinationDelta")),
            entry(PromptBlock.DECISION_FACTS, "SameAsBaseline",
                    "Dimensions that are the same as usual",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "[a-z]+( [a-z]+)*( [^;]+)?(; [a-z]+( [a-z]+)*( [^;]+)?)*",
                    List.of("day Wed seen 5 of 25; network 10.40.12.0/24 seen 25 of 25; "
                            + "login method PASSWORD seen 25 of 25"),
                    // N-DIC-1: unknown for the reasons of DeviationsFromBaseline; compared without a match it is none.
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "BASELINE_MATCH",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.DIMENSION_ORDER, false,
                    List.of("Current", "PresentInObserved")),
            entry(PromptBlock.DECISION_FACTS, "Policy",
                    "Company policy requirement and its exception conditions",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "[A-Z_]+ requires .+",
                    List.of("EXPORT_APPROVAL requires a covering approval (exceptions: assigned project up to 500 items; ticket while on call)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "condition of P3",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("ApprovalRequired")),
            entry(PromptBlock.DECISION_FACTS, "PolicySatisfied",
                    "Whether the policy is met and why: the covering record or none, late, out of period, other target, over the limit, over the cumulative limit, ticket without on-call",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "(yes|no|unknown) \\u2014 .+",
                    List.of("no — no approval for GB-500", "no — approval APR-… decided 20 min after this request", "yes — approval APR-… PROJECT_TRANSFER up to 5,000, issued before the request", "unknown — not known: approval APR-…: the items exported under it outside this session"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "POLICY_*; P3",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("ApprovalGranted", "ApprovalMissing", "ApprovalStatus")),
            entry(PromptBlock.DECISION_FACTS, "Approval",
                    "Approval details: approver, purpose, limit, period, decision time, cumulative use, pending approvers",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "\\S+ by \\S+, .+",
                    List.of("APR-… by pm-11, PROJECT_TRANSFER, up to 5,000, used 0 before this request, valid 09-29 03:17..10-01 03:17 (from 24 h before to 24 h after this request), decided 09-29 03:10 (24 h before this request)"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.HOST), "reason of P3",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("ApprovalLineage", "FrictionSummary")),
            entry(PromptBlock.DECISION_FACTS, "Assignment",
                    "Assignment and recent access to the target",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "((not the )?account manager of \\S+|(not )?assigned to \\S+( \\(.+\\))?|worked on \\S+ on \\d+ of the last (\\d+ days|days the host counts))(; ((not the )?account manager of \\S+|(not )?assigned to \\S+( \\(.+\\))?|worked on \\S+ on \\d+ of the last (\\d+ days|days the host counts)))*",
                    List.of("not assigned to GB-500; worked on GB-500 on 0 of the last 30 days", "not the account manager of CUS-0001"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "whether a difference is explained; ASSIGNED_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "Ticket",
                    "Ticket record; a ticket the requester names is 'the ticket named by the requester' (what the requester wrote is an untrusted text, N-INJ-1)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "no ticket found|the ticket named by the requester does not exist(; .+)?|.+ \\u2014 (covers this request(; .+)?"
                            + "|not known whether it covers: .+|does not cover: .+)",
                    List.of("no ticket found", "the ticket named by the requester does not exist", "TCK-90090ef490a6-1 by pm-11, INCIDENT_RECOVERY, HX-200, valid 09-30 12:20..09-30 20:20 (from 〈n〉 h before to 〈n〉 h after this request) — covers this request"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "whether a difference is explained; ASSIGNED_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "OnCall",
                    "On-call record",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "(not )?on call.*",
                    List.of("not on call", "on call (HX on-call) until 10-05 08:17 (〈n〉 days after this request)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "whether a difference is explained; ASSIGNED_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "Travel",
                    "Travel record",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+",
                    List.of("〈출장 기록〉"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.HOST), "whether a difference is explained; ASSIGNED_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "RepeatInSession",
                    "Repeats of the same action and cumulative use of an approval (the target as 'this target' or 'the same target', N-INJ-1)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+ in this session.*",
                    List.of("first export in this session"),
                    PromptMissingNotation.RENDERED_VALUE, "first",
                    Set.of(PromptSourceGrade.COMPUTED), "REPEAT_IN_SESSION; cumulative use for P3",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "RoleScope",
                    "Comparison with the 30-day facts of the scope group, the strongest difference and the evidence state",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "(action [A-Z_]+ (within|outside) the scope group's actions \\(.+?\\)|category \\S+ (within|outside) the scope group's categories \\(.+?\\)|action in the scope group's denied actions|category in the scope group's denied categories)(; (action [A-Z_]+ (within|outside) the scope group's actions \\(.+?\\)|category \\S+ (within|outside) the scope group's categories \\(.+?\\)|action in the scope group's denied actions|category in the scope group's denied categories))*(; scope group of \\d+ other users?)?(; evidence PROVISIONAL)?",
                    List.of("action EXPORT within the scope group's actions (READ, EXPORT)", "action EXPORT outside the scope group's actions (READ)",
                            "action READ outside the scope group's actions (EXPORT); evidence PROVISIONAL"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.LEARNED), "ROLE_SCOPE_OUTSIDE",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("RoleScopeDeltaSummary", "RoleScopeEvidenceState", "StrongestRoleScopeDelta")),
            entry(PromptBlock.DECISION_FACTS, "RecentPermissionChanges",
                    "Permission changes (no change and unknown told apart)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "none since observation start \\(.+\\)|\\d+ .+",
                    List.of("none since observation start (〈관측 시작일〉)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.LEARNED), "RECENT_PERMISSION_CHANGE, TEMPORARY_ELEVATION",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "TemporaryElevation",
                    "Temporary elevation of permissions",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "none since observation start \\(.+\\)|.+ until .+",
                    List.of("none since observation start (〈관측 시작일〉)"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.LEARNED), "RECENT_PERMISSION_CHANGE, TEMPORARY_ELEVATION",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "AuthorizationEffect",
                    "Authorization effect the host states, with policy id and source (a business error is a separate result, W1-6)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "[A-Z_]+( by policy .+)?( \\([A-Z_]+\\))?(; method .+ after authorization)?|method .+ after authorization",
                    List.of("ALLOW (METHOD_AUTHORIZATION_BEFORE_EXECUTION)", "ALLOW by policy 〈정책 ID〉 (METHOD_AUTHORIZATION_CHECK)", "method failed with NOT_FOUND after authorization"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED, PromptSourceGrade.HOST), "AUTHORIZATION_CONFLICT",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("AuthorizationEffectProvenance", "AuthorizationEffectStageNote")),
            entry(PromptBlock.DECISION_FACTS, "DataConflicts",
                    "Conflicts of aliases, authorization, integrations or tenants, and class mismatches between blocks",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "[A-Za-z.]+( \\(.+\\))?(; [A-Za-z.]+( \\(.+\\))?)*",
                    List.of("tenantId (request tenant-a, account tenant-b)"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "TENANT_CONFLICT, DATA_CONFLICT",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("OrganizationId", "TenantConflict", "TenantId")),
            entry(PromptBlock.DECISION_FACTS, "Movement",
                    "Previous location, distance, elapsed time, impossible travel",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+ \\u2192 .+ \\d+ km in \\d+ min.*",
                    List.of("〈이전 위치〉 → 〈현재 위치〉 〈거리〉 km in 〈경과〉 min"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "DEVIATION_MOVEMENT",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "SessionDeviceChange",
                    "Device change within the same session (W2-14)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+ \\u2192 .+ in the same session",
                    List.of("Chrome 140 on Windows → Safari 17 on macOS in the same session"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "SESSION_DEVICE_CHANGE, SESSION_NETWORK_CHANGE; P1",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("OBSERVATION")),
            entry(PromptBlock.DECISION_FACTS, "SessionNetworkChange",
                    "Network change within the same session (W2-14)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+ \\u2192 .+ in the same session",
                    List.of("〈이전 대역〉 → 〈현재 대역〉 in the same session"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "SESSION_DEVICE_CHANGE, SESSION_NETWORK_CHANGE; P1",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("OBSERVATION")),
            entry(PromptBlock.DECISION_FACTS, "ClientSignals",
                    "Bot, TLS, header order and language signals (measured ones only, W1-1)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "bot UA: (yes|no); TLS fingerprint changed: .+",
                    List.of("bot UA: no; TLS fingerprint changed: 〈yes/no〉"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "CLIENT_SIGNAL_TAMPERING",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "BlockedUser",
                    "Block history",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.HOST), "BREAK_GLASS context",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "BreakGlass",
                    "Declared break-glass access",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.HOST), "BREAK_GLASS",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.DECISION_FACTS, "PeerCohort",
                    "Comparison with the cohort",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+",
                    List.of("〈값〉"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.LEARNED), "context",
                    true, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("PeerCohortId", "PeerCohortSummary")),
            entry(PromptBlock.DECISION_FACTS, "Delegation",
                    "Delegated execution: agent, objective, allowed operations and resources, expiry, proof grade, drift and its comparison basis; an unknown without the instruction after it (TO-2)",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    "agent .+, objective [A-Z_]+, allowed [A-Z]+ on [A-Z_]+, drift (yes|no) \\(.+\\)",
                    List.of("agent 〈ID〉, objective READ_ONLY_INCIDENT_SUMMARY, allowed READ on TENANT_DATA, drift no (action READ listed)"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.HOST), "DELEGATION_SCOPE_DRIFT",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("BridgeDelegationSource", "ObjectiveFamilies")),
            entry(PromptBlock.DECISION_FACTS, "ThreatMatch",
                    "Threat class, matched facts, false-positive note, observation period and detection strategy",
                    "DecisionFactsResolver (W2-5) and the approval facts SPI (W2-6)",
                    ".+ matched .+; false-positive note .+; strategy .+",
                    List.of("〈위협 분류〉 matched 〈사실〉; false-positive note 〈…〉; strategy 〈이름〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "THREAT_MATCH",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("ApplicableContexts", "ConfidenceBand", "CrossTenantObjectiveMisusePackSummary", "LearningSummary", "Lift", "OutcomeSummary", "PolicySummary", "PromotedDetectionStrategyCount", "PromotionSummary", "RecommendedSignals", "SupportingContextOnly")),
            entry(PromptBlock.PAST_RECORDS, "PastRecordsState",
                    "Whether past records were retrieved, and the search facts; with an exact lookup the candidates are the records it counted (W3-19)",
                    "search state (W3-4)",
                    PastRecordLineValues.STATE_FORMAT,
                    List.of("5 records of 9 candidates (permission filter applied, 4 denied, 7 distinct signatures)", "none found (no direct personal comparable records)", "not retrieved (timed out)", "12 records of 12 candidates (12 authorized, 0 denied, relevance MIXED_OR_DIFFERENT_RESOURCE, PROJECTED); second search (first search TIMEOUT)"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.COMPUTED), "context",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("HistoricalComparableCount", "No", "RagAuthorizationReason", "RagDeniedDocumentCount", "RagDocumentScopeReason", "RagPermissionFiltered", "RagProjectionState", "RagScopeReason", "RagSearchExecuted")),
            entry(PromptBlock.PAST_RECORDS, "PastRecordCounts",
                    "The request's action counted over the user's past allowed records: on this target, on other targets, and through this entry point",
                    "past record store, exact metadata lookup of the action family (W3-18)",
                    "[A-Z_]+ on this target \\d+( \\(last [^)]+\\))?; on other targets \\d+( \\(last [^)]+\\))?(; target not known \\d+)?; entry point .+ (used \\d+ times? before|first used now)",
                    List.of("EXPORT on this target 3 (last 30 min before this request); on other targets 9 (last 26 h before this request); entry point POST /api/projects/{projectKey}/exports used 12 times before", "EXPORT on this target 0; on other targets 0; entry point POST /api/projects/{projectKey}/exports/async first used now"),
                    PromptMissingNotation.UNKNOWN_BLOCK, null,
                    Set.of(PromptSourceGrade.COMPUTED), "PAST_RECORD_SAME_TARGET; a first use of the entry point",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.PAST_RECORDS, "PastRecord{i}",
                    "One past allowed record (format of dictionary 7)",
                    "past records v2 (W3-3)",
                    PastRecordLineValues.RECORD_FORMAT,
                    List.of("〈날짜 요일 시각〉 (〈n〉 h before this request) / EXPORT /api/projects/{projectKey}/exports / project PLM-OPS / 〈n〉 items / class INTERNAL / 10.40.12.0/24 company office / Chrome 140 on Windows / MFA login / allowed / same target: no / authorized as personal history (same tenant, same user)"),
                    // N-DIC-1: no line without records, PastRecordsState says why; a search that did not retrieve
                    // them has the caller name them unknown now (dictionary 1.4).
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "PAST_RECORD_SAME_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, 5, PromptListOrder.PAST_RECORD, false,
                    List.of("ComparableExample", "RagDocumentAuthorizationReason")),
            entry(PromptBlock.PAST_RECORDS, "PastDeniedDecision{i}",
                    "Recent decision that did not allow",
                    "non-allowed records (W5-4)",
                    ".+ [A-Z]+ \\S+ -> [A-Z]+ \\(.+\\)",
                    List.of("〈날짜 요일 시각〉 EXPORT GB-500 -> CHALLENGE (not verified)"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "PAST_DENIED_SAME_ACTION",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.PAST_RECORDS, "SupportingCases",
                    "Count and summary of supporting comparison cases (reference only)",
                    "supporting search",
                    "\\d+ supporting cases? \\(.+\\), reference only: .+",
                    List.of("2 supporting cases (cohort), reference only: 〈요약〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "context (reference only)",
                    true, PromptDictionaryEntry.PRIORITY_SUPPORTING, null, PromptListOrder.NONE, false,
                    List.of("SupportingComparableCount", "SupportingComparableExample1", "SupportingComparableSummary")),
            entry(PromptBlock.PAST_RECORDS, "ValidatedCases",
                    "Validated past cases and their memory metadata",
                    "enterprise reasoning memory",
                    "\\d+ validated cases: reinforced \\d+, hard negatives \\d+; .+",
                    List.of("〈n〉 validated cases: reinforced 〈n〉, hard negatives 〈n〉; 〈일치 신호〉"),
                    PromptMissingNotation.LINE_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "VALIDATED_CASE_MATCH",
                    true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
                    List.of("CohortPreference", "FreshnessState", "KnowledgeAssistedCaseCount", "MemoryRiskProfile", "ObjectiveAwareReasoningMemory", "ReasoningMemorySummary", "ReasoningState", "RecallPriority", "RetentionTier", "RetrievalWeight")),
            entry(PromptBlock.UNKNOWN, "Coverage",
                    "Context coverage and bridge integration levels, the missing facts and the coverage warnings of the request's context (W3-8), each with its fact, the clause the system text's evidence rules state left out (TO-3); the fixed sentences that restate a level left out (W3-5, Q-73)",
                    "coverage evaluation of PromptContextComposer (204-209, 249-250); coverage warnings the trust profiles do not state",
                    "(context coverage [A-Z_]+(; .+)?; )?bridge [A-Z_]+(; hints .+)?",
                    List.of("context coverage BUSINESS_AWARE; bridge AUTHORIZATION_CONTEXT"),
                    PromptMissingNotation.ALWAYS_PRESENT, null,
                    Set.of(PromptSourceGrade.COMPUTED), "how to read the blocks",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of("BridgeCompletenessLevel", "BridgeCompletenessSummary", "BridgeRemediationHints", "CoverageLevel", "CoverageSummary", "MissingKnowledgeWarning")),
            entry(PromptBlock.UNKNOWN, "Unknown",
                    "Names and kinds of the facts not known now",
                    "dictionary missing rules",
                    // P3 extra 37: the words the renderer writes; a fact that does not apply is not written (1.4).
                    // N-UID-1: each name after the ID the line gives it.
                    PromptUnknownKind.linePattern(),
                    List.of("not-integrated: [U1] ClientSignals, [U2] PeerCohort; unavailable-now: [U3] PastRecord (not retrieved, TIMEOUT)"),
                    PromptMissingNotation.BLOCK_OMITTED, null,
                    Set.of(), "UNKNOWN is neither a match nor a mismatch",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NAME_ASCENDING, false,
                    List.of("MissingKnowledgeWarning")),
            entry(PromptBlock.UNTRUSTED_TEXT, "UntrustedText{i}",
                    "Text written by a user, a document author, the host or an outside party (source, quotes, length and control characters cleaned)",
                    "business label author text, the business label itself (host text, N-INJ-3), the target's category when it is not a token (host text, N-INJ-4), request body summary, outside threat knowledge sentences, anomaly signal text, elevation reason (host text); the requester's user agent (when it cannot be parsed), request path with its path variables, the session's earlier request paths and tickets the requester names (N-INJ-1)",
                    PromptSlotRenderer.UNTRUSTED_FORMAT,
                    List.of("source=" + UntrustedTextSources.DOCUMENT_DESCRIPTION + "; \"External author claim: …\"",
                            "source=" + UntrustedTextSources.BUSINESS_LABEL + "; \"Export of 4831 documents from project GB-500 …\"",
                            "source=" + UntrustedTextSources.RESOURCE_CATEGORY + "; \"Engineering data …\""),
                    PromptMissingNotation.BLOCK_OMITTED, null,
                    Set.of(PromptSourceGrade.UNTRUSTED), "never used for any normalisation, classification or comparison",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, true,
                    List.of()),
            entry(PromptBlock.SECOND_PASS, "FirstPassVerdict",
                    "The verdict of the first pass (the Layer1 model) that sent the request to this pass (W3-9)",
                    "Layer1 assessment handed to Layer2 (cold path)",
                    "(ALLOW|CHALLENGE|ESCALATE|BLOCK)",
                    List.of("ESCALATE"),
                    PromptMissingNotation.BLOCK_OMITTED, null,
                    Set.of(PromptSourceGrade.INFERRED), "what this pass adds to",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.SECOND_PASS, "NewlyKnown",
                    "A fact the first pass did not have that this pass gathered, by its dictionary name (the uncertain fact; fact IDs come with W3-13), with how many were found and the first pass state",
                    "Layer2 gathering (W3-9)",
                    "PastRecord\\{i\\}: \\d+ found \\(first pass: not retrieved, [A-Z_]+\\)",
                    List.of("PastRecord{i}: 3 found (first pass: not retrieved, TIMEOUT)"),
                    PromptMissingNotation.BLOCK_OMITTED, null,
                    Set.of(PromptSourceGrade.COMPUTED), "what is new since the first pass",
                    false, PromptDictionaryEntry.PRIORITY_HIGH_VALUE, null, PromptListOrder.NONE, false,
                    List.of()),
            entry(PromptBlock.SECOND_PASS, "NewPastRecord{i}",
                    "One past allowed record only this pass found (format of dictionary 7)",
                    "Layer2 past record search (W3-9), past records v2 (W3-3)",
                    PastRecordLineValues.RECORD_FORMAT,
                    List.of("〈날짜 요일 시각〉 (〈n〉 h before this request) / EXPORT /api/projects/{projectKey}/exports / project PLM-OPS / 〈n〉 items / class INTERNAL / 10.40.12.0/24 company office / Chrome 140 on Windows / MFA login / allowed / same target: no / authorized as personal history (same tenant, same user)"),
                    PromptMissingNotation.BLOCK_OMITTED, null,
                    Set.of(PromptSourceGrade.LEARNED), "PAST_RECORD_SAME_TARGET",
                    false, PromptDictionaryEntry.PRIORITY_REQUIRED, 5, PromptListOrder.PAST_RECORD, false,
                    List.of()));

    /** Labels whose facts a block header states (the source scope of the block). */
    public static final Map<PromptBlock, List<String>> BLOCK_HEADER_PRESERVED_LABELS = Map.of(
            PromptBlock.PAST_RECORDS, List.of("HistoricalComparableScope", "HistoricalComparableSummary"));

    /** The version of the v21 dictionary. */
    public static final String V21_VERSION = "v21";

    /** One approval or ticket record of a v21 line: its id or the requester's naming, kind, approver and values. */
    private static final String V21_TICKET_RECORD =
            "(the ticket named by the requester does not exist|(\\S+|the ticket named by the requester)( [A-Z_]+)?( by \\S+)?(, [^;]+)?)";

    /** The request's value against one of the scope group's lists, or a denied mark (v21). */
    private static final String V21_SCOPE_PART = "(action [A-Z_]+ against the scope group's actions \\(.+?\\)"
            + "|category \\S+ against the scope group's categories \\(.+?\\)"
            + "|action in the scope group's denied actions|category in the scope group's denied categories)";

    /**
     * v21.4 (finding 7 of the v21 plan): the scope the host's records hold the request's target in (a document's or a
     * customer's project), after the target line. A v21 entry only, so the v20 render keeps its lines.
     */
    private static final PromptDictionaryEntry TARGET_SCOPE = entry(PromptBlock.REQUEST, "TargetScope",
            "The scope the host's records hold the target in, by its key and value: the host's own record, unlike the"
                    + " request path and the business label",
            "host request attributes (resource scope)",
            "[A-Za-z][A-Za-z0-9_]*=[A-Za-z0-9][A-Za-z0-9._:-]* \\(" + SecurityDecisionPromptValues.TARGET_SCOPE_NOTE + "\\)",
            List.of("projectKey=HX-310 (" + SecurityDecisionPromptValues.TARGET_SCOPE_NOTE + ")"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.HOST),
            "which scope the target is in; the model reads it with the assignment and the usual targets",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /** A relative time of a v21 agent line ({@code 3 min before this request}). */
    private static final String V21_RELATIVE = "\\d+ (min|h|days) (before|after) this request";

    /**
     * v21.9 (A2-11): what the request's access token states, after the subject line. A session's request has none.
     */
    private static final PromptDictionaryEntry CREDENTIAL = entry(PromptBlock.REQUEST, "Credential",
            "The request's access token: its kind (a user's, a delegated or a client's own), the grant it shows, the"
                    + " client, when it was issued and when it expires, the actor chain and whether it is bound to a key",
            "access token claims as the resource server verified them (CredentialFacts)",
            "(user access token|delegated access token|client's own access token)(, grant \\S+)?(, client \\S+)?"
                    + "(, issued " + V21_RELATIVE + ")?(, expires " + V21_RELATIVE + ")?"
                    + "(, actor chain depth \\d+( \\(before it: .+\\))?)?"
                    + ", (not bound to a key|bound to a DPoP key|bound to an mTLS certificate)",
            List.of("delegated access token, grant token-exchange, client report-agent-client, issued 2 min before"
                            + " this request, expires 28 min after this request, actor chain depth 1, not bound to a key",
                    "client's own access token, grant client_credentials, client report-agent-client, issued 1 min"
                            + " before this request, expires 59 min after this request, not bound to a key"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.HOST),
            "how the request was authenticated; the model reads it with the subject and the delegation",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /** docs/agent F-5 (RW-1): the confirmation the accountable person gave for this request, after the credential. */
    private static final PromptDictionaryEntry CONFIRMATION = entry(PromptBlock.REQUEST, "Confirmation",
            "The accountable person's confirmation this request carried: who approved it and when, when and why it"
                    + " was asked, that it covers this one request only, and the authorization it was recorded as",
            "the confirmation record the request used (AgentConfirmationFacts)",
            "approved by (\\S+|not stated)( " + V21_RELATIVE + ")?, asked (" + V21_RELATIVE + " )?because"
                    + " (the delegation had ended|the decision in force asked for a check|the agent asked for it"
                    + "|not stated|[a-z ]+), for this request only, authorization (\\S+|not recorded)",
            List.of("approved by alice 0 min before this request, asked 2 min before this request because the"
                    + " delegation had ended, for this request only, authorization ctxa-as:5c1d2e3f"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.COMPUTED),
            "what the accountable person confirmed; the model reads it with the subject, the credential and the"
                    + " delegation",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /** v21.9 (A2-9): what an agent did so far in its session, after the session's requests. */
    private static final PromptDictionaryEntry DELEGATION_ACTIVITY = entry(PromptBlock.SESSION, "DelegationActivity",
            "What the agent did so far in this session (a delegation's session for a delegated agent): the earlier"
                    + " requests by action, the items exported, the distinct targets, the refused ones, the first"
                    + " request's time, the operations of the latest requests in the order made and the median time"
                    + " between the session's requests",
            "session decision history (W1-11) of an agent's session",
            "no earlier request in this agent session|\\d+ earlier requests? in this agent session \\(.+\\),"
                    + " [\\d,]+ items exported, \\d+ distinct targets?, \\d+ refused(, first " + V21_RELATIVE + ")?"
                    + "(, order [A-Z_]+( x\\d+)?(, [A-Z_]+( x\\d+)?)* \\(last \\d+\\))?"
                    + "(, median \\d+ (s|min) between requests)?",
            List.of("7 earlier requests in this agent session (READ 5, EXPORT 2), 1,240 items exported, 6 distinct"
                    + " targets, 1 refused, first 12 min before this request, order LIST, READ x5, EXPORT (last 7),"
                    + " median 2 s between requests"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.COMPUTED),
            "DELEGATION_SCOPE_DRIFT, SESSION_SEQUENCE; the model reads it with the delegation",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /**
     * v21.10 (A2-12): whose company records the lines are, before the policy line, when the host looked them up for
     * another person than the request's subject (an agent's sponsor or the person it acts for).
     */
    private static final PromptDictionaryEntry RECORDS_HOLDER = entry(PromptBlock.DECISION_FACTS, "RecordsHolder",
            "Whose company records the record lines are, when the host looked them up for another person than the"
                    + " request's subject: an agent's request is judged with the records of the person it acts for or of"
                    + " its sponsor",
            "host record suppliers (RecordsHolder: FrictionProfile recordsHolderId and recordsHolderRelation)",
            "\\S+ \\((the agent's sponsor|the delegator)\\)",
            List.of("v1a2b3c-eng-k (the agent's sponsor)"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.HOST),
            "whose assignment, duty, tickets and trips the record lines state; the model reads them with it",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /** v21.9 (A2-10): who wrote the records the request rests on and when, after the delegation line. */
    private static final PromptDictionaryEntry RECORD_PROVENANCE = entry(PromptBlock.DECISION_FACTS, "RecordProvenance",
            "Who wrote each approval, ticket and delegation record the request rests on, as the host states it, and"
                    + " when; the author's relation to this request (its agent, its subject, the delegator) when it has one",
            "host record suppliers (ApprovalRecord, TicketRecord, DelegationRecord recordedBy and recordedAt)",
            "(approval|ticket|delegation) .+ recorded.+(; (approval|ticket|delegation) .+ recorded.+)*",
            List.of("approval APR-1 recorded by report-agent (this request's agent) 2 min before this request;"
                    + " delegation DLG-1 recorded by alice (the delegator) 1 h before this request"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.HOST),
            "RECORD_COVERS_WORK, NO_COVERING_RECORD; who stated the record the request rests on",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /** A digest of a user agent in an agent's client value (AgentBaselineView.digest). */
    private static final String V21_CLIENT = "\\S+( #[0-9a-f]{16})?";

    /**
     * v21.12 (A4-3): whose usual behaviour the baseline lines of an agent's request state, before the status line: the
     * agent's own learned requests, never the person's (A3-1). A person's request has no line.
     */
    private static final PromptDictionaryEntry BASELINE_SUBJECT = entry(PromptBlock.USER_BASELINE, "BaselineSubject",
            "Whose usual behaviour the baseline lines state for an agent's request: the agent's own learned requests,"
                    + " the person it acts for named; the person's own baseline is not read for it",
            "learning subject (LearningSubject: the agent's learning key)",
            "agent \\S+ (acting for \\S+|on its own), learned from this agent's own requests",
            List.of("agent agt-1a2b-report acting for alice, learned from this agent's own requests"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.COMPUTED),
            "which subject the usual lines describe; the model reads them as the agent's",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /**
     * v21.12 (A4-1): which operation usually follows which in the agent's sessions, after the usual actions, and whether
     * this request's pair was seen. A person's request has no line.
     */
    private static final PromptDictionaryEntry USUAL_SEQUENCE = entry(PromptBlock.USER_BASELINE, "UsualSequence",
            "Which operation usually follows which in the agent's sessions (its learned requests, before this activity"
                    + " period) with how often, and this request's pair with how often it was seen",
            "work profile observations of the agent (previous operation of the session)",
            "(none learned|[A-Z_]+>[A-Z_]+ \\d+(, [A-Z_]+>[A-Z_]+ \\d+)*); (this request [A-Z_]+>[A-Z_]+ seen \\d+"
                    + " times? before|this request is its session's first operation)",
            List.of("LIST>READ 3, READ>READ 12, READ>EXPORT 1; this request READ>EXPORT seen 1 time before"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.LEARNED),
            "SESSION_SEQUENCE; the model reads the order with the delegation's objective",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /**
     * v21.12 (A4-6): the clients the agent usually calls from, after the usual devices: its OAuth client and the digest
     * of its user agent (the user agent itself is untrusted text), and whether this request's was seen.
     */
    private static final PromptDictionaryEntry USUAL_CLIENTS = entry(PromptBlock.USER_BASELINE, "UsualClients",
            "The clients the agent usually calls from (its learned requests, before this activity period): the OAuth"
                    + " client, or no-client for an agent signed in with its own account, and the digest of the user"
                    + " agent, with how often; and this request's client with how often it was seen",
            "work profile observations of the agent (credential client, user agent digest)",
            "(none learned|" + V21_CLIENT + " \\d+(, " + V21_CLIENT + " \\d+)*); (this request " + V21_CLIENT
                    + " seen \\d+ times? before|this request states no client)",
            List.of("report-client #1a2b3c4d5e6f7a8b 18; this request report-client #1a2b3c4d5e6f7a8b seen 18 times"
                    + " before"),
            PromptMissingNotation.LINE_OMITTED, null,
            Set.of(PromptSourceGrade.LEARNED),
            "DEVICE_CHANGE, NETWORK_CHANGE; the model reads it with the credential and the network",
            true, PromptDictionaryEntry.PRIORITY_REQUIRED, null, PromptListOrder.NONE, false,
            List.of());

    /**
     * v21.13 (B3-3): the reasoning memory lines a v21 ValidatedCases line writes, in the memory section's order: the
     * section's lines without the removed ones and those holding stored free text, which UNTRUSTED TEXT quotes.
     */
    private static final List<String> VALIDATED_CASE_LINES = List.of("ReinforcedCaseCount", "HardNegativeCaseCount",
            "FalseNegativeCaseCount", "KnowledgeAssistedCaseCount", "RetentionTier", "RecallPriority", "FreshnessState",
            "ReasoningState", "CohortPreference", "MemoryRiskProfile", "RetrievalWeight", "MatchedSignalKeys",
            "ObjectiveFamilies");

    /**
     * The v21 dictionary (V-4): the v20 entries without PolicySatisfied, the lines that state records and comparisons in
     * place of the core's conclusions (no difference marked explained, no record that covers, no scope that holds), and
     * the decision use of each entry without the minimum action rules. The model judges what the lines mean.
     */
    public static final List<PromptDictionaryEntry> V21_ENTRIES = v21Entries();

    private SecurityDecisionPromptDictionary() {
    }

    public static PromptDictionarySlotPlanProvider slotPlanProvider() {
        return new PromptDictionarySlotPlanProvider(ENTRIES, VERSION);
    }

    /** The slot plans of the v21 dictionary. */
    public static PromptDictionarySlotPlanProvider v21SlotPlanProvider() {
        return new PromptDictionarySlotPlanProvider(V21_ENTRIES, V21_VERSION);
    }

    private static List<PromptDictionaryEntry> v21Entries() {
        List<PromptDictionaryEntry> entries = new ArrayList<>();
        for (PromptDictionaryEntry entry : ENTRIES) {
            // Whether the policy is met is the model's to judge from the policy and the records.
            if (entry.block() == PromptBlock.DECISION_FACTS && "PolicySatisfied".equals(entry.name())) {
                continue;
            }
            if (entry.block() == PromptBlock.DECISION_FACTS && "Policy".equals(entry.name())) {
                entries.add(RECORDS_HOLDER);
            }
            if (entry.block() == PromptBlock.USER_BASELINE && "BaselineStatus".equals(entry.name())) {
                entries.add(BASELINE_SUBJECT);
            }
            entries.add(v21(entry));
            if (entry.block() == PromptBlock.USER_BASELINE && "UsualActions".equals(entry.name())) {
                entries.add(USUAL_SEQUENCE);
            }
            if (entry.block() == PromptBlock.USER_BASELINE && "UsualDevices".equals(entry.name())) {
                entries.add(USUAL_CLIENTS);
            }
            if (entry.block() == PromptBlock.REQUEST && "Subject".equals(entry.name())) {
                entries.add(CREDENTIAL);
                entries.add(CONFIRMATION);
            }
            if (entry.block() == PromptBlock.REQUEST && "Target".equals(entry.name())) {
                entries.add(TARGET_SCOPE);
            }
            if (entry.block() == PromptBlock.SESSION && "RequestsInSession".equals(entry.name())) {
                entries.add(DELEGATION_ACTIVITY);
            }
            if (entry.block() == PromptBlock.DECISION_FACTS && "Delegation".equals(entry.name())) {
                entries.add(RECORD_PROVENANCE);
            }
        }
        return List.copyOf(entries);
    }

    private static PromptDictionaryEntry v21(PromptDictionaryEntry entry) {
        // 판정층 E-4b: after a first pass that retrieved its own past records the second pass knows none as new.
        if (entry.block() == PromptBlock.SECOND_PASS && "NewlyKnown".equals(entry.name())) {
            return with(entry,
                    "What the second pass knows that the first did not: the past records it found when the first pass"
                            + " could not retrieve any (how many, with the first pass state), or none new when the first"
                            + " pass retrieved its own",
                    "PastRecord\\{i\\}: (\\d+ found \\(first pass: not retrieved, [A-Z_]+\\)"
                            + "|none new \\(first pass: retrieved, [A-Z_]+\\))",
                    List.of("PastRecord{i}: 3 found (first pass: not retrieved, TIMEOUT)",
                            "PastRecord{i}: none new (first pass: retrieved, AVAILABLE)"),
                    entry.decisionUse());
        }
        // v21.9 (A2-6): the coverage after the delegation's records were read, each warning with its fact only.
        if (entry.block() == PromptBlock.UNKNOWN && "Coverage".equals(entry.name())) {
            return with(entry,
                    "Context coverage and bridge integration levels, the missing facts and the coverage warnings of the"
                            + " request's context, each with its fact only; a delegation the records completed is not"
                            + " named missing, nor its bridge hint, and a request that is not delegated has no delegated"
                            + " objective facts",
                    entry.formatPattern(), entry.formatExamples(), entry.decisionUse());
        }
        // v21.9 (A2-5, A2-8): a delegation's objective and a protected method's call arguments are untrusted texts;
        // v21.11 (A3-5) the past records' targets, v21.13 (B3-3) the validated case memory's stored texts.
        if (entry.block() == PromptBlock.UNTRUSTED_TEXT) {
            return withSourcePath(entry, entry.sourcePath() + "; the delegation's objective (host text, A2-5), the"
                    + " protected method's call arguments (requester, A2-8), the targets of the past record and"
                    + " denied decision lines drawn (requester, A3-5) and the validated case memory's stored texts"
                    + " (an earlier analysis' summary, a threat signal's summary, matched threat knowledge; B3-3)");
        }
        // v21.13 (B3-3): the validated case memory's stored free texts are untrusted texts, and the form is the memory
        // lines the render writes (the v20 form names a summary the render never wrote).
        if (entry.block() == PromptBlock.PAST_RECORDS && "ValidatedCases".equals(entry.name())) {
            String label = "(" + String.join("|", VALIDATED_CASE_LINES) + ")";
            return with(entry, entry.meaning() + "; their stored texts (an earlier analysis' summary, a threat"
                            + " signal's summary, matched threat knowledge) are in UNTRUSTED TEXT",
                    label + ": .+(; " + label + ": .+)*",
                    List.of("ReinforcedCaseCount: 3; HardNegativeCaseCount: 1; RetentionTier: HOT; MatchedSignalKeys:"
                            + " sig-7"),
                    entry.decisionUse());
        }
        // v21.11 (A3-5): a past record's target is the path variables a requester wrote, an untrusted text.
        if (entry.block() == PromptBlock.PAST_RECORDS && "PastRecord{i}".equals(entry.name())) {
            return with(entry, entry.meaning() + "; the target field says the target is in UNTRUSTED TEXT, where the"
                            + " requester's value is; the same-target field is the core's comparison",
                    entry.formatPattern(),
                    List.of("\u3008날짜 요일 시각\u3009 (\u3008n\u3009 h before this request) / EXPORT"
                            + " /api/projects/{projectKey}/exports / " + PastRecordLines.TARGET_APART + " / \u3008n\u3009"
                            + " items / class INTERNAL / 10.40.12.0/24 company office / Chrome 140 on Windows / MFA login"
                            + " / allowed / same target: no / authorized as personal history (same tenant, same user)"),
                    entry.decisionUse());
        }
        if (entry.block() == PromptBlock.PAST_RECORDS && "PastDeniedDecision{i}".equals(entry.name())) {
            return with(entry, entry.meaning() + "; its target is in UNTRUSTED TEXT", entry.formatPattern(),
                    List.of("\u3008날짜 요일 시각\u3009 EXPORT " + PastDeniedLines.TARGET_APART + " -> CHALLENGE (not verified)"),
                    entry.decisionUse());
        }
        if (entry.block() == PromptBlock.SECOND_PASS && "NewPastRecord{i}".equals(entry.name())) {
            return with(entry, entry.meaning() + "; the requester's target is not shown, the same-target field is the"
                            + " core's comparison", entry.formatPattern(),
                    List.of("\u3008날짜 요일 시각\u3009 (\u3008n\u3009 h before this request) / EXPORT"
                            + " /api/projects/{projectKey}/exports / " + PastRecordLines.TARGET_WITHHELD + " /"
                            + " \u3008n\u3009 items / class INTERNAL / 10.40.12.0/24 company office / Chrome 140 on"
                            + " Windows / MFA login / allowed / same target: no / authorized as personal history (same"
                            + " tenant, same user)"),
                    entry.decisionUse());
        }
        if (entry.block() == PromptBlock.REQUEST) {
            return switch (entry.name()) {
                // v21.9 (A2-4): an agent's request names the agent apart from the account whose authority it uses.
                case "Subject" -> with(entry,
                        "Subject: account kind, account age, department, title, tenant (and organisation when"
                                + " different); a delegated agent's request names the person's account with the agent it"
                                + " goes through, an agent on its own is named by its registration with its client,"
                                + " sponsor and registration status",
                        entry.formatPattern(),
                        plus(entry.formatExamples(),
                                "alice (HUMAN_USER, account 400 days, dept Design, through agent report-agent, agent"
                                        + " sponsor bob, agent registration ACTIVE)",
                                "report-agent (AGENT_RUNTIME, account age not known, client report-agent-client, sponsor"
                                        + " bob, registration ACTIVE)"),
                        "identity context; who acts and whose authority is used");
                case "ResourceClass" -> withUse(entry, "DEVIATION_RESOURCE_CLASS; what the data is");
                case "Network" -> withUse(entry, "DEVIATION_NETWORK");
                case "Device" -> withUse(entry, "DEVIATION_DEVICE");
                default -> entry;
            };
        }
        if (entry.block() != PromptBlock.DECISION_FACTS) {
            return entry;
        }
        return switch (entry.name()) {
            // v21.9 (A2-4): the delegation by its fields; its objective's free text is an untrusted text (A2-5).
            case "Delegation" -> with(entry,
                    "Delegated execution: the agent and the person it acts for, the chain depth, the objective, the"
                            + " allowed operations and resources, the expiry, the quantity limits the delegation states"
                            + " (RL-6), the proof and the comparison of this request with the objective's scope and"
                            + " those limits",
                    "agent .+ for .+, chain depth \\d+, objective .+, allowed .+ on .+, expires .+, proof .+,"
                            + " drift (yes|no|not compared) \\(.+\\)",
                    List.of("agent report-agent for alice, chain depth 1, objective REPORTING, allowed READ/EXPORT on"
                                    + " PROJECT_DOCUMENTS/HX-310, expires 3 h after this request, proof signed token claim and"
                                    + " delegation record, drift no (Current action family is listed in delegated action scope"
                                    + " evidence; Current resource matches delegated raw resource constraints)",
                            "agent report-agent for alice, chain depth 1, objective REPORTING, allowed READ/EXPORT on"
                                    + " PROJECT_DOCUMENTS/HX-310, expires 3 h after this request, limits 40 items per request"
                                    + " and 40 items in the session, proof signed token claim and delegation record, drift yes"
                                    + " (400 requested items exceed the delegation's limit of 40 items per request.)"),
                    "DELEGATION_SCOPE_DRIFT: the core's own comparison of the request with the delegation's operations,"
                            + " resources and stated limits; DELEGATION_OBJECTIVE_EXCEEDED and RECORD_COVERS_WORK: whether"
                            + " the request stays within what the delegation calls for is the model's judgment");
            case "DeviationsFromBaseline" -> with(entry,
                    "Differences from the usual: per dimension, the request's value, how often and when it was seen and"
                            + " the usual value, dimensions compared, overlap of the closest past record read for this"
                            + " action on time, login method and browser; whether a record explains a difference is the"
                            + " model's to judge",
                    entry.formatPattern(),
                    List.of("3 of 8 compared -> time 03 seen 0 of 25 on 0 of 5 days, first time; target projectKey seen 0"
                                    + " of 25; class CRITICAL seen 0 of 25; closest of the past records read for this"
                                    + " action matches 2 of 3 on time, login method and browser",
                            "0 of 8 compared; closest of the past records read for this action matches 3 of 3 on time,"
                                    + " login method and browser",
                            "1 of 8 compared -> rate \u3008n\u3009 requests in the last 60 min, usual median \u3008m\u3009, 95th"
                                    + " percentile \u3008p\u3009 in the 60 min up to a request (baseline not established)"),
                    "DEVIATION_*; each difference is checked against the records by the model");
            case "Policy" -> withUse(entry, "what the work needs a record for; NO_COVERING_RECORD, POLICY_NOT_KNOWN");
            case "Approval" -> with(entry,
                    "Approval record: approver, state, purpose, target, limit, use before this request, period, decision"
                            + " time, pending approvers, the host's own check against this request (what it marks as not"
                            + " matching, or that it marks none) and what could not be checked",
                    entry.formatPattern(),
                    List.of("APR-\u2026 by pm-11, APPROVED, PROJECT_TRANSFER, GB-500, up to 5,000 items, used 0 before this"
                                    + " request, valid 09-29 03:17..10-01 03:17 (from 24 h before to 24 h after this"
                                    + " request), decided 09-29 03:10 (24 h before this request), the host's own check"
                                    + " marks no mismatch with this request",
                            "APR-\u2026 by pm-11, APPROVED, PROJECT_TRANSFER, GB-500, up to 5,000 items, decided 09-30 03:37"
                                    + " (20 min after this request), not known: the items exported under it outside this"
                                    + " session (the host does not report them)"),
                    "RECORD_*: whether the record covers the work is the model's judgment");
            case "Ticket" -> with(entry,
                    "Ticket record: kind, approver, state, purpose, target, period and the host's own check against"
                            + " this request (what it marks as not matching, or that it marks none); a ticket the requester"
                            + " names is 'the ticket named by the requester' (what the requester wrote is an untrusted"
                            + " text, N-INJ-1)",
                    "no ticket found|" + V21_TICKET_RECORD + "(; " + V21_TICKET_RECORD + ")*",
                    List.of("no ticket found", "the ticket named by the requester does not exist",
                            "TCK-90090ef490a6-1 INCIDENT by pm-11, ACTIVE, INCIDENT_RECOVERY, HX-200, valid 09-30"
                                    + " 12:20..09-30 20:20 (from \u3008n\u3009 h before to \u3008n\u3009 h after this request)"),
                    "RECORD_*, TICKET_CLAIM_FALSE: whether the ticket covers the work is the model's judgment");
            case "Assignment" -> withUse(entry, "a record the model checks a difference against; ASSIGNED_TARGET");
            case "OnCall" -> withUse(entry, "a record the model checks a difference against; ON_CALL");
            case "Travel" -> withUse(entry, "a record the model checks a difference against; TRAVEL_EXPLAINS_NETWORK");
            case "RepeatInSession" -> withUse(entry,
                    "REPEAT_IN_SESSION, SESSION_SEQUENCE; the use under a record before this request");
            case "RoleScope" -> with(entry,
                    "The request's action and category against the scope group's 30-day lists, the denied marks and the"
                            + " evidence state; whether the lists hold the request is the model's to read",
                    V21_SCOPE_PART + "(; " + V21_SCOPE_PART + ")*(; scope group of \\d+ other users?)?(; evidence PROVISIONAL)?",
                    List.of("action EXPORT against the scope group's actions (READ, EXPORT)",
                            "action READ against the scope group's actions (EXPORT); evidence PROVISIONAL"),
                    "ROLE_SCOPE_OUTSIDE (the model's reading of the lists)");
            case "SessionDeviceChange", "SessionNetworkChange" ->
                    withUse(entry, "SESSION_DEVICE_CHANGE, SESSION_NETWORK_CHANGE");
            default -> entry;
        };
    }

    private static List<String> plus(List<String> examples, String... more) {
        List<String> all = new ArrayList<>(examples);
        all.addAll(List.of(more));
        return List.copyOf(all);
    }

    private static PromptDictionaryEntry withSourcePath(PromptDictionaryEntry entry, String sourcePath) {
        return new PromptDictionaryEntry(entry.block(), entry.name(), entry.meaning(), sourcePath, entry.formatPattern(),
                entry.formatExamples(), entry.missing(), entry.missingText(), entry.grades(), entry.decisionUse(),
                entry.conditional(), entry.priority(), entry.listCap(), entry.listOrder(), entry.truncationAllowed(),
                entry.preservedLabels());
    }

    private static PromptDictionaryEntry withUse(PromptDictionaryEntry entry, String decisionUse) {
        return with(entry, entry.meaning(), entry.formatPattern(), entry.formatExamples(), decisionUse);
    }

    private static PromptDictionaryEntry with(PromptDictionaryEntry entry, String meaning, String formatPattern,
                                              List<String> formatExamples, String decisionUse) {
        return new PromptDictionaryEntry(entry.block(), entry.name(), meaning, entry.sourcePath(), formatPattern,
                formatExamples, entry.missing(), entry.missingText(), entry.grades(), decisionUse, entry.conditional(),
                entry.priority(), entry.listCap(), entry.listOrder(), entry.truncationAllowed(), entry.preservedLabels());
    }

    private static PromptDictionaryEntry entry(PromptBlock block, String name, String meaning, String sourcePath,
                                               String formatPattern, List<String> formatExamples,
                                               PromptMissingNotation missing, String missingText,
                                               Set<PromptSourceGrade> grades, String decisionUse, boolean conditional,
                                               String priority, Integer listCap, PromptListOrder listOrder,
                                               boolean truncationAllowed,
                                               List<String> preservedLabels) {
        return new PromptDictionaryEntry(block, name, meaning, sourcePath, formatPattern, formatExamples, missing,
                missingText, grades, decisionUse, conditional, priority, listCap, listOrder, truncationAllowed,
                preservedLabels);
    }

    /**
     * The dictionary as text: its version, every entry with all its fields in order (the source grades sorted, since a
     * set has no order) and the labels each block header keeps. A bundle's dictionary element (B2) is this text (R1b-7).
     */
    public static String contentText() {
        return contentText(VERSION, ENTRIES) + "blockHeaderLabels=" + new TreeMap<>(BLOCK_HEADER_PRESERVED_LABELS) + '\n';
    }

    /** The v21 dictionary as text, with the titles the v21 blocks carry; the v21 bundle's dictionary element (B2). */
    public static String contentTextV21() {
        StringBuilder titles = new StringBuilder();
        for (PromptBlock block : PromptBlock.values()) {
            titles.append(block).append('=').append(block.v21Title()).append(';');
        }
        return contentText(V21_VERSION, V21_ENTRIES) + "blockHeaderLabels=" + new TreeMap<>(BLOCK_HEADER_PRESERVED_LABELS)
                + '\n' + "blockTitles=" + titles + '\n';
    }

    private static String contentText(String version, List<PromptDictionaryEntry> entries) {
        StringBuilder text = new StringBuilder("version=").append(version).append('\n');
        for (PromptDictionaryEntry entry : entries) {
            text.append(entry.block()).append('|').append(entry.name()).append('|').append(entry.meaning())
                    .append('|').append(entry.sourcePath()).append('|').append(entry.formatPattern())
                    .append('|').append(entry.formatExamples()).append('|').append(entry.missing())
                    .append('|').append(entry.missingText()).append('|').append(new TreeSet<>(entry.grades()))
                    .append('|').append(entry.decisionUse()).append('|').append(entry.conditional())
                    .append('|').append(entry.priority()).append('|').append(entry.listCap())
                    .append('|').append(entry.listOrder()).append('|').append(entry.truncationAllowed())
                    .append('|').append(entry.preservedLabels()).append('\n');
        }
        return text.toString();
    }

    /** The digest of {@link #contentText()}, the same as a bundle's dictionary element hash (R1b-7). */
    public static String contentDigest() {
        return ContentDigest.VALUE;
    }

    /** The digest of {@link #contentTextV21()}, the same as the v21 bundle's dictionary element hash. */
    public static String contentDigestV21() {
        return ContentDigest.V21_VALUE;
    }

    /** The digests, computed once when they are first asked for. */
    private static final class ContentDigest {

        private static final String VALUE = PromptBundleHashes.present("B2", contentText(), "dictionary").hash();
        private static final String V21_VALUE = PromptBundleHashes.present("B2", contentTextV21(), "dictionary").hash();
    }
}
