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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputLine;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputSummary;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Quality plan 3.2: the decision input of a labelled case as the screen summarizes it in five views, read from the
 * values the replay of a sealed decision reads (the canonical context, the request facts, the authentication state):
 * the request (what was asked of which resource, when, with what authority), the session (who, from where, signed in
 * how, on which device), how the request differs from the person's usual (the deviations the context compared and
 * found different), the work records (the approvals and tickets the business records hold) and what is not known (the
 * facts the context could not have). A value the input does not hold is left out; nothing is worked out beyond it.
 */
public final class QualityCaseInputSummary {

    private QualityCaseInputSummary() {
    }

    public static InputSummary of(QualityCaseInput input) {
        JsonNode context = input.canonicalContext();
        JsonNode resource = context.path("resource");
        JsonNode facts = input.requestFacts();
        JsonNode auth = input.authState();

        List<InputLine> request = new ArrayList<>();
        String method = first(text(resource.path("httpMethod")), text(facts.path("httpMethod")));
        String path = first(text(resource.path("requestPath")), text(facts.path("requestPath")));
        add(request, "request", join(" ", method, path));
        add(request, "resource", first(text(resource.path("businessLabel")), text(resource.path("resourceId")),
                text(facts.path("resourceId"))));
        add(request, "resourceClass", text(resource.path("resourceClass")));
        add(request, "sensitivity", text(resource.path("sensitivity")));
        add(request, "action", text(resource.path("actionFamily")));
        add(request, "items", text(resource.path("requestedItems")));
        add(request, "requestedAt", text(context.path("requestObservedAt")));
        add(request, "authorization", first(text(auth.path("authorizationEffect")),
                text(context.path("authorization").path("authorizationEffect"))));
        add(request, "roles", first(text(auth.path("effectiveRoles")),
                text(context.path("authorization").path("effectiveRoles"))));

        JsonNode session = context.path("session");
        JsonNode device = context.path("device");
        JsonNode location = context.path("location");
        List<InputLine> sessionLines = new ArrayList<>();
        add(sessionLines, "user", first(text(context.path("actor").path("userId")), text(facts.path("userId"))));
        add(sessionLines, "clientIp", first(text(session.path("clientIp")), text(facts.path("clientIp"))));
        add(sessionLines, "network", join(" · ", text(location.path("networkZone")), text(location.path("ipBand")),
                text(location.path("country")), text(location.path("city"))));
        add(sessionLines, "authentication", first(text(session.path("authenticationType")),
                text(auth.path("authMethod"))));
        add(sessionLines, "mfa", first(text(session.path("mfaVerified")), text(auth.path("mfaVerified"))));
        add(sessionLines, "newSession", text(session.path("newSession")));
        add(sessionLines, "newDevice", text(session.path("newDevice")));
        String browser = join(" ", text(device.path("browser")), text(device.path("browserVersion")));
        add(sessionLines, "device", join(" · ", browser, text(device.path("os"))));
        add(sessionLines, "failedLogins", text(session.path("failedLoginAttempts")));
        add(sessionLines, "recentBlocks", text(session.path("recentBlockCount")));

        List<InputLine> deviation = new ArrayList<>();
        for (JsonNode found : context.path("decisionFacts").path("deviations")) {
            if (!found.path("different").asBoolean(false)) {
                continue;
            }
            String usual = first(text(found.path("usual")), text(found.path("observed").path("value")));
            String explained = text(found.path("explainedBy"));
            String current = text(found.path("current"));
            if (current == null) {
                continue;
            }
            deviation.add(new InputLine(first(text(found.path("dimension")), "OTHER"),
                    join(" · ", current, usual != null ? "(" + usual + ")" : null, explained)));
        }

        JsonNode friction = context.path("frictionProfile");
        List<InputLine> records = new ArrayList<>();
        add(records, "approvalStatus", text(friction.path("approvalStatus")));
        for (JsonNode line : friction.path("approvalLineage")) {
            String value = text(line);
            if (value != null) {
                records.add(new InputLine(null, value));
            }
        }

        List<InputLine> unknown = new ArrayList<>();
        JsonNode decisionFacts = context.path("decisionFacts");
        for (JsonNode fact : decisionFacts.path("unknown")) {
            add(unknown, "unknownFact", text(fact));
        }
        JsonNode unavailable = decisionFacts.path("unavailable");
        if (unavailable.isObject()) {
            Iterator<String> names = unavailable.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                add(unknown, "unavailableFact", join(": ", name, text(unavailable.path(name))));
            }
        }
        for (JsonNode fact : context.path("coverage").path("missingCriticalFacts")) {
            String value = text(fact);
            if (value != null) {
                unknown.add(new InputLine(null, value));
            }
        }
        return new InputSummary(List.copyOf(request), List.copyOf(sessionLines), List.copyOf(deviation),
                List.copyOf(records), List.copyOf(unknown));
    }

    private static void add(List<InputLine> lines, String name, @Nullable String value) {
        if (value != null) {
            lines.add(new InputLine(name, value));
        }
    }

    /** A value of the input as text: a scalar as it is, an array of scalars joined; null for none. */
    @Nullable
    static String text(@Nullable JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        if (node.isArray()) {
            List<String> parts = new ArrayList<>();
            node.forEach(item -> {
                String part = text(item);
                if (part != null) {
                    parts.add(part);
                }
            });
            return parts.isEmpty() ? null : String.join(", ", parts);
        }
        if (node.isObject()) {
            return node.isEmpty() ? null : node.toString();
        }
        String value = node.asText().trim();
        return value.isEmpty() ? null : value;
    }

    @Nullable
    private static String first(@Nullable String... values) {
        for (String value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Nullable
    private static String join(String separator, @Nullable String... values) {
        List<String> parts = new ArrayList<>();
        for (String value : values) {
            if (value != null) {
                parts.add(value);
            }
        }
        return parts.isEmpty() ? null : String.join(separator, parts);
    }
}
