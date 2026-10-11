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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * How a past record relates to the current request: the path template, the target the path names (the template's
 * variable values, such as {@code projectKey=GB-500}) and the action. The prompt, the canonical decision reasoning and
 * the sealed evidence all read this one computation, so a record is "the same resource" only when it acted on the
 * same target with the same action, never because the same protected method served it.
 */
public final class PastRecordRelevance {

    public static final String NO_DOCUMENTS = "NO_DOCUMENTS";
    public static final String UNKNOWN = "UNKNOWN";
    /** Every past record is the same action on the same target as the request. */
    public static final String SAME_RESOURCE = "SAME_RESOURCE";
    /** Every past record is the same action on another target. */
    public static final String SAME_ACTION_DIFFERENT_RESOURCE = "SAME_ACTION_DIFFERENT_RESOURCE";
    public static final String MIXED_OR_DIFFERENT_RESOURCE = "MIXED_OR_DIFFERENT_RESOURCE";

    public static final String YES = "yes";
    public static final String NO = "no";
    public static final String NOT_KNOWN = "unknown";

    private static final List<String> REQUEST_PATH_KEYS = List.of("requestPath", "requestUri", "fullPath");
    private static final List<String> RECORD_PATH_KEYS = List.of("requestPath", "resourcePath", "path");
    private static final List<String> RECORD_PATH_FAMILY_KEYS = List.of("pathFamily", "requestPathFamily");
    private static final Pattern PATH_TOKEN = Pattern.compile("(/[^\\s,;|\\]]+)");

    private PastRecordRelevance() {
    }

    public enum Relation {
        SAME_TARGET,
        SAME_ACTION_OTHER_TARGET,
        OTHER_ACTION,
        UNKNOWN
    }

    /**
     * One side of the comparison.
     *
     * @param path         the request path without its query, null when unknown
     * @param pathFamily   the path template ({@link SecuritySemanticNormalizer#pathFamilyOf})
     * @param target       the template's variable values ({@link BaselineViewCalculator#target}), null when the path
     *                     names none or cannot be matched to the template
     * @param actionFamily the action family, null when unknown
     * @param httpMethod   the HTTP method, null when unknown
     */
    public record Subject(@Nullable String path, @Nullable String pathFamily, @Nullable String target,
                          @Nullable ActionFamily actionFamily, @Nullable String httpMethod) {

        /** The current request, read from its event metadata; the first path of its description when no path is set. */
        public static Subject ofRequest(@Nullable Map<String, ?> metadata, @Nullable String description) {
            String path = firstText(metadata, REQUEST_PATH_KEYS);
            if (path == null) {
                path = pathToken(description);
            }
            String pathFamily = path == null ? null : SecuritySemanticNormalizer.pathFamilyOf(metadata, path);
            return of(path, pathFamily, ActionFamilyResolver.resolve(metadata).family(), metadata);
        }

        /** A past record, read from its stored metadata; the first path in its text is used when no path is stored. */
        public static Subject ofRecord(@Nullable Map<String, ?> metadata, @Nullable String text) {
            String path = firstText(metadata, RECORD_PATH_KEYS);
            if (path == null) {
                path = pathToken(text);
            }
            String pathFamily = firstText(metadata, RECORD_PATH_FAMILY_KEYS);
            if (pathFamily == null) {
                pathFamily = SecuritySemanticNormalizer.normalizePathFamily(path);
            }
            // A record keeps the action family resolved when it was stored; it is not inferred again from its method.
            return of(path, pathFamily, metadata == null ? null : ActionFamily.of(metadata.get("actionFamily")), metadata);
        }

        private static Subject of(@Nullable String path, @Nullable String pathFamily, @Nullable ActionFamily action,
                                  @Nullable Map<String, ?> metadata) {
            String plainPath = withoutQuery(path);
            return new Subject(
                    plainPath,
                    pathFamily,
                    BaselineViewCalculator.target(pathFamily, plainPath),
                    action == ActionFamily.UNKNOWN ? null : action,
                    firstText(metadata, List.of("httpMethod")));
        }
    }

    /** Whether the record acted on the request's target, whatever the action: yes, no or unknown. */
    public static String sameTarget(Subject request, Subject record) {
        if (request.path() == null || record.path() == null) {
            return NOT_KNOWN;
        }
        if (samePath(request.path(), record.path())) {
            return YES;
        }
        if (request.target() == null || record.target() == null) {
            return NOT_KNOWN;
        }
        return bindings(request.target()).equals(bindings(record.target())) ? YES : NO;
    }

    public static Relation relation(Subject request, Subject record) {
        if (request.pathFamily() == null || record.pathFamily() == null) {
            return Relation.UNKNOWN;
        }
        if (!request.pathFamily().equals(record.pathFamily()) || differentAction(request, record)) {
            return Relation.OTHER_ACTION;
        }
        return switch (sameTarget(request, record)) {
            case YES -> Relation.SAME_TARGET;
            case NO -> Relation.SAME_ACTION_OTHER_TARGET;
            default -> Relation.UNKNOWN;
        };
    }

    /** The relevance of the past records as a whole, one of the constants of this class. */
    public static String relevance(Subject request, List<Subject> records) {
        if (records == null || records.isEmpty()) {
            return NO_DOCUMENTS;
        }
        if (request.path() == null) {
            return UNKNOWN;
        }
        Set<Relation> relations = records.stream()
                .map(record -> relation(request, record))
                .collect(Collectors.toSet());
        if (relations.size() == 1) {
            return switch (relations.iterator().next()) {
                case SAME_TARGET -> SAME_RESOURCE;
                case SAME_ACTION_OTHER_TARGET -> SAME_ACTION_DIFFERENT_RESOURCE;
                case UNKNOWN -> UNKNOWN;
                case OTHER_ACTION -> MIXED_OR_DIFFERENT_RESOURCE;
            };
        }
        return MIXED_OR_DIFFERENT_RESOURCE;
    }

    /** The first path written in a text, as a record's text names the request it remembers. */
    @Nullable
    public static String pathToken(@Nullable String text) {
        if (!StringUtils.hasText(text)) {
            return null;
        }
        Matcher matcher = PATH_TOKEN.matcher(text);
        return matcher.find() ? matcher.group(1).trim() : null;
    }

    private static boolean differentAction(Subject request, Subject record) {
        // Actions differ only when both sides name one; the family decides first, then the HTTP method.
        if (request.actionFamily() != null && record.actionFamily() != null) {
            return request.actionFamily() != record.actionFamily();
        }
        if (request.httpMethod() != null && record.httpMethod() != null) {
            return !request.httpMethod().equalsIgnoreCase(record.httpMethod());
        }
        return false;
    }

    private static boolean samePath(String left, String right) {
        return trimSlash(left).equals(trimSlash(right));
    }

    private static String trimSlash(String path) {
        String trimmed = path.trim();
        return trimmed.length() > 1 && trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private static Set<String> bindings(String target) {
        return Arrays.stream(target.split(",")).map(String::trim).filter(StringUtils::hasText).collect(Collectors.toSet());
    }

    @Nullable
    private static String withoutQuery(@Nullable String path) {
        if (path == null) {
            return null;
        }
        int query = path.indexOf('?');
        String plain = (query >= 0 ? path.substring(0, query) : path).trim();
        return plain.isEmpty() ? null : plain;
    }

    @Nullable
    private static String firstText(@Nullable Map<String, ?> metadata, List<String> keys) {
        if (metadata == null) {
            return null;
        }
        for (String key : keys) {
            String value = text(metadata.get(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
