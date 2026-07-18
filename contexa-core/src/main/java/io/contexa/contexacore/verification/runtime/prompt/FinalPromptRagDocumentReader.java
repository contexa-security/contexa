package io.contexa.contexacore.verification.runtime.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FinalPromptRagDocumentReader {

    private FinalPromptRagDocumentReader() {
    }

    static List<Object> documents(FinalPromptSnapshot prompt, FinalPromptEvidenceContext evidence) {
        List<Object> documents = new ArrayList<>();
        if (prompt != null) {
            prompt.fields().stream()
                    .filter(field -> field != null && StringUtils.hasText(field.label()))
                    .filter(field -> field.label().trim().toLowerCase(Locale.ROOT).startsWith("ragdocument"))
                    .map(FinalPromptField::value)
                    .filter(StringUtils::hasText)
                    .forEach(documents::add);
        }
        if (documents.isEmpty() && evidence != null
                && evidence.ragResults() != null && !evidence.ragResults().isEmpty()) {
            documents.addAll(documents(FinalPromptDisplayValues.firstPresent(
                    evidence.ragResults(),
                    "ragDocument", "ragDocuments", "documents", "relatedDocuments",
                    "retrievedDocuments", "authorizedDocuments")));
        }
        return documents;
    }

    static List<Object> documents(Object value) {
        if (value == null) {
            return List.of();
        }
        if (value instanceof Iterable<?> iterable) {
            List<Object> documents = new ArrayList<>();
            for (Object item : iterable) {
                if (item != null) {
                    documents.add(item);
                }
            }
            return documents;
        }
        return List.of(value);
    }

    static String fieldValue(Object document, String key) {
        if (document == null || !StringUtils.hasText(key)) {
            return "";
        }
        if (document instanceof Map<?, ?> map) {
            Object value = firstPresentFromObjectMap(map, keyAliases(key));
            return FinalPromptDisplayValues.customerRuntimeValue(value);
        }
        String text = FinalPromptDisplayValues.customerRuntimeValue(document);
        return StringUtils.hasText(text) ? textValue(text, key) : "";
    }

    static String firstPromptValue(FinalPromptSnapshot prompt, String... labels) {
        if (prompt == null || labels == null) {
            return "";
        }
        for (String label : labels) {
            String value = prompt.firstValue(label);
            if (StringUtils.hasText(value) && !"N/A".equalsIgnoreCase(value.trim())) {
                return value.trim();
            }
        }
        return "";
    }

    static boolean resourceMatchesRequest(
            Object document,
            String requestResourceId,
            String requestPath,
            String requestResourceFamily,
            String requestPathFamily) {
        String documentExactResource = FinalPromptDisplayValues.firstNonBlank(
                fieldValue(document, "resourceId"),
                fieldValue(document, "requestPath"));
        if (sameValue(documentExactResource, requestResourceId)
                || sameValue(documentExactResource, requestPath)) {
            return true;
        }
        String documentResourceFamily = FinalPromptDisplayValues.firstNonBlank(
                fieldValue(document, "resourceFamily"),
                fieldValue(document, "resource"));
        if (sameValue(documentResourceFamily, requestResourceFamily)) {
            return true;
        }
        String documentPathFamily = fieldValue(document, "pathFamily");
        return sameValue(documentPathFamily, requestPathFamily)
                || pathFamilyCoversPath(documentPathFamily, requestPath)
                || pathFamilyCoversPath(requestPathFamily, documentExactResource);
    }

    static boolean sameValue(String left, String right) {
        String normalizedLeft = normalizeScopeValue(left);
        String normalizedRight = normalizeScopeValue(right);
        return StringUtils.hasText(normalizedLeft) && normalizedLeft.equals(normalizedRight);
    }

    static boolean authorizationPresent(Object document) {
        String authorization = FinalPromptDisplayValues.firstNonBlank(
                fieldValue(document, "authorization"),
                fieldValue(document, "authorized"),
                fieldValue(document, "allowed"));
        if (!StringUtils.hasText(authorization)) {
            return false;
        }
        String normalized = authorization.toLowerCase(Locale.ROOT);
        return (normalized.contains("allow") || normalized.contains("authorized") || normalized.contains("true"))
                && !normalized.contains("deny")
                && !normalized.contains("blocked")
                && !normalized.contains("unauthorized");
    }

    private static String[] keyAliases(String key) {
        String normalized = key == null ? "" : key.trim();
        return switch (normalized.toLowerCase(Locale.ROOT)) {
            case "userid" -> new String[] { "userId", "user", "subjectId", "userScope" };
            case "tenantid" -> new String[] { "tenantId", "tenant" };
            case "organizationid" -> new String[] { "organizationId", "organization", "orgId", "org" };
            case "resourceid" -> new String[] { "resourceId", "resourceScope" };
            case "resource" -> new String[] { "resource" };
            case "resourcefamily" -> new String[] {
                    "resourceFamily", "currentResourceFamily", "resourceType", "resourceCategory", "resource"
            };
            case "requestpath" -> new String[] { "requestPath", "path" };
            case "pathfamily" -> new String[] { "pathFamily", "requestPathFamily" };
            case "retrievalpurpose" -> new String[] { "retrievalPurpose", "purpose" };
            case "accessscope" -> new String[] { "accessScope", "scope", "permissionScope" };
            case "authorization" -> new String[] {
                    "authorization", "authorizationDecision", "authorized", "allowed", "auth"
            };
            default -> new String[] { normalized, FinalPromptDisplayValues.lowerFirst(normalized) };
        };
    }

    private static Object firstPresentFromObjectMap(Map<?, ?> values, String... keys) {
        if (values == null || keys == null) {
            return "";
        }
        for (String key : keys) {
            if (!StringUtils.hasText(key)) {
                continue;
            }
            Object value = values.get(key);
            if (value == null) {
                value = caseInsensitiveValue(values, key);
            }
            if (value != null && StringUtils.hasText(String.valueOf(value))) {
                return value;
            }
        }
        return "";
    }

    private static Object caseInsensitiveValue(Map<?, ?> values, String key) {
        for (Map.Entry<?, ?> entry : values.entrySet()) {
            if (entry.getKey() != null && key.equalsIgnoreCase(String.valueOf(entry.getKey()))) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static String textValue(String text, String key) {
        if (!StringUtils.hasText(text) || !StringUtils.hasText(key)) {
            return "";
        }
        for (String alias : keyAliases(key.trim())) {
            String value = namedTokenValue(text, alias);
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return "";
    }

    private static String namedTokenValue(String text, String key) {
        if (!StringUtils.hasText(text) || !StringUtils.hasText(key)) {
            return "";
        }
        String pattern = "(?i)(?:^|[\\[\\],|\\s])" + Pattern.quote(key.trim())
                + "\\s*(?:=|:|value\\s+is|값은)\\s*([^,|\\]\\n\\r]+)";
        Matcher matcher = Pattern.compile(pattern).matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private static boolean pathFamilyCoversPath(String family, String path) {
        String normalizedFamily = normalizeScopeValue(family);
        String normalizedPath = normalizeScopeValue(path);
        if (!StringUtils.hasText(normalizedFamily) || !StringUtils.hasText(normalizedPath)) {
            return false;
        }
        if (!normalizedFamily.endsWith("/*")) {
            return normalizedFamily.equals(normalizedPath);
        }
        String prefix = normalizedFamily.substring(0, normalizedFamily.length() - 1);
        return normalizedPath.startsWith(prefix);
    }

    private static String normalizeScopeValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replaceAll("^/+", "")
                .replaceAll("/+$", "")
                .toLowerCase(Locale.ROOT);
    }
}