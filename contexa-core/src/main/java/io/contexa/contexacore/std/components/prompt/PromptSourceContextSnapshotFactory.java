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
package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import org.springframework.ai.document.Document;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public final class PromptSourceContextSnapshotFactory {

    private static final int MAX_DEPTH = 12;
    private static final int MAX_FIELD_COUNT = 20_000;

    private PromptSourceContextSnapshotFactory() {
    }

    public static PromptSourceContextSnapshot capture(SecurityDecisionContext context) {
        if (context == null) {
            return new PromptSourceContextSnapshot(List.of(), 0, 0, 0);
        }
        CaptureState state = new CaptureState();
        SecurityEvent event = context.getSecurityEvent();
        if (event != null) {
            captureAny(state, "securityEvent", event, 0);
        }
        captureAny(state, "sessionContext", context.getSessionContext(), 0);
        captureAny(state, "behaviorAnalysis", context.getBehaviorAnalysis(), 0);
        captureDocuments(state, "relatedDocuments", context.getRelatedDocuments());
        int failureCount = state.depthLimitCount.get() + state.cycleCount.get() + state.errorCount.get();
        return new PromptSourceContextSnapshot(
                List.copyOf(state.fields),
                state.depthLimitCount.get(),
                state.cycleCount.get(),
                state.errorCount.get(),
                failureCount == 0,
                failureCount);
    }

    private static void captureDocuments(CaptureState state, String path, List<Document> documents) {
        if (documents == null) {
            captureScalar(state, path, null);
            return;
        }
        captureScalar(state, path + ".size", documents.size());
        for (int i = 0; i < documents.size(); i++) {
            Document document = documents.get(i);
            if (document == null) {
                captureScalar(state, path + "[" + i + "]", null);
                continue;
            }
            captureScalar(state, path + "[" + i + "].id", document.getId());
            captureScalar(state, path + "[" + i + "].text", document.getText());
            captureAny(state, path + "[" + i + "].metadata", document.getMetadata(), 0);
        }
    }

    private static void captureAny(CaptureState state, String path, Object value, int depth) {
        if (state.fields.size() >= MAX_FIELD_COUNT) {
            state.depthLimitCount.incrementAndGet();
            return;
        }
        if (value == null || isScalar(value)) {
            captureScalar(state, path, value);
            return;
        }
        if (depth >= MAX_DEPTH) {
            state.depthLimitCount.incrementAndGet();
            captureScalar(state, path + ".__depthLimit__", value.getClass().getName());
            return;
        }
        if (state.visited.containsKey(value)) {
            state.cycleCount.incrementAndGet();
            captureScalar(state, path + ".__cycle__", value.getClass().getName());
            return;
        }
        state.visited.put(value, Boolean.TRUE);
        try {
            if (value instanceof Map<?, ?> map) {
                captureScalar(state, path + ".size", map.size());
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    String key = String.valueOf(entry.getKey());
                    if (isGeneratedPromptTelemetryKey(key)) {
                        continue;
                    }
                    captureAny(state, path + "." + safePath(key), entry.getValue(), depth + 1);
                }
                return;
            }
            if (value instanceof Iterable<?> iterable) {
                int index = 0;
                for (Object item : iterable) {
                    captureAny(state, path + "[" + index + "]", item, depth + 1);
                    index++;
                }
                captureScalar(state, path + ".size", index);
                return;
            }
            if (value.getClass().isArray()) {
                int length = Array.getLength(value);
                captureScalar(state, path + ".size", length);
                for (int i = 0; i < length; i++) {
                    captureAny(state, path + "[" + i + "]", Array.get(value, i), depth + 1);
                }
                return;
            }
            if (!isProjectObject(value)) {
                captureScalar(state, path, value);
                return;
            }
            captureObjectFields(state, path, value, depth);
        }
        catch (RuntimeException ex) {
            state.errorCount.incrementAndGet();
            captureScalar(state, path + ".__error__", ex.getClass().getSimpleName());
        }
        finally {
            state.visited.remove(value);
        }
    }

    private static void captureObjectFields(CaptureState state, String path, Object bean, int depth) {
        List<Field> fields = declaredFields(bean.getClass());
        if (fields.isEmpty()) {
            captureScalar(state, path, bean);
            return;
        }
        captureScalar(state, path + ".__type__", bean.getClass().getName());
        for (Field field : fields) {
            if (skipField(field)) {
                continue;
            }
            String childPath = path + "." + safePath(field.getName());
            try {
                field.setAccessible(true);
                captureAny(state, childPath, field.get(bean), depth + 1);
            }
            catch (ReflectiveOperationException | RuntimeException ex) {
                state.errorCount.incrementAndGet();
                captureScalar(state, childPath + ".__error__", ex.getClass().getSimpleName());
            }
        }
    }

    private static List<Field> declaredFields(Class<?> type) {
        List<Field> fields = new ArrayList<>();
        Class<?> current = type;
        while (current != null && current != Object.class) {
            fields.addAll(List.of(current.getDeclaredFields()));
            current = current.getSuperclass();
        }
        return fields;
    }

    private static boolean skipField(Field field) {
        int modifiers = field.getModifiers();
        return field.isSynthetic()
                || Modifier.isStatic(modifiers)
                || Modifier.isTransient(modifiers)
                || field.getName().startsWith("this$");
    }

    private static void captureScalar(CaptureState state, String path, Object value) {
        if (state.fields.size() >= MAX_FIELD_COUNT) {
            state.depthLimitCount.incrementAndGet();
            return;
        }
        String valueText = normalizeValue(value);
        state.fields.add(new PromptSourceContextFieldSnapshot(
                path,
                sourceType(path),
                value == null ? "null" : value.getClass().getName(),
                PromptGovernanceSupport.sha256(valueText),
                valueText.length(),
                valueText));
    }

    private static boolean isScalar(Object value) {
        return value instanceof CharSequence
                || value instanceof Number
                || value instanceof Boolean
                || value instanceof Enum<?>
                || value instanceof TemporalAccessor
                || value instanceof Character;
    }

    private static boolean isProjectObject(Object value) {
        Package objectPackage = value.getClass().getPackage();
        String packageName = objectPackage != null ? objectPackage.getName() : "";
        return packageName.startsWith("io.contexa.");
    }

    private static String normalizeValue(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof Enum<?> enumValue) {
            return enumValue.name();
        }
        return String.valueOf(value);
    }

    private static String safePath(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.replaceAll("[^A-Za-z0-9_.-]+", "_");
    }

    private static String sourceType(String path) {
        if (path.startsWith("securityEvent.metadata.sealedEvidence.canonicalContext")) {
            return "CANONICAL_CONTEXT";
        }
        if (path.startsWith("securityEvent.metadata")) {
            return "SECURITY_EVENT_METADATA";
        }
        if (path.startsWith("securityEvent")) {
            return "SECURITY_EVENT";
        }
        if (path.startsWith("sessionContext")) {
            return "SESSION_CONTEXT";
        }
        if (path.startsWith("behaviorAnalysis")) {
            return "BEHAVIOR_ANALYSIS";
        }
        if (path.startsWith("relatedDocuments")) {
            return "RAG_DOCUMENT";
        }
        return "SOURCE_CONTEXT";
    }

    private static boolean isGeneratedPromptTelemetryKey(String key) {
        return PromptRuntimeTelemetrySupport.runtimeTelemetryKeys().contains(key)
                || "systemPrompt".equals(key)
                || "userPrompt".equals(key)
                || "rawSystemPrompt".equals(key)
                || "rawUserPrompt".equals(key)
                || key.startsWith("promptSourceContext")
                || key.startsWith("promptRawUserField")
                || key.startsWith("promptFinalUserField")
                || key.startsWith("promptUserField")
                || key.startsWith("promptFieldState")
                || "promptSourceContextLedger".equals(key)
                || "promptRawUserFieldLedger".equals(key)
                || "promptFinalUserFieldLedger".equals(key)
                || "promptUserFieldDiffLedger".equals(key);
    }

    private static final class CaptureState {
        private final List<PromptSourceContextFieldSnapshot> fields = new ArrayList<>();
        private final IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
        private final AtomicInteger depthLimitCount = new AtomicInteger();
        private final AtomicInteger cycleCount = new AtomicInteger();
        private final AtomicInteger errorCount = new AtomicInteger();
    }
}
