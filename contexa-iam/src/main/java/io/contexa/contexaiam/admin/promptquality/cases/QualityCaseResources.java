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
package io.contexa.contexaiam.admin.promptquality.cases;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.monitoring.ai.DecisionConsoleColumns;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseResource;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * The resource and resource class of a labelled case (quality P46), worked out from its input as the decision rows of
 * the operation are: the class is the one the decision row of the same input gets
 * ({@link DecisionConsoleColumns#resourceClass(String, Object)}: the class the canonical context gives the resource,
 * else SENSITIVE for a request that marks its resource sensitive), in the vocabulary of the resource classes
 * ({@link SecuritySemanticNormalizer#normalizeResourceClass}); the operation keeps that class with every decision and
 * hour ({@code resource_class}), so the cases of a class stand beside the decisions of the class. The resource is the
 * one the decision row keeps ({@code resource_id}: the request's {@code resourceId}), else the protected resource the
 * request declared ({@code protectableResourceId}), with the protected resource's method and URL template. Nothing is
 * stored: the input of a case does not change once kept, so its class is read from it where it is needed, for the
 * cases kept before as for the new.
 */
public final class QualityCaseResources {

    /**
     * The resource classes every view shows, also when no case and no decision has them, in the order of their
     * sensitivity: the values {@link SecuritySemanticNormalizer#normalizeResourceClass} gives.
     */
    public static final List<String> CLASSES = List.of("CRITICAL", "SENSITIVE", "NORMAL", "PUBLIC");

    private QualityCaseResources() {
    }

    /** The resource and class of the case. */
    public static QualityCaseResource of(QualityCase item) {
        return of(item.input());
    }

    /** The resource and class of the input. */
    public static QualityCaseResource of(QualityCaseInput input) {
        JsonNode facts = input.requestFacts();
        // The class as the context holds it, untrimmed: the decision row reads the same value.
        JsonNode declaredNode = input.canonicalContext().path("resource").path("resourceClass");
        String declared = declaredNode.isValueNode() && !declaredNode.isNull() ? declaredNode.asText() : null;
        JsonNode sensitive = facts.path("isSensitiveResource");
        Object flag = sensitive.isBoolean() ? Boolean.valueOf(sensitive.booleanValue())
                : sensitive.isTextual() ? sensitive.textValue() : null;
        String resourceClass = SecuritySemanticNormalizer.normalizeResourceClass(
                DecisionConsoleColumns.resourceClass(declared, flag));
        String resource = first(facts, "resourceId", "protectableResourceId");
        String method = first(facts, "protectableHttpMethod", "httpMethod");
        return new QualityCaseResource(resourceClass, resource, method, text(facts.path("protectableResourceUrl")));
    }

    /**
     * The class an hour of the operation keeps ({@code resource_class}, empty for none) in the groups of the cases: the
     * same vocabulary, the unclassified under {@link QualityCaseResource#UNCLASSIFIED}.
     */
    public static String groupOfDecisions(@Nullable String resourceClass) {
        String normalized = resourceClass == null || resourceClass.isBlank() ? null
                : SecuritySemanticNormalizer.normalizeResourceClass(resourceClass);
        return normalized != null ? normalized : QualityCaseResource.UNCLASSIFIED;
    }

    @Nullable
    private static String first(JsonNode facts, String... fields) {
        for (String field : fields) {
            String value = text(facts.path(field));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Nullable
    private static String text(JsonNode node) {
        if (node == null || !node.isValueNode() || node.isNull()) {
            return null;
        }
        String value = node.asText().trim();
        return value.isEmpty() ? null : value;
    }
}
