package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;

import java.util.List;

public final class PolicyBuilderDtos {

    private PolicyBuilderDtos() {
    }

    public static final class PolicyBuilderResourceContext {

        private final String resourceIdentifier;
        private final String resourceType;
        private final String friendlyName;
        private final String description;
        private final Object parameterTypes;
        private final String returnType;
        private final String returnObjectType;
        private final Boolean isDirectAccess;

        private PolicyBuilderResourceContext(
                String resourceIdentifier,
                String resourceType,
                String friendlyName,
                String description,
                Object parameterTypes,
                String returnType,
                String returnObjectType,
                Boolean isDirectAccess) {
            this.resourceIdentifier = resourceIdentifier;
            this.resourceType = resourceType;
            this.friendlyName = friendlyName;
            this.description = description;
            this.parameterTypes = parameterTypes;
            this.returnType = returnType;
            this.returnObjectType = returnObjectType;
            this.isDirectAccess = isDirectAccess;
        }

        public static PolicyBuilderResourceContext defaultContext() {
            return new PolicyBuilderResourceContext(
                    "GENERAL_POLICY",
                    "GENERAL",
                    "General Policy",
                    "A general policy not dependent on a specific resource",
                    "",
                    "void",
                    null,
                    true);
        }

        public static PolicyBuilderResourceContext fromResource(
                ManagedResource resource,
                Object parameterTypes) {
            return new PolicyBuilderResourceContext(
                    resource.getResourceIdentifier(),
                    null,
                    null,
                    null,
                    parameterTypes,
                    null,
                    resource.getReturnType(),
                    null);
        }

        public String getResourceIdentifier() {
            return resourceIdentifier;
        }

        public String getResourceType() {
            return resourceType;
        }

        public String getFriendlyName() {
            return friendlyName;
        }

        public String getDescription() {
            return description;
        }

        public Object getParameterTypes() {
            return parameterTypes;
        }

        public String getReturnType() {
            return returnType;
        }

        public String getReturnObjectType() {
            return returnObjectType;
        }

        public Boolean getIsDirectAccess() {
            return isDirectAccess;
        }
    }

    public record PolicyBuilderConditionStatistics(
            int total,
            ConditionClassificationCounts byClassification,
            double averageComplexity,
            long requireApproval
    ) {
        public static PolicyBuilderConditionStatistics from(List<ConditionTemplate> conditions) {
            ConditionClassificationCounts byClassification = ConditionClassificationCounts.from(conditions);
            double averageComplexity = conditions.stream()
                    .mapToInt(condition -> condition.getComplexityScore() != null
                            ? condition.getComplexityScore()
                            : 1)
                    .average()
                    .orElse(0.0);
            long requireApproval = conditions.stream()
                    .mapToLong(condition -> Boolean.TRUE.equals(condition.getApprovalRequired()) ? 1 : 0)
                    .sum();

            return new PolicyBuilderConditionStatistics(
                    conditions.size(),
                    byClassification,
                    averageComplexity,
                    requireApproval);
        }
    }

    public static final class ConditionClassificationCounts {

        private final long universal;
        private final long contextDependent;
        private final long customComplex;

        private ConditionClassificationCounts(
                long universal,
                long contextDependent,
                long customComplex) {
            this.universal = universal;
            this.contextDependent = contextDependent;
            this.customComplex = customComplex;
        }

        public static ConditionClassificationCounts from(List<ConditionTemplate> conditions) {
            long universal = 0;
            long contextDependent = 0;
            long customComplex = 0;

            for (ConditionTemplate condition : conditions) {
                ConditionTemplate.ConditionClassification classification =
                        condition.getClassification() != null
                                ? condition.getClassification()
                                : ConditionTemplate.ConditionClassification.UNIVERSAL;
                switch (classification) {
                    case UNIVERSAL -> universal++;
                    case CONTEXT_DEPENDENT -> contextDependent++;
                    case CUSTOM_COMPLEX -> customComplex++;
                }
            }

            return new ConditionClassificationCounts(universal, contextDependent, customComplex);
        }

        public long getUNIVERSAL() {
            return universal;
        }

        public long getCONTEXT_DEPENDENT() {
            return contextDependent;
        }

        public long getCUSTOM_COMPLEX() {
            return customComplex;
        }
    }
}
