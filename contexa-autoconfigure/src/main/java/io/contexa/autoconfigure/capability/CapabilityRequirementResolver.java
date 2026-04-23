package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityMode;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityStatus;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityRequirement;
import io.contexa.contexacommon.autoconfigure.capability.ContexaCapability;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.core.env.Environment;
import org.springframework.util.ClassUtils;

import java.util.List;
import java.util.Optional;

public class CapabilityRequirementResolver {

    private final ContexaCapabilityProperties properties;
    private final Environment environment;
    private final ListableBeanFactory beanFactory;

    public CapabilityRequirementResolver(
            ContexaCapabilityProperties properties,
            Environment environment,
            ListableBeanFactory beanFactory) {
        this.properties = properties;
        this.environment = environment;
        this.beanFactory = beanFactory;
    }

    public CapabilityMode effectiveMode() {
        CapabilityMode configuredMode = properties.getMode();
        if (configuredMode != CapabilityMode.AUTO) {
            return configuredMode;
        }
        return isContexaOwnedApplication() ? CapabilityMode.FAIL_FAST : CapabilityMode.WARN;
    }

    public Optional<CapabilityCheckResult> visibleIssueForCurrentApplication(CapabilityCheckResult result) {
        if (!isAbnormal(result.status())) {
            return Optional.of(result);
        }
        CapabilityMode mode = effectiveMode();
        if (isContexaOwnedApplication()
                || mode == CapabilityMode.FAIL_FAST
                || mode == CapabilityMode.STRICT) {
            return Optional.of(result);
        }

        List<String> actionableMissingBeans = actionableMissingBeans(result);
        if (actionableMissingBeans.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(new CapabilityCheckResult(
                result.capability(),
                result.status(),
                result.required(),
                result.reason(),
                result.presentBeans(),
                actionableMissingBeans,
                actionableRecommendations(result.capability())));
    }

    public CapabilityRequirement requirement(ContexaCapability capability) {
        return properties.requiredOverride(capability)
                .map(required -> required
                        ? CapabilityRequirement.required(capability, "overridden by contexa.capability.required." + capability.propertyKey())
                        : CapabilityRequirement.optional(capability, "requirement disabled by contexa.capability.required." + capability.propertyKey()))
                .orElseGet(() -> defaultRequirement(capability));
    }

    private CapabilityRequirement defaultRequirement(ContexaCapability capability) {
        boolean contexaOwnedApplication = isContexaOwnedApplication();
        boolean platformConfigPresent = hasBean("io.contexa.contexaidentity.security.core.config.PlatformConfig");
        boolean autonomousEnabled = getBoolean("contexa.autonomous.enabled", true);
        boolean ragEnabled = getBoolean("contexa.rag.enabled", true);
        boolean enterpriseEnabled = getBoolean("contexa.enterprise.enabled", false);

        return switch (capability) {
            case LLM_RUNTIME -> activeWhen(capability,
                    contexaOwnedApplication || platformConfigPresent || autonomousEnabled,
                    contexaOwnedApplication || platformConfigPresent,
                    "LLM runtime participates in AI Native decision flow");
            case EMBEDDING_RUNTIME -> activeWhen(capability,
                    ragEnabled && classPresent("org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration"),
                    contexaOwnedApplication || environment.containsProperty("contexa.rag.enabled"),
                    "PgVector RAG requires an EmbeddingModel before VectorStore can be created");
            case RAG_VECTOR -> activeWhen(capability,
                    ragEnabled && (classPresent("org.springframework.ai.vectorstore.VectorStore")
                            || classPresent("org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration")),
                    contexaOwnedApplication || environment.containsProperty("contexa.rag.enabled"),
                    "RAG vector chain is enabled");
            case SECURITY_LEARNING -> activeWhen(capability,
                    autonomousEnabled || hasBean("io.contexa.contexacore.autonomous.service.SecurityLearningService"),
                    contexaOwnedApplication || platformConfigPresent,
                    "security learning is part of post-authentication monitoring");
            case AUTONOMOUS_DECISION -> activeWhen(capability,
                    autonomousEnabled || hasBean("io.contexa.contexacore.autonomous.SecurityPlaneAgent"),
                    contexaOwnedApplication || platformConfigPresent,
                    "autonomous decision plane is enabled");
            case BRIDGE -> activeWhen(capability,
                    platformConfigPresent || hasBean("io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter"),
                    platformConfigPresent,
                    "AI security bridge is active");
            case PQA_ENGINE -> activeWhen(capability,
                    enterpriseEnabled && classPresent("io.contexa.contexaiamenterprise.admin.verification.controller.PromptQualityVerificationApiController"),
                    contexaOwnedApplication && enterpriseEnabled,
                    "enterprise prompt quality assurance engine is available");
            case ENTERPRISE_SOAR -> activeWhen(capability,
                    enterpriseEnabled && classPresent("io.contexa.contexacoreenterprise.soar.retriever.SoarContextRetriever"),
                    contexaOwnedApplication && enterpriseEnabled,
                    "enterprise SOAR is available");
            case ENTERPRISE_MCP -> activeWhen(capability,
                    enterpriseEnabled && classPresent("io.contexa.contexamcp.config.ContexaMcpServerConfiguration"),
                    false,
                    "enterprise MCP module is available");
            case ENTERPRISE_DASHBOARD -> activeWhen(capability,
                    enterpriseEnabled && classPresent("io.contexa.contexacoreenterprise.dashboard.metrics.vectorstore.VectorStoreMetricsImpl"),
                    contexaOwnedApplication && enterpriseEnabled,
                    "enterprise dashboard is available");
        };
    }

    private CapabilityRequirement activeWhen(
            ContexaCapability capability,
            boolean enabled,
            boolean required,
            String reason) {
        if (!enabled) {
            return CapabilityRequirement.disabled(capability, reason);
        }
        return required
                ? CapabilityRequirement.required(capability, reason)
                : CapabilityRequirement.optional(capability, reason);
    }

    public boolean isContexaOwnedApplication() {
        if (getBoolean("contexa.datasource.isolation.contexa-owned-application", false)) {
            return true;
        }
        String applicationName = environment.getProperty("spring.application.name", "");
        return applicationName.startsWith("contexa-");
    }

    private boolean isAbnormal(CapabilityStatus status) {
        return status == CapabilityStatus.DEGRADED
                || status == CapabilityStatus.INACTIVE_UNEXPECTED
                || status == CapabilityStatus.FAILED;
    }

    private List<String> actionableMissingBeans(CapabilityCheckResult result) {
        return switch (result.capability()) {
            case LLM_RUNTIME -> filterMissingBeans(result, List.of(
                    "org.springframework.ai.chat.model.ChatModel"));
            case EMBEDDING_RUNTIME -> filterMissingBeans(result, List.of(
                    "org.springframework.ai.embedding.EmbeddingModel"));
            case RAG_VECTOR -> filterMissingBeans(result, List.of(
                    "org.springframework.ai.vectorstore.VectorStore"));
            default -> List.of();
        };
    }

    private List<String> actionableRecommendations(ContexaCapability capability) {
        return switch (capability) {
            case LLM_RUNTIME -> List.of(
                    "Configure at least one Spring AI ChatModel provider for the application.");
            case EMBEDDING_RUNTIME -> List.of(
                    "Configure a Spring AI EmbeddingModel provider before enabling vector-backed retrieval.");
            case RAG_VECTOR -> List.of(
                    "Verify the Spring AI PgVector runtime, datasource, and VectorStore prerequisites are configured.");
            default -> List.of();
        };
    }

    private List<String> filterMissingBeans(CapabilityCheckResult result, List<String> beanTypes) {
        return beanTypes.stream()
                .filter(result.missingBeans()::contains)
                .toList();
    }

    private boolean getBoolean(String key, boolean defaultValue) {
        return environment.getProperty(key, Boolean.class, defaultValue);
    }

    private boolean classPresent(String className) {
        return ClassUtils.isPresent(className, getClass().getClassLoader());
    }

    private boolean hasBean(String className) {
        if (!classPresent(className)) {
            return false;
        }
        try {
            Class<?> beanType = ClassUtils.forName(className, getClass().getClassLoader());
            return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, beanType, true, false).length > 0;
        } catch (ClassNotFoundException ex) {
            return false;
        }
    }
}
