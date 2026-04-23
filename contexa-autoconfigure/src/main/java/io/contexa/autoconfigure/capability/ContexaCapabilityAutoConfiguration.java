package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityContributor;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.List;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration",
        "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration",
        "io.contexa.autoconfigure.core.rag.CoreRAGAutoConfiguration",
        "io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration",
        "io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration"
})
@EnableConfigurationProperties(ContexaCapabilityProperties.class)
public class ContexaCapabilityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CapabilityRequirementResolver capabilityRequirementResolver(
            ContexaCapabilityProperties properties,
            Environment environment,
            ListableBeanFactory beanFactory) {
        return new CapabilityRequirementResolver(properties, environment, beanFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public CoreCapabilityContributor coreCapabilityContributor(
            ListableBeanFactory beanFactory,
            CapabilityRequirementResolver requirementResolver) {
        return new CoreCapabilityContributor(beanFactory, requirementResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public ContexaCapabilityRegistry contexaCapabilityRegistry(
            ObjectProvider<CapabilityContributor> contributors) {
        List<CapabilityContributor> contributorList = contributors.orderedStream().toList();
        return new ContexaCapabilityRegistry(contributorList);
    }

    @Bean
    @ConditionalOnMissingBean
    public ContexaAutoConfigurationIntegrityVerifier contexaAutoConfigurationIntegrityVerifier(
            ContexaCapabilityRegistry registry,
            CapabilityRequirementResolver requirementResolver) {
        return new ContexaAutoConfigurationIntegrityVerifier(registry, requirementResolver);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
    @ConditionalOnProperty(prefix = "contexa.capability", name = "expose-diagnostics-endpoint", havingValue = "true", matchIfMissing = true)
    static class EndpointConfiguration {

        @Bean
        @ConditionalOnMissingBean
        CapabilityDiagnosticsEndpoint capabilityDiagnosticsEndpoint(
                ContexaCapabilityRegistry registry,
                CapabilityRequirementResolver requirementResolver) {
            return new CapabilityDiagnosticsEndpoint(registry, requirementResolver);
        }
    }
}
