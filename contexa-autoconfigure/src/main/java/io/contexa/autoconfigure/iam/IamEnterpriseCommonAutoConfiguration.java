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
package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.capture.PromptEvidenceMetadataProvider;
import io.contexa.contexacore.verification.capture.SealedEvidenceLayer1CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.verification.service.quality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexaiam.admin.verification.service.quality.runtime.JdbcPromptRuntimeGovernanceRuleProvider;
import io.contexa.contexaiam.security.xacml.pep.ProtectableResourceCertificationGate;
import io.contexa.contexaiam.admin.verification.service.resource.EnterpriseProtectableResourceCertificationGate;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateService;
import io.contexa.contexaiam.admin.verification.service.resource.PromptQualityCertificateAuditService;
import io.contexa.contexacore.repository.ProtectableResourceRegistryRepository;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true")
public class IamEnterpriseCommonAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SealedEvidencePromptTraceStore sealedEvidencePromptTraceStore(
            ObjectProvider<PromptEvidenceMetadataProvider> metadataProviderProvider) {
        return new SealedEvidencePromptTraceStore(metadataProviderProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public SealedEvidencePromptCaptureAspect sealedEvidencePromptCaptureAspect(
            SealedEvidencePromptTraceStore sealedEvidencePromptTraceStore) {
        return new SealedEvidencePromptCaptureAspect(sealedEvidencePromptTraceStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public SealedEvidenceLayer1CompletionAspect sealedEvidenceLayer1CompletionAspect(
            SealedEvidencePromptTraceStore sealedEvidencePromptTraceStore) {
        return new SealedEvidenceLayer1CompletionAspect(sealedEvidencePromptTraceStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptGovernanceDescriptorResolver promptGovernanceDescriptorResolver(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper
    ) {
        return new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public PromptRuntimeGovernanceRuleProvider promptRuntimeGovernanceRuleProvider(
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper
    ) {
        return new JdbcPromptRuntimeGovernanceRuleProvider(jdbcTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public EnterpriseProtectableResourceCertificationGate enterpriseProtectableResourceCertificationGate(
            PromptQualityCertificateService promptQualityCertificateService,
            PromptQualityCertificateAuditService auditService,
            ProtectableResourceRegistryRepository registryRepository,
            @Value("${contexa.zerotrust.certificate.enforcement-mode:BLOCK}") String enforcementMode
    ) {
        return new EnterpriseProtectableResourceCertificationGate(
                promptQualityCertificateService,
                auditService,
                registryRepository,
                enforcementMode
        );
    }

    @Bean(name = "protectableCertificationGateBinder")
    @ConditionalOnMissingBean(name = "protectableCertificationGateBinder")
    public BeanPostProcessor protectableCertificationGateBinder(
            ObjectProvider<EnterpriseProtectableResourceCertificationGate> certificationGateProvider
    ) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
                if (bean instanceof AuthorizationManagerMethodInterceptor interceptor) {
                    EnterpriseProtectableResourceCertificationGate certificationGate =
                            certificationGateProvider.getIfAvailable();
                    if (certificationGate != null) {
                        interceptor.setProtectableResourceCertificationGate(certificationGate);
                    }
                }
                return bean;
            }
        };
    }
}
