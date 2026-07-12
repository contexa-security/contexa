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
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.scanner.MethodResourceScanner;
import io.contexa.contexaiam.resource.scanner.MvcResourceScanner;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.resource.service.ResourceRegistryServiceImpl;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

import java.util.List;

@AutoConfiguration
public class IamResourceAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ResourceRegistryService resourceRegistryService(
            List<ResourceScanner> scanners,
            ManagedResourceRepository managedResourceRepository,
            PermissionCatalogService permissionCatalogService,
            AICoreOperations aiNativeProcessor,
            AutoConditionTemplateService autoConditionTemplateService,
            PolicyRepository policyRepository,
            IamAdminProperties iamAdminProperties,
            MessageSource messageSource) {
        return new ResourceRegistryServiceImpl(
                scanners, managedResourceRepository, permissionCatalogService,
                aiNativeProcessor, autoConditionTemplateService, policyRepository,
                iamAdminProperties, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionCompatibilityService conditionCompatibilityService() {
        return new ConditionCompatibilityService();
    }

    @Bean
    @ConditionalOnMissingBean
    public AutoConditionTemplateService autoConditionTemplateService(
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            AICoreOperations aiNativeProcessor) {
        return new AutoConditionTemplateService(
                conditionTemplateRepository, managedResourceRepository, aiNativeProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public MvcResourceScanner mvcResourceScanner(
            ApplicationContext applicationContext,
            IamAdminProperties iamAdminProperties,
            ObjectProvider<SystemRuntimeSettingsService> runtimeSettingsServiceProvider) {
        return new MvcResourceScanner(applicationContext, iamAdminProperties, runtimeSettingsServiceProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public MethodResourceScanner methodResourceScanner(
            ApplicationContext applicationContext,
            ObjectMapper objectMapper,
            ObjectProvider<SystemRuntimeSettingsService> runtimeSettingsServiceProvider) {
        return new MethodResourceScanner(applicationContext, objectMapper,
                runtimeSettingsServiceProvider.getIfAvailable());
    }
}