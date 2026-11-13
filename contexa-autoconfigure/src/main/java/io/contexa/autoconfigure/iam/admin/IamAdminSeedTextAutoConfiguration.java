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
package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.i18n.SeedTextDialect;
import io.contexa.contexaiam.admin.web.i18n.SeedTextResponseAdvice;
import io.contexa.contexaiam.admin.web.i18n.SeedTexts;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;

/**
 * The seed texts of the console in the language of the page (IAM-D31): the pages the server writes, through a
 * Thymeleaf post-processor, and the lists the access center and the policy center draw from their answers.
 */
@AutoConfiguration
public class IamAdminSeedTextAutoConfiguration {

    @Bean(name = "contexaSeedTexts")
    @ConditionalOnMissingBean
    public SeedTexts contexaSeedTexts(ResourceLoader resourceLoader) {
        return SeedTexts.load(ResourcePatternUtils.getResourcePatternResolver(resourceLoader));
    }

    @Bean(name = "contexaSeedTextResponseAdvice")
    @ConditionalOnMissingBean
    public SeedTextResponseAdvice contexaSeedTextResponseAdvice(SeedTexts contexaSeedTexts,
            @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper) {
        return new SeedTextResponseAdvice(contexaSeedTexts,
                objectMapper.getIfAvailable(() -> new ObjectMapper().findAndRegisterModules()));
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.thymeleaf.spring6.SpringTemplateEngine")
    static class SeedTextTemplates {

        @Bean(name = "contexaSeedTextDialect")
        @ConditionalOnMissingBean
        SeedTextDialect contexaSeedTextDialect() {
            return new SeedTextDialect();
        }
    }
}
