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
package io.contexa.autoconfigure.core;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.jpa.repository.config.JpaRepositoryConfigExtension;
import org.springframework.data.repository.config.AnnotationRepositoryConfigurationSource;
import org.springframework.data.repository.config.RepositoryConfigurationDelegate;

public class ContexaRepositoriesPostProcessor implements BeanDefinitionRegistryPostProcessor,
        EnvironmentAware, ResourceLoaderAware {

    private Environment environment;
    private ResourceLoader resourceLoader;

    public ContexaRepositoriesPostProcessor() {
    }

    public ContexaRepositoriesPostProcessor(Environment environment, ResourceLoader resourceLoader) {
        this.environment = environment;
        this.resourceLoader = resourceLoader;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setResourceLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        AnnotationMetadata metadata = AnnotationMetadata.introspect(ContexaRepositoriesConfiguration.class);
        AnnotationRepositoryConfigurationSource source = new AnnotationRepositoryConfigurationSource(
                metadata, EnableJpaRepositories.class, this.resourceLoader, this.environment, registry, null);
        RepositoryConfigurationDelegate delegate = new RepositoryConfigurationDelegate(source, this.resourceLoader, this.environment);
        delegate.registerRepositoriesIn(registry, new JpaRepositoryConfigExtension());
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // No-op
    }

    @EnableJpaRepositories(
            basePackages = {
                    "io.contexa.contexacommon.repository",
                    "io.contexa.contexacore.repository",
                    "io.contexa.contexaiam.repository"
            },
            entityManagerFactoryRef = "contexaEntityManagerFactory",
            transactionManagerRef = "contexaTransactionManager"
    )
    private static class ContexaRepositoriesConfiguration {
    }
}
