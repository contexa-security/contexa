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
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.jpa.repository.config.JpaRepositoryConfigExtension;
import org.springframework.data.repository.config.AnnotationRepositoryConfigurationSource;
import org.springframework.data.repository.config.RepositoryConfigurationDelegate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.stream.Stream;

public class ContexaRepositoriesPostProcessor implements BeanDefinitionRegistryPostProcessor,
        EnvironmentAware, ResourceLoaderAware {

    private static final String ENABLED_PROPERTY = "contexa.jpa.repositories.enabled";
    private static final String CONFLICT_MESSAGE = "Contexa repository packages must not be registered by the "
            + "application's @EnableJpaRepositories. Contexa repositories are bound to contexaEntityManagerFactory "
            + "and contexaTransactionManager by the Contexa auto-configuration.";
    private static final List<String> CONTEXA_REPOSITORY_PACKAGES = List.of(
            "io.contexa.contexacommon.repository",
            "io.contexa.contexacore.repository",
            "io.contexa.contexaiam.repository"
    );
    private static final List<String> OSS_OFFICIAL_REPOSITORY_PACKAGES = List.of(
            "io.contexa.contexacore.verification.evidence"
    );

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
        if (!repositoriesEnabled()) {
            return;
        }
        assertApplicationDidNotPreRegisterContexaRepositories(registry);

        AnnotationMetadata metadata = AnnotationMetadata.introspect(
                includeOssOfficialRepositories()
                        ? ContexaRepositoriesWithOfficialEvidenceConfiguration.class
                        : ContexaRepositoriesConfiguration.class);
        AnnotationRepositoryConfigurationSource source = new AnnotationRepositoryConfigurationSource(
                metadata, EnableJpaRepositories.class, this.resourceLoader, this.environment, registry, null);
        RepositoryConfigurationDelegate delegate = new RepositoryConfigurationDelegate(source, this.resourceLoader, this.environment);
        delegate.registerRepositoriesIn(registry, new JpaRepositoryConfigExtension());
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // No-op
    }

    private boolean repositoriesEnabled() {
        return environment == null || environment.getProperty(ENABLED_PROPERTY, Boolean.class, true);
    }

    private boolean includeOssOfficialRepositories() {
        return environment == null
                || !environment.getProperty("contexa.enterprise.enabled", Boolean.class, false);
    }

    private void assertApplicationDidNotPreRegisterContexaRepositories(BeanDefinitionRegistry registry) {
        for (String beanName : registry.getBeanDefinitionNames()) {
            BeanDefinition beanDefinition = registry.getBeanDefinition(beanName);
            String repositoryInterface = repositoryInterface(beanDefinition);
            if (isContexaRepository(repositoryInterface)) {
                throw new IllegalStateException(CONFLICT_MESSAGE + " Conflicting bean: " + beanName
                        + ", repositoryInterface=" + repositoryInterface);
            }
        }
    }

    private String repositoryInterface(BeanDefinition beanDefinition) {
        Object value = beanDefinition.getPropertyValues().get("repositoryInterface");
        if (value == null) {
            value = beanDefinition.getAttribute("repositoryInterface");
        }
        if (value != null) {
            return repositoryInterfaceName(value);
        }
        for (var holder : beanDefinition.getConstructorArgumentValues().getGenericArgumentValues()) {
            String repositoryInterface = repositoryInterfaceName(holder.getValue());
            if (StringUtils.hasText(repositoryInterface)) {
                return repositoryInterface;
            }
        }
        for (var holder : beanDefinition.getConstructorArgumentValues().getIndexedArgumentValues().values()) {
            String repositoryInterface = repositoryInterfaceName(holder.getValue());
            if (StringUtils.hasText(repositoryInterface)) {
                return repositoryInterface;
            }
        }
        return null;
    }

    private String repositoryInterfaceName(Object value) {
        if (value instanceof Class<?> repositoryInterface) {
            return repositoryInterface.getName();
        }
        return value == null ? null : value.toString();
    }

    private boolean isContexaRepository(String repositoryInterface) {
        if (!StringUtils.hasText(repositoryInterface)) {
            return false;
        }
        String normalized = repositoryInterface.replace("class ", "").trim();
        return contexaRepositoryPackages().stream()
                .anyMatch(repositoryPackage -> normalized.startsWith(repositoryPackage + "."));
    }

    private List<String> contexaRepositoryPackages() {
        if (!includeOssOfficialRepositories()) {
            return CONTEXA_REPOSITORY_PACKAGES;
        }
        return Stream.concat(
                        CONTEXA_REPOSITORY_PACKAGES.stream(),
                        OSS_OFFICIAL_REPOSITORY_PACKAGES.stream())
                .toList();
    }

    @EnableJpaRepositories(
            basePackages = {
                    "io.contexa.contexacommon.repository",
                    "io.contexa.contexacore.repository",
                    "io.contexa.contexaiam.repository"
            },
            entityManagerFactoryRef = "contexaEntityManagerFactory",
            transactionManagerRef = "contexaTransactionManager",
            nameGenerator = ContexaRepositoryBeanNameGenerator.class
    )
    private static class ContexaRepositoriesConfiguration {
    }

    @EnableJpaRepositories(
            basePackages = {
                    "io.contexa.contexacommon.repository",
                    "io.contexa.contexacore.repository",
                    "io.contexa.contexacore.verification.evidence",
                    "io.contexa.contexaiam.repository"
            },
            entityManagerFactoryRef = "contexaEntityManagerFactory",
            transactionManagerRef = "contexaTransactionManager",
            nameGenerator = ContexaRepositoryBeanNameGenerator.class
    )
    private static class ContexaRepositoriesWithOfficialEvidenceConfiguration {
    }

    public static final class ContexaRepositoryBeanNameGenerator extends AnnotationBeanNameGenerator {

        @Override
        public String generateBeanName(BeanDefinition definition, BeanDefinitionRegistry registry) {
            String beanName = super.generateBeanName(definition, registry);
            if (!StringUtils.hasText(beanName)) {
                return beanName;
            }
            String capitalized = Character.toUpperCase(beanName.charAt(0)) + beanName.substring(1);
            return "contexa" + capitalized;
        }
    }
}
