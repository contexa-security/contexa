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
package io.contexa.autoconfigure.identity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.ServiceLoader;

/**
 * Moves a Contexa database that still has the former table names to the {@code ctxa_} names (see
 * {@link ContexaSchemaPrefixMigration}) the moment Contexa's data source exists, before any bean can read from it: the
 * schema installation, the JPA setup, the stores and the schedulers all see the new names or none.
 */
@Slf4j
@AutoConfiguration
@ConditionalOnClass(DataSource.class)
public class ContexaSchemaPrefixAutoConfiguration {

    static final String DATA_SOURCE_BEAN = "contexaDataSource";

    @Bean
    public static BeanPostProcessor contexaSchemaPrefixMigrationPostProcessor() {
        return new MigrationPostProcessor();
    }

    static final class MigrationPostProcessor implements BeanPostProcessor, BeanFactoryAware {

        private ConfigurableBeanFactory beanFactory;

        @Override
        public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
            this.beanFactory = beanFactory instanceof ConfigurableBeanFactory configurable ? configurable : null;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
            if (bean instanceof DataSource dataSource && isContexaDataSource(beanName)) {
                try {
                    ContexaSchemaPrefixMigration migration = new ContexaSchemaPrefixMigration(dataSource);
                    if (legacyInstallation(migration)) {
                        beforeRename(dataSource);
                    }
                    migration.migrate();
                } catch (SQLException | RuntimeException e) {
                    throw new BeanInitializationException("The Contexa database could not be moved to the ctxa_ table names; "
                            + "it was left as it was: " + e.getMessage(), e);
                }
            }
            return bean;
        }

        /** A database that cannot be reached is left to migrate(), which says so and goes on, as before. */
        private static boolean legacyInstallation(ContexaSchemaPrefixMigration migration) {
            try {
                return migration.hasLegacyInstallation();
            } catch (SQLException unreachable) {
                return false;
            }
        }

        /** The participants of the modules on the class path finish what needs the former names (ContexaSchemaPrefixParticipant). */
        private void beforeRename(DataSource dataSource) {
            Environment environment = beanFactory != null && beanFactory.containsBean("environment")
                    ? beanFactory.getBean("environment", Environment.class) : null;
            ClassLoader classLoader = beanFactory != null && beanFactory.getBeanClassLoader() != null
                    ? beanFactory.getBeanClassLoader() : getClass().getClassLoader();
            for (ContexaSchemaPrefixParticipant participant
                    : ServiceLoader.load(ContexaSchemaPrefixParticipant.class, classLoader)) {
                try {
                    participant.beforeRename(dataSource, environment);
                } catch (Exception e) {
                    throw new BeanInitializationException("The work " + participant.getClass().getName()
                            + " does on the former table names before the move to ctxa_ failed; the database was not "
                            + "moved: " + e.getMessage(), e);
                }
            }
        }

        private boolean isContexaDataSource(String beanName) {
            return DATA_SOURCE_BEAN.equals(beanName)
                    || beanFactory != null && Arrays.asList(beanFactory.getAliases(beanName)).contains(DATA_SOURCE_BEAN);
        }
    }
}
