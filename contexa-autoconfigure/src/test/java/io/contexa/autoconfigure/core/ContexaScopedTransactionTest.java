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

import hosttest.HostTransactionalService;
import io.contexa.autoconfigure.iam.sample.ContexaTransactionalSample;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.transaction.TransactionAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application without a database of its own had no transaction advisor at all, so every {@code @Transactional} of
 * Contexa was ignored; the failed sign-ins were not counted and no account was ever locked.
 */
class ContexaScopedTransactionTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Beans.class)
            .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, TransactionAutoConfiguration.class,
                    ContexaProxyModeAutoConfiguration.class, ContexaScopedTransactionAutoConfiguration.class));

    @Test
    void contexasTransactionsRunWhereTheApplicationHasNoTransactionManager() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(ContexaScopedTransactionAutoConfiguration.APPLICATION_ADVISOR);
            assertThat(context.getBean(ContexaTransactionalSample.class).inATransaction()).isTrue();
        });
    }

    /** Proxied, it would look for a transaction manager the application does not have, and fail on every call. */
    @Test
    void theApplicationsTransactionalStaysAsItWasWithoutATransactionManager() {
        runner.run(context -> {
            HostTransactionalService service = context.getBean(HostTransactionalService.class);

            assertThat(AopUtils.isAopProxy(service)).isFalse();
            assertThat(service.place()).isEqualTo("placed");
        });
    }

    @Test
    void anApplicationThatTurnedAspectsOffStillGetsContexasTransactions() {
        runner.withPropertyValues("spring.aop.auto=false").run(context ->
                assertThat(context.getBean(ContexaTransactionalSample.class).inATransaction()).isTrue());
    }

    @Test
    void anApplicationWithTransactionsOfItsOwnServesContexasClassesAndThisAdvisorStandsAside() {
        runner.withUserConfiguration(ApplicationTransactions.class).run(context -> {
            assertThat(context).hasBean(ContexaScopedTransactionAutoConfiguration.APPLICATION_ADVISOR);
            ContexaTransactionalSample sample = context.getBean(ContexaTransactionalSample.class);

            assertThat(sample.inATransaction()).isTrue();
            assertThat(context.getBean("contexaTransactionManager", CountingTransactionManager.class).begun)
                    .as("one transaction, not one per advisor").isEqualTo(1);
            assertThat(AopUtils.isAopProxy(context.getBean(HostTransactionalService.class))).isTrue();
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class Beans {

        @Bean(name = "contexaTransactionManager", defaultCandidate = false)
        CountingTransactionManager contexaTransactionManager() {
            return new CountingTransactionManager();
        }

        @Bean
        ContexaTransactionalSample contexaTransactionalSample() {
            return new ContexaTransactionalSample();
        }

        @Bean
        HostTransactionalService hostTransactionalService() {
            return new HostTransactionalService();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationTransactions {

        @Bean
        PlatformTransactionManager transactionManager() {
            return new CountingTransactionManager();
        }
    }

    static class CountingTransactionManager extends AbstractPlatformTransactionManager {

        int begun;

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
            begun++;
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
        }
    }
}
