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

import io.contexa.contexacore.config.ApplicationConfig;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code @EnableAspectJAutoProxy} in a Contexa configuration switched the application's aspects on against its own setting. */
class ContexaAspectProxyingHostCoexistenceTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(ApplicationConfig.class, Application.class)
            .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class));

    @Test
    void anApplicationThatTurnedAspectsOffKeepsThemOff() {
        runner.withPropertyValues("spring.aop.auto=false")
                .run(context -> assertThat(AopUtils.isAopProxy(context.getBean(Orders.class))).isFalse());
    }

    @Test
    void anApplicationThatLeftThemOnKeepsThemOn() {
        runner.run(context -> assertThat(AopUtils.isAopProxy(context.getBean(Orders.class))).isTrue());
    }

    @Configuration(proxyBeanMethods = false)
    static class Application {

        @Bean
        Orders orders() {
            return new Orders();
        }

        @Bean
        Audit audit() {
            return new Audit();
        }
    }

    static class Orders {

        public void place() {
        }
    }

    @Aspect
    static class Audit {

        @Before("execution(* io.contexa.autoconfigure.core.ContexaAspectProxyingHostCoexistenceTest.Orders.place(..))")
        public void record() {
        }
    }
}
