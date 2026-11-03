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

import com.legacyshop.proxytest.LegacyApplication;
import io.contexa.autoconfigure.core.proxytest.ContexaSideBean;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's beans are proxied by class and the application's beans the way the application chose: an application that chose JDK proxies
 * (spring.aop.proxy-target-class=false) and has a final class behind an interface starts with Contexa's configuration present, and a
 * bean that a Contexa package defines keeps its class proxy.
 */
class ContexaProxyModeAutoConfigurationTest {

    private ApplicationContextRunner runner(String proxyTargetClass) {
        return new ApplicationContextRunner()
                .withUserConfiguration(LegacyApplication.class, ContexaSideBean.Definition.class)
                .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, ContexaProxyModeAutoConfiguration.class))
                .withPropertyValues("spring.aop.proxy-target-class=" + proxyTargetClass);
    }

    @Test
    void anApplicationThatChoseJdkProxiesKeepsThemForItsFinalClass() {
        runner("false").run(context -> {
            assertThat(context).hasNotFailed();
            LegacyApplication.Port port = context.getBean(LegacyApplication.Port.class);
            assertThat(AopUtils.isJdkDynamicProxy(port)).as("the application's final class").isTrue();
            assertThat(port.run()).isEqualTo("ran");
        });
    }

    @Test
    void aBeanOfAContexaPackageKeepsItsClassProxy() {
        runner("false").run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSideBean bean = context.getBean(ContexaSideBean.class);
            assertThat(AopUtils.isCglibProxy(bean)).as("a bean defined in a Contexa package").isTrue();
            assertThat(bean.work()).isEqualTo("worked");
        });
    }

    @Test
    void anApplicationThatChoseClassProxiesGetsTheConsequenceOfItsOwnChoice() {
        // Contexa does not change the choice in either direction: with class proxies a final class cannot be advised
        runner("true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("CGLIB");
        });
    }

    @Test
    void theMarkedDefinitionsAreThoseOfTheContexaLibraryPackages() {
        assertThat(ContexaProxyModeAutoConfiguration.CONTEXA_PACKAGES).containsExactly("io.contexa.contexa", "io.contexa.autoconfigure");
    }
}
