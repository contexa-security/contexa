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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * PR-174: the functional routes of a WebFlux application were refused when every bean existed, which is after Contexa had
 * installed its tables and seed rows in its database. They are refused from their bean definitions, before anything is made.
 */
class ReactiveRoutesDefinitionCheckTest {

    private static final String REASON = "Contexa runs on a servlet stack, and this application has WebFlux routes that it"
            + " never maps: [fnRouterFunction].";
    private static final String ACTION = "Run this application on the servlet stack with Spring MVC, or remove Contexa from it.";

    /** What a refused start must not have made: the routes themselves, and what stands for the work of a start. */
    private static final AtomicInteger MADE = new AtomicInteger();

    @BeforeEach
    void nothingIsMadeYet() {
        MADE.set(0);
    }

    // ---- the refusal

    @Test
    void routesAreRefusedFromTheirDefinitionsBeforeAnythingIsMade() {
        try (AnnotationConfigApplicationContext host = host(HostWithRoutes.class)) {
            assertThatThrownBy(host::refresh)
                    .isInstanceOf(ContexaOperatingProfileException.class)
                    .hasMessageContaining("[fnRouterFunction]");
        }

        assertThat(MADE).hasValue(0);
    }

    @Test
    void theRefusalSaysWhatTheLaterRefusalSays() {
        ContexaOperatingProfileException one = OwnershipStartupDiagnostics.reactiveRoutesRefused(new String[] {"fnRouterFunction"});
        assertThat(one.getMessage()).isEqualTo(REASON);
        assertThat(one.action()).isEqualTo(ACTION);

        try (AnnotationConfigApplicationContext host = host(HostWithRoutes.class)) {
            assertThatThrownBy(host::refresh).isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                assertThat(refused.getMessage()).isEqualTo(REASON);
                assertThat(refused.action()).isEqualTo(ACTION);
            });
        }
        DefaultListableBeanFactory made = new DefaultListableBeanFactory();
        made.registerSingleton("fnRouterFunction", routes());
        assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseReactiveRoutes(made, getClass().getClassLoader()))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).isEqualTo(REASON);
                    assertThat(refused.action()).isEqualTo(ACTION);
                });
    }

    /** Routes that are declared and made as nothing are the later refusal's too: for those it reads the declaration as well. */
    @Test
    void routesDeclaredAndNotMadeAreRefusedByBothAlike() {
        try (AnnotationConfigApplicationContext started = new AnnotationConfigApplicationContext(HostWithRoutesNotMade.class)) {
            assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseReactiveRoutes(started.getBeanFactory(),
                    getClass().getClassLoader()))
                    .isInstanceOf(ContexaOperatingProfileException.class)
                    .hasMessageContaining("[notMade]");
        }
        try (AnnotationConfigApplicationContext host = host(HostWithRoutesNotMade.class)) {
            assertThatThrownBy(host::refresh)
                    .isInstanceOf(ContexaOperatingProfileException.class)
                    .hasMessageContaining("[notMade]");
        }
    }

    // ---- what it does not refuse

    /** The functional routes of Spring MVC are the servlet stack's own: they are mapped, and nothing is wrong with them. */
    @Test
    void anApplicationOnTheServletStackStarts() {
        try (AnnotationConfigApplicationContext host = host(ServletHost.class)) {
            assertThatCode(host::refresh).doesNotThrowAnyException();
            assertThat(host.getBeanNamesForType(org.springframework.web.servlet.function.RouterFunction.class)).hasSize(1);
        }

        assertThat(MADE).hasValue(1);
    }

    /** What is declared as something wider is not seen in its definition; the later refusal finds it when it exists. */
    @Test
    void routesDeclaredAsSomethingWiderAreLeftToTheLaterRefusal() {
        try (AnnotationConfigApplicationContext host = host(HostWithRoutesDeclaredWider.class)) {
            assertThatCode(host::refresh).doesNotThrowAnyException();
            assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseReactiveRoutes(host.getBeanFactory(),
                    getClass().getClassLoader()))
                    .isInstanceOf(ContexaOperatingProfileException.class)
                    .hasMessageContaining("[declaredWider]");
        }
    }

    /** What the check cannot read lets the start go on, to the later refusal. */
    @Test
    void aFailureOfItsOwnReadingLetsTheStartGoOn() {
        DefaultListableBeanFactory unreadable = new DefaultListableBeanFactory() {
            @Override
            public String[] getBeanNamesForType(Class<?> type, boolean includeNonSingletons, boolean allowEagerInit) {
                throw new IllegalStateException("unreadable");
            }
        };
        DefaultListableBeanFactory unlinked = new DefaultListableBeanFactory() {
            @Override
            public String[] getBeanNamesForType(Class<?> type, boolean includeNonSingletons, boolean allowEagerInit) {
                throw new NoClassDefFoundError("a class of the application that is not there");
            }
        };

        assertThatCode(() -> new ReactiveRoutesDefinitionCheck().postProcessBeanFactory(unreadable)).doesNotThrowAnyException();
        assertThatCode(() -> new ReactiveRoutesDefinitionCheck().postProcessBeanFactory(unlinked)).doesNotThrowAnyException();
    }

    // ---- as an installation has it

    /** The check stands in the configuration {@code @EnableAISecurity} brings, whoever owns the sign-in. */
    @Test
    void anInstallationRefusesTheRoutesBeforeAnythingIsMade() {
        for (String ownership : List.of("HOST_OWNED", "CONTEXA_OWNED")) {
            MADE.set(0);
            installation(HostWithRoutes.class)
                    .withPropertyValues("contexa.bridge.ownership=" + ownership)
                    .run(context -> {
                        assertThat(context).as(ownership).hasFailed();
                        assertThat(context.getStartupFailure()).as(ownership)
                                .isInstanceOf(ContexaOperatingProfileException.class)
                                .hasMessage(REASON);
                    });

            assertThat(MADE).as(ownership).hasValue(0);
        }
    }

    @Test
    void anInstallationOnTheServletStackStarts() {
        installation(ServletHost.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(ReactiveRoutesDefinitionCheck.class);
            assertThat(context).hasSingleBean(OwnershipStartupDiagnostics.class);
        });

        assertThat(MADE).hasValue(1);
    }

    // ---- helpers

    /** A start with the check and without Contexa's own beans: the definitions are read as in any start. */
    private static AnnotationConfigApplicationContext host(Class<?> configuration) {
        AnnotationConfigApplicationContext host = new AnnotationConfigApplicationContext();
        host.register(configuration);
        host.addBeanFactoryPostProcessor(new ReactiveRoutesDefinitionCheck());
        return host;
    }

    private static ApplicationContextRunner installation(Class<?> host) {
        return new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class, host)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build());
    }

    private static RouterFunction<ServerResponse> routes() {
        return RouterFunctions.route().GET("/orders", request -> ServerResponse.ok().build()).build();
    }

    /** Stands for what a start does before it is over: Contexa's tables and seed rows, the application's own work. */
    static class Installed {

        Installed() {
            MADE.incrementAndGet();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class HostWithRoutes {

        @Bean
        RouterFunction<ServerResponse> fnRouterFunction() {
            MADE.incrementAndGet();
            return routes();
        }

        @Bean
        Installed installed() {
            return new Installed();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class HostWithRoutesNotMade {

        @Bean
        RouterFunction<ServerResponse> notMade() {
            return null;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class HostWithRoutesDeclaredWider {

        @Bean
        Object declaredWider() {
            return routes();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ServletHost {

        @Bean
        org.springframework.web.servlet.function.RouterFunction<org.springframework.web.servlet.function.ServerResponse> mvcRoutes() {
            return org.springframework.web.servlet.function.RouterFunctions.route()
                    .GET("/orders", request -> org.springframework.web.servlet.function.ServerResponse.ok().build())
                    .build();
        }

        @Bean
        Installed installed() {
            return new Installed();
        }
    }
}
