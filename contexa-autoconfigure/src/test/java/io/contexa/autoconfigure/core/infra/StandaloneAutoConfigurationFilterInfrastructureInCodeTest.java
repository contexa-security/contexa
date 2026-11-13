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
package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.lettuce.core.RedisClient;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.junit.jupiter.api.Test;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.annotation.AnnotatedGenericBeanDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DeferredImportSelector;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.mock.env.MockEnvironment;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application says in two ways that it uses Redis or Kafka itself: with a connection property, or in its code. One that builds its
 * factories in code, or takes Spring Boot's template with the default address, gives no property. Switched on in Contexa's default
 * standalone mode it keeps the auto-configuration its beans come from (PR-185: such an application did not start, or started and
 * received none of its messages), and an application that uses no Redis still gets none of Spring Boot's Redis support. Spring Boot's
 * Kafka support stays in every case: nothing of Contexa's standalone mode uses Kafka.
 */
class StandaloneAutoConfigurationFilterInfrastructureInCodeTest {

    private static final String[] INFRASTRUCTURE = {
            "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
            "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration",
            "org.redisson.spring.starter.RedissonAutoConfigurationV2",
            "org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration",
            "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration",
            "io.contexa.contexaidentity.config.ZeroTrustRedisConfig"
    };

    /**
     * The application keeps its Redis, Contexa's own Redis stays out of the standalone mode. Spring Boot's Kafka support (the fourth) stays
     * whatever the code says: nothing of Contexa's standalone mode uses Kafka, so leaving it out only took the application's beans.
     */
    private static final boolean[] ITS_REDIS = {true, true, true, true, false, false};
    private static final boolean[] ITS_KAFKA = {false, false, false, true, false, false};
    private static final boolean[] BOTH = {true, true, true, true, false, false};
    private static final boolean[] NONE = {false, false, false, true, false, false};

    @Test
    void anApplicationThatBuildsItsKafkaFactoryInCodeKeepsSpringBootsKafkaSupport() {
        assertThat(kept(applicationWith(KafkaFactoryInCode.class))).containsExactly(ITS_KAFKA);
    }

    /** It gives no address at all: Spring Boot's template with the default one is what it runs on. */
    @Test
    void anApplicationThatOnlyTakesTheKafkaTemplateKeepsIt() {
        assertThat(kept(applicationWith(KafkaTemplateTaken.class))).containsExactly(ITS_KAFKA);
    }

    /** Without the auto-configuration nothing reads the annotation: the application starts and receives nothing. */
    @Test
    void anApplicationThatOnlyListensKeepsWhatStartsItsListeners() {
        assertThat(kept(applicationWith(KafkaListenerOnly.class))).containsExactly(ITS_KAFKA);
    }

    @Test
    void anApplicationThatBuildsItsRedisConnectionInCodeKeepsSpringBootsRedisSupport() {
        assertThat(kept(applicationWith(RedisConnectionInCode.class))).containsExactly(ITS_REDIS);
    }

    @Test
    void anApplicationThatOnlyTakesTheRedisTemplateKeepsIt() {
        assertThat(kept(applicationWith(RedisTemplateTaken.class))).containsExactly(ITS_REDIS);
    }

    @Test
    void anApplicationThatTakesTheRedissonClientKeepsItsRedis() {
        assertThat(kept(applicationWith(RedissonClientTaken.class))).containsExactly(ITS_REDIS);
    }

    @Test
    void anApplicationThatUsesBothKeepsBoth() {
        assertThat(kept(applicationWith(KafkaTemplateTaken.class, RedisTemplateTaken.class))).containsExactly(BOTH);
    }

    /** The client libraries alone need nothing of Spring Boot's Redis support, and a name in a string is not a use. */
    @Test
    void anApplicationThatUsesNoneOfSpringsSupportStillGetsNoneOfIt() {
        assertThat(kept(applicationWith(NoInfrastructure.class))).containsExactly(NONE);
        assertThat(kept(applicationWith(ClientLibrariesOnly.class))).containsExactly(NONE);
        assertThat(kept(applicationWith(LibrariesNamedInAStringOnly.class))).containsExactly(NONE);
        assertThat(kept(new DefaultListableBeanFactory())).containsExactly(NONE);
    }

    /** What the property decided is not taken back by the code: Redis by its property, Kafka by the code. */
    @Test
    void aConnectionPropertyAndTheCodeAddUp() {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter();
        filter.setEnvironment(switchedOn(new MockEnvironment().withProperty("spring.data.redis.host", "redis.internal")));
        filter.setBeanFactory(applicationWith(KafkaTemplateTaken.class));

        assertThat(filter.match(INFRASTRUCTURE, null)).containsExactly(BOTH);
    }

    /** Reading the classes must never be what stops an application: one that cannot be read says nothing. */
    @Test
    void aClassThatCannotBeReadSaysNothingAndFailsNothing() {
        DefaultListableBeanFactory unreadable = applicationWith(KafkaFactoryInCode.class, RedisConnectionInCode.class);
        unreadable.setBeanClassLoader(new ClassLoader(getClass().getClassLoader()) {
            @Override
            public InputStream getResourceAsStream(String name) {
                return new InputStream() {
                    @Override
                    public int read() throws IOException {
                        throw new IOException("unreadable");
                    }
                };
            }
        });
        DefaultListableBeanFactory missing = applicationWith(KafkaFactoryInCode.class, RedisConnectionInCode.class);
        missing.setBeanClassLoader(new ClassLoader(getClass().getClassLoader()) {
            @Override
            public InputStream getResourceAsStream(String name) {
                return null;
            }
        });

        assertThat(kept(unreadable)).containsExactly(NONE);
        assertThat(kept(missing)).containsExactly(NONE);
    }

    /** The distributed mode and an application that is not switched on keep every auto-configuration that is not Contexa's, as before. */
    @Test
    void whatTheModeAndTheSwitchDecideStaysAsItWas() {
        StandaloneAutoConfigurationFilter distributed = new StandaloneAutoConfigurationFilter();
        distributed.setEnvironment(switchedOn(new MockEnvironment().withProperty("contexa.infrastructure.mode", "distributed")));
        distributed.setBeanFactory(applicationWith(NoInfrastructure.class));
        StandaloneAutoConfigurationFilter notSwitchedOn = new StandaloneAutoConfigurationFilter();
        notSwitchedOn.setEnvironment(new MockEnvironment());
        notSwitchedOn.setBeanFactory(applicationWith(KafkaTemplateTaken.class));

        assertThat(distributed.match(INFRASTRUCTURE, null)).containsOnly(true);
        assertThat(notSwitchedOn.match(INFRASTRUCTURE, null)).containsExactly(true, true, true, true, false, false);
    }

    /**
     * Spring asks the filter while it handles deferred imports: by then it has registered the classes it scanned, and none of the beans
     * they declare. This asks the filter at that very point.
     */
    @Test
    void theClassesOfAScannedApplicationAreAlreadyInSightWhenSpringAsksTheFilter() {
        AskedAtImportTime.kept = null;

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(ScanningApplication.class)) {
            assertThat(context.getBeansOfType(RedisTemplateWhereThereIsOne.class)).hasSize(1);
            assertThat(AskedAtImportTime.kept).containsExactly(ITS_REDIS);
        }
    }

    private static boolean[] kept(BeanFactory application) {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter();
        filter.setEnvironment(switchedOn(new MockEnvironment()));
        filter.setBeanFactory(application);
        return filter.match(INFRASTRUCTURE, null);
    }

    /** The annotation publishes this source when it switches Contexa on. */
    private static MockEnvironment switchedOn(MockEnvironment environment) {
        environment.getPropertySources().addFirst(new MapPropertySource(
                AiSecurityImportSelector.ACTIVATION_SOURCE, Map.of("contexa.ai.security.mode", "SANDBOX")));
        return environment;
    }

    private static DefaultListableBeanFactory applicationWith(Class<?>... classes) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        for (Class<?> each : classes) {
            beanFactory.registerBeanDefinition(each.getName(), new AnnotatedGenericBeanDefinition(each));
        }
        return beanFactory;
    }

    /** Builds its factory from its own settings, and leans on Spring Boot for the template and the listeners. */
    @Configuration(proxyBeanMethods = false)
    static class KafkaFactoryInCode {
        @Bean
        ProducerFactory<String, String> orderEvents() {
            return new DefaultKafkaProducerFactory<>(Map.of());
        }
    }

    static class KafkaTemplateTaken {

        private final KafkaTemplate<String, String> orders;

        KafkaTemplateTaken(KafkaTemplate<String, String> orders) {
            this.orders = orders;
        }
    }

    static class KafkaListenerOnly {
        @KafkaListener(topics = "orders")
        void received(String order) {
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class RedisConnectionInCode {
        @Bean
        LettuceConnectionFactory sessions() {
            return new LettuceConnectionFactory("redis.internal", 6379);
        }
    }

    static class RedisTemplateTaken {

        private final StringRedisTemplate sessions;

        RedisTemplateTaken(StringRedisTemplate sessions) {
            this.sessions = sessions;
        }
    }

    static class RedissonClientTaken {

        private final RedissonClient locks;

        RedissonClientTaken(RedissonClient locks) {
            this.locks = locks;
        }
    }

    /** Takes Spring Data Redis's template where there is one, so that it is made without a Redis. */
    static class RedisTemplateWhereThereIsOne {

        @Autowired(required = false)
        private StringRedisTemplate sessions;
    }

    /** Talks to Kafka and Redis with their own clients: nothing of Spring's support for them. */
    static class ClientLibrariesOnly {

        private KafkaProducer<String, String> producer;

        private RedisClient redis;
    }

    static class LibrariesNamedInAStringOnly {

        static final String TEMPLATE = "org.springframework.kafka.core.KafkaTemplate";

        static final String SESSIONS = "org.springframework.data.redis.core.StringRedisTemplate";
    }

    @Configuration(proxyBeanMethods = false)
    static class NoInfrastructure {
        @Bean
        String greeting() {
            return "hello";
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ComponentScan(basePackageClasses = StandaloneAutoConfigurationFilterInfrastructureInCodeTest.class, useDefaultFilters = false,
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = RedisTemplateWhereThereIsOne.class))
    @Import(AskedAtImportTime.class)
    static class ScanningApplication {
    }

    static class AskedAtImportTime implements DeferredImportSelector, BeanFactoryAware {

        static boolean[] kept;

        private BeanFactory beanFactory;

        @Override
        public void setBeanFactory(BeanFactory beanFactory) {
            this.beanFactory = beanFactory;
        }

        @Override
        public String[] selectImports(AnnotationMetadata importingClassMetadata) {
            kept = StandaloneAutoConfigurationFilterInfrastructureInCodeTest.kept(this.beanFactory);
            return new String[0];
        }
    }
}
