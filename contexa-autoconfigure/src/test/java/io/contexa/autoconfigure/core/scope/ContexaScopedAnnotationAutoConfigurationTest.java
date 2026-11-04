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
package io.contexa.autoconfigure.core.scope;

import com.legacyshop.scope.LegacyScopeApplication;
import io.contexa.autoconfigure.core.ContexaProxyModeAutoConfiguration;
import io.contexa.autoconfigure.core.scope.sample.ContexaSample;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cache.CacheManager;
import org.springframework.cache.interceptor.CacheAspectSupport;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's scheduling, asynchronous execution and caching reach Contexa's own beans only. The application's annotations stay as dormant
 * as it left them, an application that turned the support on itself is not given a second one, and Contexa's caches never share a store
 * with the application's.
 */
class ContexaScopedAnnotationAutoConfigurationTest {

    private ApplicationContextRunner runner(Class<?> application) {
        return new ApplicationContextRunner()
                .withUserConfiguration(application, ContexaSample.Definition.class)
                .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, CacheAutoConfiguration.class,
                        TaskExecutionAutoConfiguration.class,
                        ContexaProxyModeAutoConfiguration.class, ContexaScopedAnnotationAutoConfiguration.class));
    }

    @Test
    void theApplicationsDormantAnnotationsStayDormant() {
        runner(LegacyScopeApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            LegacyScopeApplication.AppService app = context.getBean(LegacyScopeApplication.AppService.class);
            Thread.sleep(400);

            assertThat(app.ticks()).as("@Scheduled of the application").isZero();
            assertThat(app.thread().get(2, TimeUnit.SECONDS)).as("@Async of the application runs on the caller's thread")
                    .isEqualTo(Thread.currentThread().getName());
            app.cached("a");
            app.cached("a");
            assertThat(app.cacheCalls()).as("@Cacheable of the application: no cache").isEqualTo(2);
            assertThat(app.shared("k")).isEqualTo("app:k");
        });
    }

    @Test
    void theApplicationsSchedulingConfigurerIsNeverCalledWhenSchedulingIsNotEnabled() {
        runner(LegacyScopeApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBean(LegacyScopeApplication.CountingSchedulingConfigurer.class).calls())
                    .as("the application never turned scheduling on: Contexa's scheduling does not bring its configurer to life").isZero();
        });
    }

    @Test
    void theApplicationsSchedulingConfigurerIsCalledOnceNotForContexasSchedulingToo() {
        runner(LegacyScopeApplication.Enabled.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBean(LegacyScopeApplication.CountingSchedulingConfigurer.class).calls())
                    .as("applied to the application's own scheduling only").isEqualTo(1);
        });
    }

    @Test
    void contexasOwnAnnotationsWork() {
        runner(LegacyScopeApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSample bean = context.getBean(ContexaSample.class);
            Thread.sleep(500);

            assertThat(bean.ticks()).as("@Scheduled of Contexa").isGreaterThan(2);
            assertThat(bean.thread().get(2, TimeUnit.SECONDS)).as("@Async of Contexa runs on Contexa's executor").startsWith("contexa-async-");
            bean.cached("a");
            bean.cached("a");
            assertThat(bean.cacheCalls()).as("@Cacheable of Contexa: cached").isEqualTo(1);
        });
    }

    @Test
    void theApplicationIsNotGivenACacheManagerOrACacheInterceptorByContexa() {
        runner(LegacyScopeApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            LegacyScopeApplication.CacheManagerConsumer consumer = context.getBean(LegacyScopeApplication.CacheManagerConsumer.class);
            assertThat(consumer.viaProvider()).as("application code asking for a cache manager, if any (ObjectProvider)").isNull();
            assertThat(consumer.viaInjection()).as("application code asking for a cache manager, if any (@Nullable)").isNull();
            assertThat(context.getBeansOfType(CacheAspectSupport.class))
                    .as("no cache interceptor bean (Spring Boot's cache configuration stays off)").isEmpty();
            assertThat(context.getBean("contexaCacheManager")).as("Contexa's own, reachable by its name").isNotNull();
        });
    }

    @Test
    void anApplicationThatEnabledSchedulingAndAsyncItselfIsNotGivenASecondProcessor() {
        runner(LegacyScopeApplication.Enabled.class).run(context -> {
            assertThat(context).hasNotFailed();
            LegacyScopeApplication.AppService app = context.getBean(LegacyScopeApplication.AppService.class);
            ContexaSample sample = context.getBean(ContexaSample.class);
            Thread.sleep(400);

            assertThat(app.ticks()).as("the application asked for it").isGreaterThan(2);
            assertThat(context).as("Spring Boot still makes the application's default executor").hasBean("applicationTaskExecutor");
            assertThat(app.thread().get(2, TimeUnit.SECONDS))
                    .as("the application's @Async runs on Spring Boot's default executor, never on Contexa's")
                    .startsWith("task-");
            assertThat(sample.thread().get(2, TimeUnit.SECONDS))
                    .as("Contexa's @Async names Contexa's executor, whoever applies the annotation")
                    .startsWith("contexa-async-");
        });
    }

    @Test
    void anApplicationThatEnabledSchedulingItselfRunsContexasScheduledMethodToo() {
        runner(LegacyScopeApplication.Enabled.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSample sample = context.getBean(ContexaSample.class);
            Thread.sleep(500);

            assertThat(sample.ticks()).as("@Scheduled of Contexa, served by the application's own scheduling support").isGreaterThan(2);
        });
    }

    @Test
    void anApplicationThatEnabledAsyncExecutionForItsOwnMarkerOnlyStillGetsContexasAsync() {
        runner(LegacyScopeApplication.AsyncForItsOwnMarker.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSample sample = context.getBean(ContexaSample.class);

            assertThat(sample.thread().get(2, TimeUnit.SECONDS))
                    .as("the application's support does not look at @Async, so Contexa's own support must serve Contexa's method")
                    .startsWith("contexa-async-");
        });
    }

    @Test
    void anApplicationThatEnabledCachingItselfKeepsItsOwnCacheManagerAndItsOwnCaches() {
        runner(LegacyScopeApplication.CachingEnabled.class).run(context -> {
            assertThat(context).hasNotFailed();
            CacheManager application = context.getBean("cacheManager", CacheManager.class);
            CacheManager contexa = context.getBean("contexaCacheManager", CacheManager.class);
            assertThat(application).as("Spring Boot made the application's cache manager").isNotSameAs(contexa);
            assertThat(context.getBean(CacheManager.class)).as("by type, the application's").isSameAs(application);

            LegacyScopeApplication.AppService app = context.getBean(LegacyScopeApplication.AppService.class);
            ContexaSample sample = context.getBean(ContexaSample.class);

            app.cached("a");
            app.cached("a");
            assertThat(app.cacheCalls()).as("the application's cache works").isEqualTo(1);
            assertThat(application.getCache("legacyCache")).isNotNull();

            sample.cached("a");
            sample.cached("a");
            assertThat(sample.cacheCalls()).as("Contexa's cache works under the application's interceptor").isEqualTo(1);
            assertThat(contexa.getCache("contexaCache").get("a")).as("held by Contexa's manager").isNotNull();
            assertThat(application.getCacheNames()).as("Contexa's cache names never reach the application's manager")
                    .doesNotContain("contexaCache");
        });
    }

    @Test
    void sameCacheNameAndSameKeyNeverMeet() {
        runner(LegacyScopeApplication.CachingEnabled.class).run(context -> {
            assertThat(context).hasNotFailed();
            LegacyScopeApplication.AppService app = context.getBean(LegacyScopeApplication.AppService.class);
            ContexaSample sample = context.getBean(ContexaSample.class);

            assertThat(app.shared("k")).isEqualTo("app:k");
            assertThat(sample.shared("k")).as("Contexa's \"shared\" is not the application's \"shared\"").isEqualTo("contexa:k");
            assertThat(app.shared("k")).isEqualTo("app:k");
            assertThat(sample.shared("k")).isEqualTo("contexa:k");

            CacheManager application = context.getBean("cacheManager", CacheManager.class);
            CacheManager contexa = context.getBean("contexaCacheManager", CacheManager.class);
            assertThat(application.getCache("shared").get("k").get()).isEqualTo("app:k");
            assertThat(contexa.getCache("shared").get("k").get()).isEqualTo("contexa:k");
        });
    }

    @Test
    void sameCacheNameAndSameKeyNeverMeetWhenContexaAppliesTheAnnotationsItself() {
        runner(LegacyScopeApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSample sample = context.getBean(ContexaSample.class);
            LegacyScopeApplication.AppService app = context.getBean(LegacyScopeApplication.AppService.class);

            assertThat(sample.shared("k")).isEqualTo("contexa:k");
            assertThat(app.shared("k")).as("the application's method is not cached by Contexa").isEqualTo("app:k");
            assertThat(context.getBean("contexaCacheManager", CacheManager.class).getCache("shared").get("k").get())
                    .isEqualTo("contexa:k");
        });
    }
}
