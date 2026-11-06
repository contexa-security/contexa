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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.security.xacml.pip.attribute.DatabaseAttributePIP;
import io.contexa.contexaiam.security.xacml.pip.context.DefaultContextHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationListener;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/** PR-87: what a start does with the users' copies an earlier version left in the cache. */
class IamXacmlPipAutoConfigurationTest {

    private static final String CLEAR_ON_START = "contexaSubjectCacheClearOnStart";
    private static final long WAIT_MILLIS = 5_000;

    private final ContexaCacheService cache = mock(ContexaCacheService.class);

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IamXacmlPipAutoConfiguration.class))
                .withBean(UserRepository.class, () -> mock(UserRepository.class))
                .withBean(AuditLogRepository.class, () -> mock(AuditLogRepository.class))
                .withBean(BusinessResourceActionRepository.class, () -> mock(BusinessResourceActionRepository.class))
                .withBean(ContexaCacheService.class, () -> cache);
    }

    @Test
    @DisplayName("PR-87: every start takes the users' copies out of the cache")
    void aStartClearsTheCopies() {
        runner().run(context -> {
            ready(context.getBean(CLEAR_ON_START, ApplicationListener.class));

            verify(cache, timeout(WAIT_MILLIS)).invalidate("user_details:*");
            verify(cache, timeout(WAIT_MILLIS)).invalidate("user_details_name:*");
        });
    }

    @Test
    @DisplayName("PR-87: a store that cannot be reached does not stop the start")
    void anUnreachableStoreDoesNotStopTheStart() {
        doThrow(new IllegalStateException("The store cannot be reached")).when(cache).invalidate(anyString());

        runner().run(context -> {
            ApplicationListener<?> clearing = context.getBean(CLEAR_ON_START, ApplicationListener.class);

            assertThatCode(() -> ready(clearing)).doesNotThrowAnyException();

            verify(cache, timeout(WAIT_MILLIS)).invalidate("user_details:*");
        });
    }

    @Test
    @DisplayName("PR-87: a host that replaced the beans that need the cache and runs without one still starts")
    void aHostWithoutTheCacheStillStarts() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IamXacmlPipAutoConfiguration.class))
                .withBean(DatabaseAttributePIP.class, () -> mock(DatabaseAttributePIP.class))
                .withBean(DefaultContextHandler.class, () -> mock(DefaultContextHandler.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThatCode(() -> ready(context.getBean(CLEAR_ON_START, ApplicationListener.class)))
                            .doesNotThrowAnyException();
                });
    }

    @SuppressWarnings("unchecked")
    private static void ready(ApplicationListener<?> listener) {
        ((ApplicationListener<ApplicationReadyEvent>) listener).onApplicationEvent(mock(ApplicationReadyEvent.class));
    }
}
