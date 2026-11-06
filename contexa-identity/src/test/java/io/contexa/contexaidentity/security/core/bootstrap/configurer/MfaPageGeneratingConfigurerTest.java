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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * PR-19: the page that asks for the code looked the registered address up with whatever JdbcTemplate the application
 * had, so it ran {@code SELECT email FROM ctxa_users} on the application's database and came back empty.
 */
class MfaPageGeneratingConfigurerTest {

    @Test
    @DisplayName("the code page reads Contexa's accounts, not the database of the application")
    void readsContexasDatabase() {
        JdbcTemplate application = mock(JdbcTemplate.class);
        JdbcTemplate contexa = mock(JdbcTemplate.class);
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            context.registerBean("jdbcTemplate", JdbcTemplate.class, () -> application);
            context.registerBean("contexaJdbcTemplate", JdbcTemplate.class, () -> contexa,
                    definition -> ((AbstractBeanDefinition) definition).setDefaultCandidate(false));
            context.refresh();

            assertThat(MfaPageGeneratingConfigurer.accountStore(context)).isSameAs(contexa);
        }
    }
}
