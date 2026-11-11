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
package io.contexa.contexacore.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ContexaUserStoreTest {

    private static final UserDetailsService CONTEXA = mock(UserDetailsService.class);
    private static final UserDetailsService ONE = mock(UserDetailsService.class);
    private static final UserDetailsService TWO = mock(UserDetailsService.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(ContexaStore.class);

    @Test
    void anApplicationWithoutAStoreSignsInWithContexas() {
        runner.run(context -> assertThat(ContexaUserStore.of(context)).isSameAs(CONTEXA));
    }

    @Test
    void theOnlyStoreOfTheApplicationIsTheStoreOfTheSignIn() {
        runner.withUserConfiguration(OneStore.class).run(context -> assertThat(ContexaUserStore.of(context)).isSameAs(ONE));
    }

    @Test
    void severalStoresOfTheApplicationLeaveContexasRatherThanStopTheStart() {
        runner.withUserConfiguration(OneStore.class, AnotherStore.class).run(context -> assertThat(ContexaUserStore.of(context)).isSameAs(CONTEXA));
    }

    @Test
    void theStoreTheApplicationMarksPrimaryIsTheChoiceItMade() {
        runner.withUserConfiguration(OneStore.class, PrimaryStore.class).run(context -> assertThat(ContexaUserStore.of(context)).isSameAs(TWO));
    }

    /** Where Contexa owns the sign-in its accounts sign in from its own store, whatever stores the application declares. */
    @Test
    void contexasSignInReadsContexasStoreWhateverTheApplicationDeclares() {
        runner.run(context -> assertThat(ContexaUserStore.forSignIn(context)).isSameAs(CONTEXA));
        runner.withUserConfiguration(OneStore.class)
                .run(context -> assertThat(ContexaUserStore.forSignIn(context)).isSameAs(CONTEXA));
        runner.withUserConfiguration(OneStore.class, AnotherStore.class)
                .run(context -> assertThat(ContexaUserStore.forSignIn(context)).isSameAs(CONTEXA));
        runner.withUserConfiguration(OneStore.class, PrimaryStore.class)
                .run(context -> assertThat(ContexaUserStore.forSignIn(context)).isSameAs(CONTEXA));
    }

    /** Where the application keeps its sign-in Contexa has no store of its own to prefer, and what it asks is asked as before. */
    @Test
    void whereContexaDoesNotOwnTheSignInTheApplicationsStoreServesAsBefore() {
        ApplicationContextRunner application = new ApplicationContextRunner();
        application.withUserConfiguration(OneStore.class)
                .run(context -> assertThat(ContexaUserStore.forSignIn(context)).isSameAs(ONE));
        application.withUserConfiguration(OneStore.class, PrimaryStore.class)
                .run(context -> assertThat(ContexaUserStore.forSignIn(context)).isSameAs(TWO));
    }

    /** A token of the sign-in names one of Contexa's accounts only while Contexa's store is the one that signs the users in. */
    @Test
    void contexasAccountsSignInOnlyWhileItsStoreServesTheSignIn() {
        runner.run(context -> assertThat(ContexaUserStore.signsInWithContexaAccounts(context).getAsBoolean()).isTrue());
        runner.withUserConfiguration(OneStore.class, AnotherStore.class)
                .run(context -> assertThat(ContexaUserStore.signsInWithContexaAccounts(context).getAsBoolean()).isTrue());
        runner.withUserConfiguration(OneStore.class)
                .run(context -> assertThat(ContexaUserStore.signsInWithContexaAccounts(context).getAsBoolean()).isFalse());
        runner.withUserConfiguration(OneStore.class, PrimaryStore.class)
                .run(context -> assertThat(ContexaUserStore.signsInWithContexaAccounts(context).getAsBoolean()).isFalse());
        new ApplicationContextRunner().withUserConfiguration(OneStore.class)
                .run(context -> assertThat(ContexaUserStore.signsInWithContexaAccounts(context).getAsBoolean())
                        .as("where the application owns the sign-in Contexa's store does not exist").isFalse());
    }

    @Configuration(proxyBeanMethods = false)
    static class ContexaStore {
        @Bean(name = ContexaUserStore.BEAN_NAME, defaultCandidate = false)
        UserDetailsService contexa() {
            return CONTEXA;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class OneStore {
        @Bean
        UserDetailsService one() {
            return ONE;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class AnotherStore {
        @Bean
        UserDetailsService two() {
            return TWO;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class PrimaryStore {
        @Bean
        @Primary
        UserDetailsService two() {
            return TWO;
        }
    }
}
