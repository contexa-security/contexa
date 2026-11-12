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

import hosttest.HostFieldMailingService;
import hosttest.HostMailingService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.actuate.autoconfigure.health.HealthContributorAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.health.HealthEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.mail.MailHealthContributorAutoConfiguration;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.actuate.mail.MailHealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mail.MailSender;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;

import java.lang.reflect.Proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/** The mail server in these settings is a port nothing listens on: a {@code mail} health that is asked answers DOWN. */
@ExtendWith(OutputCaptureExtension.class)
class HostHealthWithoutContexaMailTest {

    private static final String TOLD = "'mail' health is left out";

    private final WebApplicationContextRunner health = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MailSenderAutoConfiguration.class,
                    MailHealthContributorAutoConfiguration.class, HealthContributorAutoConfiguration.class,
                    HealthEndpointAutoConfiguration.class));

    private final WebApplicationContextRunner boot = health
            .withPropertyValues("spring.mail.host=127.0.0.1", "spring.mail.port=1");

    private final WebApplicationContextRunner host = boot.withUserConfiguration(HostMailHealthConfiguration.class);

    /** The control: without Contexa's part, settings that name a mail server put that server into the health. */
    @Test
    void aMailServerInTheSettingsBecomesAHealthOfItsOwnInSpringBoot() {
        boot.run(context -> {
            assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class);
            assertThat(context.getBean(HealthEndpoint.class).health().getStatus()).isEqualTo(Status.DOWN);
        });
    }

    @Test
    void aMailServerOnlyContexaUsesDoesNotDecideTheHealthOfTheApplication(CapturedOutput output) {
        host.withUserConfiguration(CodeMailAskedForWhenDue.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(registry(context).getContributor("mail")).isNull();
            assertThat(registry(context).getContributor("ping")).isNotNull();
            assertThat(context.getBean(HealthEndpoint.class).health().getStatus()).isEqualTo(Status.UP);
            assertThat(context).hasSingleBean(JavaMailSender.class);
            assertThat(output).containsOnlyOnce(TOLD).contains("management.health.mail.enabled=true");
        });
    }

    @Test
    void aSenderWiredIntoABeanOfContexaIsStillOnlyContexasUse() {
        host.withUserConfiguration(CodeMailWired.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(registry(context).getContributor("mail")).isNull();
        });
    }

    @Test
    void anApplicationThatMailsKeepsItsMailHealth(CapturedOutput output) {
        host.withBean(HostMailingService.class).run(context -> {
            assertThat(context.getBean(HostMailingService.class).sender()).isNotNull();
            assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class);
            assertThat(output).doesNotContain(TOLD);
        });
    }

    @Test
    void anApplicationThatTakesTheSenderIntoAFieldKeepsItsMailHealth() {
        host.withBean(HostFieldMailingService.class).run(context -> {
            assertThat(context.getBean(HostFieldMailingService.class).sender()).isNotNull();
            assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class);
        });
    }

    @Test
    void anApplicationThatHandsTheSenderToABeanMethodKeepsItsMailHealth() {
        host.withUserConfiguration(MailOfTheApplication.class).run(context ->
                assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class));
    }

    @Test
    void anApplicationThatAsksForTheMailHealthKeepsIt(CapturedOutput output) {
        host.withPropertyValues("management.health.mail.enabled=true").run(context -> {
            assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class);
            assertThat(output).doesNotContain(TOLD);
        });
    }

    @Test
    void anApplicationThatTurnedTheMailHealthOffIsNothingToDo(CapturedOutput output) {
        host.withPropertyValues("management.health.mail.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(registry(context).getContributor("mail")).isNull();
            assertThat(output).doesNotContain(TOLD);
        });
    }

    /** Spring Boot refuses to start where a group names a health that does not exist, so a named one must stay. */
    @ParameterizedTest
    @ValueSource(strings = {
            "management.endpoint.health.group.ready.include=ping,mail",
            "management.endpoint.health.group.ready.include[0]=mail",
            "management.endpoint.health.group.ready.exclude=mail",
            "management.endpoint.health.group.live.include=ping;management.endpoint.health.group.ready.include=mail"})
    void aHealthGroupThatNamesMailKeepsItAndTheApplicationStarts(String settings) {
        host.withPropertyValues(settings.split(";")).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class);
        });
    }

    @Test
    void aHealthGroupOfEverythingLosesTheMailHealthAndStillStarts() {
        host.withPropertyValues("management.endpoint.health.group.ready.include=*").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(registry(context).getContributor("mail")).isNull();
        });
    }

    @Test
    void aSenderTheApplicationDeclaresIsItsOwnMail(CapturedOutput output) {
        host.withUserConfiguration(SenderOfTheApplication.class).run(context -> {
            assertThat(context).hasSingleBean(MailSender.class);
            assertThat(registry(context).getContributor("mail")).isInstanceOf(MailHealthIndicator.class);
            assertThat(output).doesNotContain(TOLD);
        });
    }

    @Test
    void aMailHealthTheApplicationWroteIsNotTouched(CapturedOutput output) {
        host.withUserConfiguration(MailHealthOfTheApplication.class).run(context -> {
            assertThat(registry(context).getContributor("mail")).isNotNull().isNotInstanceOf(MailHealthIndicator.class);
            assertThat(output).doesNotContain(TOLD);
        });
    }

    @Test
    void anApplicationWithoutAMailServerIsNothingToDo(CapturedOutput output) {
        health.withUserConfiguration(HostMailHealthConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(registry(context).getContributor("mail")).isNull();
            assertThat(registry(context).getContributor("ping")).isNotNull();
            assertThat(output).doesNotContain(TOLD);
        });
    }

    @Test
    void anApplicationWithoutAHealthEndpointStarts() {
        new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(MailSenderAutoConfiguration.class))
                .withPropertyValues("spring.mail.host=127.0.0.1", "spring.mail.port=1")
                .withUserConfiguration(HostMailHealthConfiguration.class).run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JavaMailSender.class);
                });
        assertThatCode(() -> new HostHealthWithoutContexaMail(null, new DefaultListableBeanFactory(), new MockEnvironment())
                .afterSingletonsInstantiated()).doesNotThrowAnyException();
    }

    @Test
    void anApplicationWithoutTheHealthOrTheMailClassesStarts() {
        WebApplicationContextRunner bare = new WebApplicationContextRunner().withUserConfiguration(HostMailHealthConfiguration.class);
        bare.withClassLoader(new FilteredClassLoader(HealthContributorRegistry.class)).run(context ->
                assertThat(context).hasNotFailed().doesNotHaveBean("contexaHostHealthWithoutContexaMail"));
        bare.withClassLoader(new FilteredClassLoader(MailSender.class)).run(context ->
                assertThat(context).hasNotFailed().doesNotHaveBean("contexaHostHealthWithoutContexaMail"));
    }

    /** What cannot be told apart counts as the application's, so that nothing of the application is taken away on a guess. */
    @Test
    void onlyContexasAndSpringBootsOwnBeansAreNotTheApplication() {
        assertThat(HostHealthWithoutContexaMail.ofTheApplication(MailHealthIndicator.class)).isFalse();
        assertThat(HostHealthWithoutContexaMail.ofTheApplication(CodeMail.class)).isFalse();
        assertThat(HostHealthWithoutContexaMail.ofTheApplication(HostMailingService.class)).isTrue();
        assertThat(HostHealthWithoutContexaMail.ofTheApplication(JavaMailSenderImpl.class)).isTrue();
        assertThat(HostHealthWithoutContexaMail.ofTheApplication(null)).isTrue();
        Object proxied = Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Runnable.class}, (proxy, method, args) -> null);
        assertThat(HostHealthWithoutContexaMail.ofTheApplication(proxied.getClass())).isTrue();
    }

    @Test
    void contexaBringsThisWithItsSecurityUnderEitherOwnership() {
        assertThat(AiSecurityConfiguration.class.getAnnotation(Import.class).value()).contains(HostMailHealthConfiguration.class);
    }

    private static HealthContributorRegistry registry(ApplicationContext context) {
        return context.getBean(HealthContributorRegistry.class);
    }

    record CodeMail(JavaMailSender sender) {
    }

    /** The way Contexa's own beans come to the sender: asked for when a mail is due, not wired in. */
    @Configuration(proxyBeanMethods = false)
    static class CodeMailAskedForWhenDue {

        @Bean
        CodeMail contexaCodeMail(ObjectProvider<JavaMailSender> senders) {
            return new CodeMail(senders.getIfUnique());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CodeMailWired {

        @Bean
        CodeMail contexaCodeMail(JavaMailSender sender) {
            return new CodeMail(sender);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class MailOfTheApplication {

        @Bean
        HostMailingService hostMailingService(JavaMailSender sender) {
            return new HostMailingService(sender);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class SenderOfTheApplication {

        @Bean
        JavaMailSenderImpl applicationMailSender() {
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            sender.setHost("127.0.0.1");
            sender.setPort(1);
            return sender;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class MailHealthOfTheApplication {

        @Bean
        HealthIndicator mailHealthIndicator() {
            return () -> Health.up().build();
        }
    }
}
