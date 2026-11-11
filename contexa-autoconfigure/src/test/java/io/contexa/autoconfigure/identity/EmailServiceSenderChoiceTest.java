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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Which mail sender the e-mail service holds. Where the application signs its users in (SANDBOX, HOST_OWNED) it is the
 * application's one sender, as before. Where Contexa signs them in (FULL, CONTEXA_OWNED) it is the same sender when the
 * application has one, and otherwise a sender Contexa builds from spring.mail.*, held by the service alone: the
 * application's beans, and what it injects by type, are as they were.
 */
class EmailServiceSenderChoiceTest {

    private static final String FULL = "contexa.ai.security.mode=FULL";
    private static final String SANDBOX = "contexa.ai.security.mode=SANDBOX";

    private final ApplicationContextRunner contexts = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdentityServiceAutoConfiguration.class))
            .withUserConfiguration(Collaborators.class);

    @Configuration(proxyBeanMethods = false)
    static class Collaborators {

        @Bean
        PlatformConfig platformConfig() {
            return mock(PlatformConfig.class);
        }

        @Bean
        AuthContextProperties authContextProperties() {
            return new AuthContextProperties();
        }

        /** What the MFA endpoint of an application whose sign-in Contexa owns is built on. */
        @Bean
        MfaStateMachineIntegrator mfaStateMachineIntegrator() {
            return mock(MfaStateMachineIntegrator.class);
        }

        @Bean("contexaJdbcTemplate")
        JdbcTemplate contexaJdbcTemplate() {
            return mock(JdbcTemplate.class);
        }

        @Bean("contexaTransactionTemplate")
        TransactionTemplate contexaTransactionTemplate() {
            return new TransactionTemplate(mock(PlatformTransactionManager.class));
        }
    }

    @Test
    @DisplayName("FULL, one sender of the application: the code goes by that sender, the same object, whether or not spring.mail.host is set")
    void theApplicationsOneSenderIsTheOneUsed() throws Exception {
        int dead = deadPort();
        for (String[] settings : new String[][] {{FULL}, {FULL, "spring.mail.host=127.0.0.1", "spring.mail.port=" + dead}}) {
            Mailbox application = new Mailbox();
            contexts.withBean("applicationMail", JavaMailSender.class, application::sender)
                    .withPropertyValues(settings)
                    .run(context -> {
                        EmailService email = context.getBean(EmailService.class);

                        assertThat(email.isMailSenderConfigured()).isTrue();
                        email.sendHtmlMessage("admin@app.test", "subject", "<p>body</p>");

                        assertThat(application.sent()).as("the application's sender was asked to send, once").isEqualTo(1);
                        assertThat(context.getBeansOfType(JavaMailSender.class).keySet()).containsExactly("applicationMail");
                    });
        }
    }

    @Test
    @DisplayName("SANDBOX: the application's one sender is used, and several or none is no sender, with spring.mail.host set or not")
    void whereTheApplicationSignsInNothingChanged() throws Exception {
        int dead = deadPort();
        String[] host = {"spring.mail.host=127.0.0.1", "spring.mail.port=" + dead};
        for (String mode : List.of(SANDBOX, "contexa.bridge.ownership=HOST_OWNED")) {
            Mailbox one = new Mailbox();
            contexts.withBean("applicationMail", JavaMailSender.class, one::sender).withPropertyValues(mode).withPropertyValues(host)
                    .run(context -> {
                        context.getBean(EmailService.class).sendHtmlMessage("user@app.test", "subject", "<p>body</p>");
                        assertThat(one.sent()).isEqualTo(1);
                    });

            Mailbox first = new Mailbox();
            Mailbox second = new Mailbox();
            for (String[] settings : new String[][] {{mode}, {mode, host[0], host[1]}}) {
                contexts.withBean("mailA", JavaMailSender.class, first::sender)
                        .withBean("mailB", JavaMailSender.class, second::sender)
                        .withPropertyValues(settings)
                        .run(context -> assertThat(context.getBean(EmailService.class).isMailSenderConfigured())
                                .as("several senders of the application: Contexa does not choose, and builds none, in " + mode).isFalse());
            }
            contexts.withPropertyValues(mode).withPropertyValues(host)
                    .run(context -> assertThat(context.getBean(EmailService.class).isMailSenderConfigured())
                            .as("no sender of the application, none made, in " + mode).isFalse());
            assertThat(first.sent() + second.sent()).isZero();
        }
        // no mode at all: Contexa is not told it owns the sign-in
        contexts.withBean("mailA", JavaMailSender.class, new Mailbox()::sender)
                .withBean("mailB", JavaMailSender.class, new Mailbox()::sender)
                .withPropertyValues(host)
                .run(context -> assertThat(context.getBean(EmailService.class).isMailSenderConfigured()).isFalse());
    }

    @Test
    @DisplayName("FULL, several senders of the application and spring.mail.host: Contexa builds its own, uses none of theirs, and adds no bean")
    void severalSendersOfTheApplicationAreLeftAloneAndContexaMailsWithItsOwn() throws Exception {
        int dead = deadPort();
        for (String mode : List.of(FULL, "contexa.bridge.ownership=CONTEXA_OWNED")) {
            Mailbox first = new Mailbox();
            Mailbox second = new Mailbox();
            contexts.withBean("mailA", JavaMailSender.class, first::sender)
                    .withBean("mailB", JavaMailSender.class, second::sender)
                    .withPropertyValues(mode, "spring.mail.host=127.0.0.1", "spring.mail.port=" + dead,
                            "spring.mail.properties.mail.smtp.connectiontimeout=2000")
                    .run(context -> {
                        EmailService email = context.getBean(EmailService.class);

                        assertThat(email.isMailSenderConfigured()).as("in " + mode).isTrue();
                        assertThatThrownBy(() -> email.sendHtmlMessage("admin@app.test", "subject", "<p>body</p>"))
                                .as("the sender Contexa made reached for spring.mail.host, a port nothing listens on")
                                .isInstanceOf(MailSendException.class);
                        assertThat(first.sent() + second.sent()).as("none of the application's senders was asked").isZero();
                        assertThat(context.getBeansOfType(JavaMailSender.class).keySet())
                                .as("Contexa's sender is held by the service: what the application injects by type is as it was")
                                .containsExactlyInAnyOrder("mailA", "mailB");
                        assertThat(context.getBeanProvider(JavaMailSender.class).getIfUnique()).isNull();
                    });
        }
    }

    @Test
    @DisplayName("FULL, several senders of the application and no spring.mail.host: no sender, as before")
    void severalSendersAndNoHostLeaveNoSender() {
        contexts.withBean("mailA", JavaMailSender.class, new Mailbox()::sender)
                .withBean("mailB", JavaMailSender.class, new Mailbox()::sender)
                .withPropertyValues(FULL, "spring.mail.port=2525", "spring.mail.username=sender")
                .run(context -> assertThat(context.getBean(EmailService.class).isMailSenderConfigured()).isFalse());
    }

    @Test
    @DisplayName("FULL, none of the application's and no spring.mail.host: no sender, as before; with the host, a sender from it")
    void noSenderOfTheApplicationAndTheHostDecides() {
        contexts.withPropertyValues(FULL)
                .run(context -> assertThat(context.getBean(EmailService.class).isMailSenderConfigured()).isFalse());
        contexts.withPropertyValues(FULL, "spring.mail.host=127.0.0.1")
                .run(context -> assertThat(context.getBean(EmailService.class).isMailSenderConfigured()).isTrue());
    }

    @Test
    @DisplayName("FULL, several senders with one of them @Primary: that one is the application's sender, as Spring resolves it")
    void aPrimarySenderIsStillTheApplicationsOne() {
        Mailbox primary = new Mailbox();
        Mailbox other = new Mailbox();
        contexts.withBean("mailA", JavaMailSender.class, primary::sender, definition -> definition.setPrimary(true))
                .withBean("mailB", JavaMailSender.class, other::sender)
                .withPropertyValues(FULL, "spring.mail.host=127.0.0.1", "spring.mail.port=1")
                .run(context -> {
                    context.getBean(EmailService.class).sendHtmlMessage("admin@app.test", "subject", "<p>body</p>");

                    assertThat(primary.sent()).isEqualTo(1);
                    assertThat(other.sent()).isZero();
                });
    }

    @Test
    @DisplayName("settings of spring.mail.* that cannot be used do not stop the start: the service has no sender")
    void unusableSettingsDoNotStopTheStart() {
        contexts.withBean("mailA", JavaMailSender.class, new Mailbox()::sender)
                .withBean("mailB", JavaMailSender.class, new Mailbox()::sender)
                .withPropertyValues(FULL, "spring.mail.host=127.0.0.1", "spring.mail.port=not-a-number")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(EmailService.class).isMailSenderConfigured()).isFalse();
                });
    }

    private static int deadPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /** A mail sender of an application that makes its messages as Spring's does and keeps what it is asked to send. */
    private static final class Mailbox implements InvocationHandler {

        private final JavaMailSenderImpl maker = new JavaMailSenderImpl();
        private final List<String> sends = new CopyOnWriteArrayList<>();

        JavaMailSender sender() {
            return (JavaMailSender) Proxy.newProxyInstance(JavaMailSender.class.getClassLoader(),
                    new Class<?>[] {JavaMailSender.class}, this);
        }

        /** How many messages the sender was asked to send. */
        int sent() {
            return sends.size();
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            if (method.getName().equals("send")) {
                sends.add(method.getName());
                return null;
            }
            try {
                return method.invoke(maker, arguments);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }
    }
}
