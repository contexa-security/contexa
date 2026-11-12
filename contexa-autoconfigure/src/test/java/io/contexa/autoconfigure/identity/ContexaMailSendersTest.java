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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The sender Contexa builds where it owns the sign-in and the application has none to take: made from spring.mail.* as
 * Spring Boot makes the sender it builds from them, so the limits and the login an application sets there apply to it
 * as they apply to Boot's own. A limit the settings do not set is Contexa's: its sender never waits without one.
 */
class ContexaMailSendersTest {

    private final ApplicationContextRunner boot = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MailSenderAutoConfiguration.class));

    @Test
    @DisplayName("from the settings Spring Boot reads for its own sender, Contexa's has the same host, port, login, protocol, encoding and mail properties, and nothing more than the limits the settings left out")
    void theSenderIsTheOneSpringBootBuildsFromTheSameSettings() {
        for (String[] settings : new String[][] {
                {"spring.mail.host=smtp.example.test"},
                {"spring.mail.host=smtp.example.test", "spring.mail.port=2525", "spring.mail.username=sender",
                        "spring.mail.password=secret", "spring.mail.protocol=smtps", "spring.mail.default-encoding=ISO-8859-1"},
                {"spring.mail.host=smtp.example.test", "spring.mail.properties.mail.smtp.auth=true",
                        "spring.mail.properties.mail.smtp.starttls.enable=true",
                        "spring.mail.properties.mail.smtp.connectiontimeout=3000",
                        "spring.mail.properties.mail.smtp.timeout=4000", "spring.mail.properties.mail.smtp.writetimeout=5000"},
                {"spring.mail.host=smtp.example.test", "spring.mail.ssl.enabled=true"},
                {"spring.mail.host=smtp.example.test", "spring.mail.protocol=smtps", "spring.mail.ssl.enabled=true"}}) {
            boot.withPropertyValues(settings).run(context -> {
                JavaMailSenderImpl theirs = context.getBean(JavaMailSenderImpl.class);

                JavaMailSender ours = ContexaMailSenders.fromSettings(environmentOf(settings), context.getBeanProvider(SslBundles.class));

                assertThat(ours).isInstanceOfSatisfying(JavaMailSenderImpl.class, sender -> {
                    assertThat(sender).isNotSameAs(theirs);
                    assertThat(sender.getHost()).isEqualTo(theirs.getHost());
                    assertThat(sender.getPort()).isEqualTo(theirs.getPort());
                    assertThat(sender.getUsername()).isEqualTo(theirs.getUsername());
                    assertThat(sender.getPassword()).isEqualTo(theirs.getPassword());
                    assertThat(sender.getProtocol()).isEqualTo(theirs.getProtocol());
                    assertThat(sender.getDefaultEncoding()).isEqualTo(theirs.getDefaultEncoding());
                    Properties properties = sender.getJavaMailProperties();
                    assertThat(properties).containsAllEntriesOf(theirs.getJavaMailProperties());
                    String protocol = theirs.getProtocol() == null ? "smtp" : theirs.getProtocol();
                    assertThat(properties.stringPropertyNames())
                            .filteredOn(name -> !theirs.getJavaMailProperties().containsKey(name))
                            .as("what Contexa's sender has and Spring Boot's has not: the limits the settings left out")
                            .allMatch(name -> name.equals("mail." + protocol + ".connectiontimeout")
                                    || name.equals("mail." + protocol + ".timeout")
                                    || name.equals("mail." + protocol + ".writetimeout"));
                });
            });
        }
    }

    @Test
    @DisplayName("the limits spring.mail.properties sets are Contexa's sender's limits too, a zero that says 'no limit' among them")
    void theLimitsOfTheSettingsAreTheLimitsOfTheSender() {
        JavaMailSenderImpl limited = (JavaMailSenderImpl) ContexaMailSenders.fromSettings(environmentOf(
                "spring.mail.host=smtp.example.test", "spring.mail.properties.mail.smtp.connectiontimeout=3000",
                "spring.mail.properties.mail.smtp.timeout=4000", "spring.mail.properties.mail.smtp.writetimeout=0"), none());
        Properties properties = limited.getJavaMailProperties();
        assertThat(properties.getProperty("mail.smtp.connectiontimeout")).isEqualTo("3000");
        assertThat(properties.getProperty("mail.smtp.timeout")).isEqualTo("4000");
        assertThat(properties.getProperty("mail.smtp.writetimeout")).isEqualTo("0");
    }

    @Test
    @DisplayName("a limit the settings do not set is Contexa's: its sender never waits for a mail server without one")
    void aLimitTheSettingsDoNotSetIsContexas() {
        Properties none = ((JavaMailSenderImpl) ContexaMailSenders.fromSettings(
                environmentOf("spring.mail.host=smtp.example.test"), none())).getJavaMailProperties();
        assertThat(none.getProperty("mail.smtp.connectiontimeout")).isEqualTo(ContexaMailSenders.CONNECT_LIMIT_MS);
        assertThat(none.getProperty("mail.smtp.timeout")).isEqualTo(ContexaMailSenders.ANSWER_LIMIT_MS);
        assertThat(none.getProperty("mail.smtp.writetimeout")).isEqualTo(ContexaMailSenders.ANSWER_LIMIT_MS);
        assertThat(Integer.parseInt(ContexaMailSenders.CONNECT_LIMIT_MS)).isBetween(1, 30_000);
        assertThat(Integer.parseInt(ContexaMailSenders.ANSWER_LIMIT_MS)).isBetween(1, 30_000);

        Properties one = ((JavaMailSenderImpl) ContexaMailSenders.fromSettings(environmentOf(
                "spring.mail.host=smtp.example.test", "spring.mail.properties.mail.smtp.timeout=4000"), none())).getJavaMailProperties();
        assertThat(one.getProperty("mail.smtp.timeout")).as("the one the settings set").isEqualTo("4000");
        assertThat(one.getProperty("mail.smtp.connectiontimeout")).isEqualTo(ContexaMailSenders.CONNECT_LIMIT_MS);
        assertThat(one.getProperty("mail.smtp.writetimeout")).isEqualTo(ContexaMailSenders.ANSWER_LIMIT_MS);

        Properties secure = ((JavaMailSenderImpl) ContexaMailSenders.fromSettings(environmentOf(
                "spring.mail.host=smtp.example.test", "spring.mail.protocol=smtps",
                "spring.mail.properties.mail.smtp.timeout=4000"), none())).getJavaMailProperties();
        assertThat(secure.getProperty("mail.smtps.connectiontimeout"))
                .as("the mail library reads the limits of the protocol it sends with").isEqualTo(ContexaMailSenders.CONNECT_LIMIT_MS);
        assertThat(secure.getProperty("mail.smtps.timeout"))
                .as("a limit set for smtp is no limit for smtps").isEqualTo(ContexaMailSenders.ANSWER_LIMIT_MS);
        assertThat(secure.getProperty("mail.smtps.writetimeout")).isEqualTo(ContexaMailSenders.ANSWER_LIMIT_MS);
        assertThat(secure.getProperty("mail.smtp.timeout")).isEqualTo("4000");
    }

    @Test
    @DisplayName("without spring.mail.host there is no sender: another mail setting does not make one")
    void withoutAHostThereIsNoSender() {
        assertThat(ContexaMailSenders.fromSettings(environmentOf(), none())).isNull();
        assertThat(ContexaMailSenders.fromSettings(environmentOf("spring.mail.host="), none())).isNull();
        assertThat(ContexaMailSenders.fromSettings(environmentOf("spring.mail.host=  "), none())).isNull();
        assertThat(ContexaMailSenders.fromSettings(environmentOf("spring.mail.port=2525", "spring.mail.username=sender",
                "spring.mail.jndi-name=mail/Session"), none())).isNull();
    }

    @Test
    @DisplayName("settings that cannot be read give no sender and do not stop the application")
    void settingsThatCannotBeReadGiveNoSender() {
        assertThat(ContexaMailSenders.fromSettings(environmentOf("spring.mail.host=smtp.example.test",
                "spring.mail.port=not-a-number"), none())).isNull();
        assertThat(ContexaMailSenders.fromSettings(environmentOf("spring.mail.host=smtp.example.test",
                "spring.mail.ssl.bundle=mail"), none()))
                .as("a bundle is named and the application has no bundles").isNull();
    }

    private static MockEnvironment environmentOf(String... settings) {
        MockEnvironment environment = new MockEnvironment();
        for (String setting : settings) {
            int equals = setting.indexOf('=');
            environment.setProperty(setting.substring(0, equals), setting.substring(equals + 1));
        }
        return environment;
    }

    /** An application without bundles of its own. */
    private static ObjectProvider<SslBundles> none() {
        return new DefaultListableBeanFactory().getBeanProvider(SslBundles.class);
    }
}
