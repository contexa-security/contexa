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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mail sender is the application's own: the mail of a sign-in is sent with it, and so is the application's other
 * mail. What Contexa writes into it bounds that other mail as well, so nothing is written unless the application asks.
 */
class EmailServiceMailSettingsTest {

    @Test
    @DisplayName("the application's mail sender keeps its settings when the application asked for no limit")
    void theSenderIsLeftAsTheApplicationConfiguredIt() {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        AuthContextProperties.OttSettings settings = new AuthContextProperties.OttSettings();

        new EmailService(sender);
        new EmailService(sender, settings.getEmailMaxConcurrentSends(), settings.getEmailSendWaitSeconds(),
                settings.getEmailSmtpTimeoutSeconds());

        assertThat(settings.getEmailSmtpTimeoutSeconds()).isZero();
        assertThat(sender.getJavaMailProperties()).isEmpty();
    }

    @Test
    @DisplayName("a limit the application asks for is set where its mail settings name none, and its own values stay")
    void aLimitTheApplicationAsksForIsSet() {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        Properties own = new Properties();
        own.setProperty("mail.smtp.timeout", "45000");
        sender.setJavaMailProperties(own);

        new EmailService(sender, EmailService.DEFAULT_MAX_CONCURRENT_SENDS, EmailService.DEFAULT_SEND_WAIT_SECONDS, 7);

        Properties after = sender.getJavaMailProperties();
        assertThat(after.getProperty("mail.smtp.timeout")).isEqualTo("45000");
        assertThat(after.getProperty("mail.smtp.connectiontimeout")).isEqualTo("7000");
        assertThat(after.getProperty("mail.smtp.writetimeout")).isEqualTo("7000");
        assertThat(after.getProperty("mail.smtps.timeout")).isEqualTo("7000");
    }
}
