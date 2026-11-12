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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.util.StringUtils;

import java.util.Properties;

/**
 * The mail sender Contexa builds for itself where it owns the sign-in and the application has no single sender to take
 * (none, or several of them): made of the application's {@code spring.mail.*} settings the way Spring Boot makes the
 * sender it builds from them, so a limit or a login the application sets there applies to it as it applies to Boot's own.
 * A limit the settings do not set is Contexa's: without one a mail server that takes the connection and says nothing
 * keeps the thread that sends, one of Contexa's few, for as long as it likes, and no code is mailed until it lets go.
 * The sender is held by the e-mail service alone and is no bean: what the application injects by type, and what Spring
 * Boot's mail configuration decides, are as they were.
 */
@Slf4j
final class ContexaMailSenders {

    private static final String SETTINGS = "spring.mail";
    private static final String HOST = SETTINGS + ".host";

    /** How long the sender waits for the mail server to take the connection, where the settings name no limit. */
    static final String CONNECT_LIMIT_MS = "5000";

    /** How long the sender waits for the mail server to answer, or to take what is written, where the settings name no limit. */
    static final String ANSWER_LIMIT_MS = "10000";

    private ContexaMailSenders() {
    }

    /**
     * The sender {@code spring.mail.*} describes, or null: without {@code spring.mail.host} there is nothing to send with, and
     * settings that cannot be used leave no sender (a start that stops for the mail setting of an application whose own
     * senders it does not use would be Contexa's fault).
     */
    @Nullable
    static JavaMailSender fromSettings(Environment environment, ObjectProvider<SslBundles> sslBundles) {
        if (!StringUtils.hasText(environment.getProperty(HOST))) {
            return null;
        }
        try {
            MailProperties settings = Binder.get(environment).bind(SETTINGS, MailProperties.class).orElseGet(MailProperties::new);
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            apply(settings, sender, sslBundles.getIfAvailable());
            return sender;
        } catch (RuntimeException e) {
            log.error("[Contexa] The mail sender Contexa builds from spring.mail.* could not be created, so no one-time code "
                    + "can be mailed: {}", e.getMessage());
            return null;
        }
    }

    /** As Spring Boot applies the settings to the sender it builds from them (MailSenderPropertiesConfiguration). */
    private static void apply(MailProperties settings, JavaMailSenderImpl sender, @Nullable SslBundles sslBundles) {
        sender.setHost(settings.getHost());
        if (settings.getPort() != null) {
            sender.setPort(settings.getPort());
        }
        sender.setUsername(settings.getUsername());
        sender.setPassword(settings.getPassword());
        sender.setProtocol(settings.getProtocol());
        if (settings.getDefaultEncoding() != null) {
            sender.setDefaultEncoding(settings.getDefaultEncoding().name());
        }
        Properties javaMailProperties = new Properties();
        javaMailProperties.putAll(settings.getProperties());
        String protocol = StringUtils.hasLength(settings.getProtocol()) ? settings.getProtocol() : "smtp";
        javaMailProperties.putIfAbsent("mail." + protocol + ".connectiontimeout", CONNECT_LIMIT_MS);
        javaMailProperties.putIfAbsent("mail." + protocol + ".timeout", ANSWER_LIMIT_MS);
        javaMailProperties.putIfAbsent("mail." + protocol + ".writetimeout", ANSWER_LIMIT_MS);
        if (settings.getSsl().isEnabled()) {
            javaMailProperties.setProperty("mail." + protocol + ".ssl.enable", "true");
        }
        if (settings.getSsl().getBundle() != null) {
            if (sslBundles == null) {
                throw new IllegalStateException("spring.mail.ssl.bundle names a bundle and the application has no SSL bundles");
            }
            SslBundle bundle = sslBundles.getBundle(settings.getSsl().getBundle());
            javaMailProperties.put("mail." + protocol + ".ssl.socketFactory", bundle.createSslContext().getSocketFactory());
        }
        sender.setJavaMailProperties(javaMailProperties);
    }
}
