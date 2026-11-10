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

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.util.List;
import java.util.Properties;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Sends the mails of a sign-in on the thread of the request that asked for them, so a mail server that answers slowly
 * holds requests. Two limits keep that from taking every request thread of the application for as long as the server
 * likes: each step of the SMTP conversation ends after a time when the application's mail settings name none, and only
 * so many mails are being sent at once, a request beyond them waiting a short while for a place and then failing as an
 * undelivered mail does.
 */
public class EmailService {

    public static final int DEFAULT_MAX_CONCURRENT_SENDS = 64;
    public static final int DEFAULT_SEND_WAIT_SECONDS = 5;
    public static final int DEFAULT_SMTP_TIMEOUT_SECONDS = 10;

    private final JavaMailSender mailSender;
    private final Semaphore places;
    private final long placeWaitMillis;

    public EmailService(JavaMailSender mailSender) {
        this(mailSender, DEFAULT_MAX_CONCURRENT_SENDS, DEFAULT_SEND_WAIT_SECONDS, DEFAULT_SMTP_TIMEOUT_SECONDS);
    }

    /**
     * @param maxConcurrentSends the mails being sent at one time; below one it is one
     * @param sendWaitSeconds how long a request waits for a place among them before it fails; below zero it is zero
     * @param smtpTimeoutSeconds the limit of the connect, the read and the write of the SMTP conversation where the
     * application's mail settings name none; zero or less leaves the settings as they are
     */
    public EmailService(JavaMailSender mailSender, int maxConcurrentSends, int sendWaitSeconds, int smtpTimeoutSeconds) {
        this.mailSender = mailSender;
        this.places = new Semaphore(Math.max(1, maxConcurrentSends));
        this.placeWaitMillis = TimeUnit.SECONDS.toMillis(Math.max(0, sendWaitSeconds));
        limitSmtpSteps(mailSender, smtpTimeoutSeconds);
    }

    /** JavaMail waits without end where no timeout is set; a value the application set is kept. */
    private static void limitSmtpSteps(JavaMailSender sender, int seconds) {
        if (seconds <= 0 || !(sender instanceof JavaMailSenderImpl configured)) {
            return;
        }
        Properties settings = configured.getJavaMailProperties();
        String millis = String.valueOf(TimeUnit.SECONDS.toMillis(seconds));
        boolean changed = false;
        for (String protocol : List.of("smtp", "smtps")) {
            for (String step : List.of("connectiontimeout", "timeout", "writetimeout")) {
                changed |= settings.putIfAbsent("mail." + protocol + "." + step, millis) == null;
            }
        }
        if (changed) {
            // setting them again makes the sender build its mail session anew with the limits
            configured.setJavaMailProperties(settings);
        }
    }

    public boolean isMailSenderConfigured() {
        return this.mailSender != null;
    }

    public void sendHtmlMessage(String to, String subject, String htmlBody) {
        if (!takePlace()) {
            throw new MailSendException("The mail server is not keeping up: " + (places.getQueueLength() + 1)
                    + " mails wait behind the ones being sent, and this one waited " + placeWaitMillis + " ms for a place");
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom("no-reply@ctxa.ai");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlBody, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Email sending failed", e);
        } finally {
            places.release();
        }
    }

    private boolean takePlace() {
        try {
            return places.tryAcquire(placeWaitMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}

