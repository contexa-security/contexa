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
import org.springframework.beans.factory.DisposableBean;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Mails for Contexa with the one mail sender it was given. A thread of Contexa's own sends the mail and the request
 * that asked for it waits for the outcome no longer than {@link #SEND_WAIT}: a sender may have no limit of its own (an
 * application's, or spring.mail.* without timeouts), and a mail server that takes the connection and says nothing
 * then held the request thread, the application's, for as long as it liked. A mail that is not sent in that time is a
 * mail that failed, as one the mail server refused is. Once a mail server that does not answer holds every mail thread,
 * a request is refused at once and waits for nothing, until a thread comes back.
 */
public class EmailService implements DisposableBean {

    /**
     * How long a request waits for its mail. A mail server on the same network takes the mail in milliseconds and one
     * across the internet in a second or two.
     */
    static final Duration SEND_WAIT = Duration.ofSeconds(5);

    /** How many mails are sent at once, and so how many threads a mail server that does not answer can hold. */
    static final int SENDERS = 8;

    /** How many mails wait for a thread; one more is refused, and none waits longer than {@link #SEND_WAIT}. */
    static final int WAITING = 32;

    static final String THREAD_NAME_PREFIX = "contexa-mail-";

    private final JavaMailSender mailSender;
    private final Duration wait;
    private final ThreadPoolExecutor senders;

    /** The mail threads a request gave up on and the mail server still holds. */
    private final AtomicInteger held = new AtomicInteger();

    public EmailService(JavaMailSender mailSender) {
        this(mailSender, SEND_WAIT);
    }

    EmailService(JavaMailSender mailSender, Duration wait) {
        this.mailSender = mailSender;
        this.wait = wait;
        this.senders = mailSender == null ? null : senders();
    }

    public boolean isMailSenderConfigured() {
        return this.mailSender != null;
    }

    public void sendHtmlMessage(String to, String subject, String htmlBody) {
        MimeMessage message;
        try {
            message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom("no-reply@ctxa.ai");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlBody, true);
        } catch (MessagingException e) {
            throw new RuntimeException("Email sending failed", e);
        }
        if (held.get() >= SENDERS) {
            throw new MailSendException("Email sending failed: the mail server holds every mail thread of Contexa");
        }
        Sending sending = new Sending(message, Thread.currentThread().getContextClassLoader());
        try {
            senders.execute(sending);
        } catch (RejectedExecutionException e) {
            throw new MailSendException("Email sending failed: too many mails wait to be sent", e);
        }
        sending.await();
    }

    @Override
    public void destroy() {
        if (senders != null) {
            senders.shutdownNow();
        }
    }

    /** Threads that are made when a mail is to be sent and end a minute after the last one. */
    private static ThreadPoolExecutor senders() {
        AtomicInteger number = new AtomicInteger();
        ThreadPoolExecutor senders = new ThreadPoolExecutor(SENDERS, SENDERS, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(WAITING), task -> {
                    Thread thread = new Thread(task, THREAD_NAME_PREFIX + number.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                });
        senders.allowCoreThreadTimeOut(true);
        return senders;
    }

    /** One mail on its way, and the request that waits for it. */
    private final class Sending implements Runnable {

        private static final int QUEUED = 0;
        private static final int SENDING = 1;
        private static final int DONE = 2;
        private static final int GIVEN_UP = 3;
        private static final int HELD = 4;

        private final MimeMessage message;
        private final ClassLoader requestClassLoader;
        private final AtomicInteger state = new AtomicInteger(QUEUED);
        private final CompletableFuture<Void> outcome = new CompletableFuture<>();

        Sending(MimeMessage message, ClassLoader requestClassLoader) {
            this.message = message;
            this.requestClassLoader = requestClassLoader;
        }

        @Override
        public void run() {
            if (!state.compareAndSet(QUEUED, SENDING)) {
                // the request gave up while the mail waited for a thread: nothing is mailed late
                return;
            }
            Thread thread = Thread.currentThread();
            ClassLoader own = thread.getContextClassLoader();
            // the mail library finds its providers and content handlers by the class loader of the thread, the request's until now
            thread.setContextClassLoader(requestClassLoader);
            try {
                mailSender.send(message);
                outcome.complete(null);
            } catch (Throwable failure) {
                outcome.completeExceptionally(failure);
            } finally {
                thread.setContextClassLoader(own);
                if (!state.compareAndSet(SENDING, DONE)) {
                    held.decrementAndGet();
                }
            }
        }

        void await() {
            try {
                outcome.get(wait.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                giveUp();
                throw new MailSendException("Email sending failed: the mail server did not take the mail in "
                        + wait.toMillis() + " ms");
            } catch (InterruptedException e) {
                giveUp();
                Thread.currentThread().interrupt();
                throw new MailSendException("Email sending failed: interrupted while the mail was sent", e);
            } catch (ExecutionException e) {
                Throwable failure = e.getCause();
                if (failure instanceof RuntimeException unchecked) {
                    throw unchecked;
                }
                if (failure instanceof Error error) {
                    throw error;
                }
                throw new MailSendException("Email sending failed", failure);
            }
        }

        private void giveUp() {
            if (state.compareAndSet(QUEUED, GIVEN_UP)) {
                senders.remove(this);
            } else if (state.compareAndSet(SENDING, HELD)) {
                held.incrementAndGet();
            }
        }
    }
}
