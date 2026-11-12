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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * A request that asks for a mail waits for the mail server no longer than Contexa's own limit, whatever limits the mail
 * sender has: an application's sender, or the settings Contexa's sender is made of, may have none, and a mail server
 * that takes the connection and says nothing then held the request thread for as long as it liked.
 */
class EmailServiceSendLimitTest {

    private static final int BURST = 60;

    private final List<AutoCloseable> opened = new CopyOnWriteArrayList<>();

    @AfterEach
    void close() throws Exception {
        for (AutoCloseable closeable : opened) {
            closeable.close();
        }
    }

    @Test
    @DisplayName("a mail server that takes the connection and says nothing, a sender without limits: the request is answered within Contexa's limit")
    void aSilentMailServerDoesNotHoldTheRequest() throws Exception {
        SilentServer server = new SilentServer();
        opened.add(server);
        JavaMailSenderImpl unlimited = new JavaMailSenderImpl();
        unlimited.setHost("127.0.0.1");
        unlimited.setPort(server.port());
        EmailService email = new EmailService(unlimited);
        opened.add(email::destroy);

        assertTimeoutPreemptively(Duration.ofSeconds(20), () ->
                assertThatThrownBy(() -> email.sendHtmlMessage("user@app.test", "subject", "<p>body</p>"))
                        .isInstanceOf(MailException.class));
        assertThat(server.connections()).as("the mail server was reached").isEqualTo(1);
    }

    @Test
    @DisplayName("a mail server that answers: the mail goes as before, on a mail thread of Contexa")
    void aMailIsSentOnAMailThread() {
        ScriptedSender sender = sender();
        EmailService email = service(sender, EmailService.SEND_WAIT);

        email.sendHtmlMessage("user@app.test", "Your code", "<p>body</p>");

        assertThat(sender.subjects()).containsExactly("Your code");
        assertThat(sender.recipients()).containsExactly("user@app.test");
        assertThat(sender.threads()).hasSize(1).allSatisfy(thread -> {
            assertThat(thread).isNotSameAs(Thread.currentThread());
            assertThat(thread.getName()).startsWith(EmailService.THREAD_NAME_PREFIX);
            assertThat(thread.isDaemon()).isTrue();
        });
    }

    @Test
    @DisplayName("what the mail sender throws reaches the request as it is")
    void theFailureOfTheSenderIsTheFailureOfTheRequest() {
        ScriptedSender sender = sender();
        EmailService email = service(sender, EmailService.SEND_WAIT);
        MailAuthenticationException refused = new MailAuthenticationException("the mail server refused the account");
        sender.failWith(refused);

        assertThatThrownBy(() -> email.sendHtmlMessage("user@app.test", "subject", "<p>body</p>")).isSameAs(refused);
    }

    @Test
    @DisplayName("each mail is sent with the class loader of the request that asked for it")
    void theMailIsSentWithTheClassLoaderOfTheRequest() {
        ScriptedSender sender = sender();
        EmailService email = service(sender, EmailService.SEND_WAIT);
        Thread request = Thread.currentThread();
        ClassLoader before = request.getContextClassLoader();
        ClassLoader first = new URLClassLoader(new URL[0], before);
        ClassLoader second = new URLClassLoader(new URL[0], before);
        try {
            request.setContextClassLoader(first);
            email.sendHtmlMessage("user@app.test", "one", "<p>body</p>");
            request.setContextClassLoader(second);
            email.sendHtmlMessage("user@app.test", "two", "<p>body</p>");
        } finally {
            request.setContextClassLoader(before);
        }

        assertThat(sender.classLoaders()).containsExactly(first, second);
    }

    @Test
    @DisplayName("every mail thread held by a mail server that says nothing: the next request is refused without asking the sender, and mail goes again once the threads are back")
    void aMailServerThatHoldsEveryThreadIsNotWaitedForAgain() throws Exception {
        ScriptedSender sender = sender();
        sender.hold();
        EmailService email = service(sender, Duration.ofMillis(300));

        for (int mail = 0; mail < EmailService.SENDERS; mail++) {
            assertThatThrownBy(() -> email.sendHtmlMessage("user@app.test", "held", "<p>body</p>"))
                    .isInstanceOf(MailSendException.class)
                    .hasMessageContaining("did not take the mail");
        }
        assertThat(sender.calls()).isEqualTo(EmailService.SENDERS);

        assertThatThrownBy(() -> email.sendHtmlMessage("user@app.test", "refused", "<p>body</p>"))
                .isInstanceOf(MailSendException.class)
                .hasMessageContaining("holds every mail thread");
        assertThat(sender.calls()).as("the sender was not asked again").isEqualTo(EmailService.SENDERS);

        sender.release();
        sendOnceTheThreadsAreBack(email, "after");

        assertThat(sender.subjects()).contains("after").doesNotContain("refused");
    }

    @Test
    @DisplayName("a burst while the mail server says nothing: as many as there are mail threads are tried, those that wait give up at the limit and are never mailed, the rest are refused at once")
    void aBurstWaitsNoLongerThanTheLimit() throws Exception {
        ScriptedSender sender = sender();
        sender.hold();
        Duration limit = Duration.ofSeconds(2);
        EmailService email = service(sender, limit);
        ExecutorService requests = Executors.newFixedThreadPool(BURST);
        opened.add(requests::shutdownNow);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> answers = new ArrayList<>();
        for (int request = 0; request < BURST; request++) {
            String subject = "burst-" + request;
            answers.add(requests.submit(() -> {
                start.await();
                try {
                    email.sendHtmlMessage("user@app.test", subject, "<p>body</p>");
                    return "sent";
                } catch (MailSendException e) {
                    return e.getMessage();
                }
            }));
        }

        long began = System.nanoTime();
        start.countDown();
        List<String> outcomes = new ArrayList<>();
        for (Future<String> answer : answers) {
            outcomes.add(answer.get(30, TimeUnit.SECONDS));
        }
        Duration took = Duration.ofNanos(System.nanoTime() - began);

        assertThat(took).as("no request waits much longer than the limit").isLessThan(limit.multipliedBy(4));
        assertThat(outcomes).doesNotContain("sent");
        assertThat(outcomes).filteredOn(outcome -> outcome.contains("did not take the mail"))
                .hasSize(EmailService.SENDERS + EmailService.WAITING);
        assertThat(outcomes).filteredOn(outcome -> outcome.contains("too many mails wait"))
                .hasSize(BURST - EmailService.SENDERS - EmailService.WAITING);
        assertThat(sender.calls()).isEqualTo(EmailService.SENDERS);

        sender.release();
        sendOnceTheThreadsAreBack(email, "after");

        assertThat(sender.calls()).as("a mail that gave up while it waited is not mailed late")
                .isEqualTo(EmailService.SENDERS + 1);
    }

    @Test
    @DisplayName("a request interrupted while its mail is sent: answered at once and still interrupted")
    void anInterruptedRequestIsAnsweredAtOnce() throws Exception {
        ScriptedSender sender = sender();
        sender.hold();
        EmailService email = service(sender, Duration.ofSeconds(60));
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicBoolean stillInterrupted = new AtomicBoolean();
        Thread request = new Thread(() -> {
            try {
                email.sendHtmlMessage("user@app.test", "subject", "<p>body</p>");
            } catch (Throwable failure) {
                thrown.set(failure);
            }
            stillInterrupted.set(Thread.currentThread().isInterrupted());
        }, "request");
        request.setDaemon(true);
        request.start();
        assertThat(sender.asked(1)).as("the mail reached the sender").isTrue();

        request.interrupt();
        request.join(TimeUnit.SECONDS.toMillis(10));

        assertThat(request.isAlive()).isFalse();
        assertThat(thrown.get()).isInstanceOf(MailSendException.class).hasMessageContaining("interrupted");
        assertThat(stillInterrupted).isTrue();
    }

    @Test
    @DisplayName("the mail threads end with the service")
    void theMailThreadsEndWithTheService() throws Exception {
        ScriptedSender sender = sender();
        EmailService email = service(sender, EmailService.SEND_WAIT);
        email.sendHtmlMessage("user@app.test", "subject", "<p>body</p>");
        Thread mailThread = sender.threads().get(0);

        email.destroy();
        mailThread.join(TimeUnit.SECONDS.toMillis(10));

        assertThat(mailThread.isAlive()).isFalse();
    }

    @Test
    @DisplayName("no mail sender: no mail, and nothing to end")
    void withoutASenderThereIsNothingToEnd() {
        EmailService email = new EmailService(null);

        assertThat(email.isMailSenderConfigured()).isFalse();
        assertThatCode(email::destroy).doesNotThrowAnyException();
    }

    private EmailService service(JavaMailSender sender, Duration wait) {
        EmailService email = new EmailService(sender, wait);
        opened.add(email::destroy);
        return email;
    }

    private ScriptedSender sender() {
        ScriptedSender sender = new ScriptedSender();
        opened.add(sender::release);
        return sender;
    }

    /** The threads a held sender let go come back a moment after it did. */
    private static void sendOnceTheThreadsAreBack(EmailService email, String subject) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (true) {
            try {
                email.sendHtmlMessage("user@app.test", subject, "<p>body</p>");
                return;
            } catch (MailSendException refused) {
                if (System.nanoTime() > deadline) {
                    throw refused;
                }
                Thread.sleep(20);
            }
        }
    }

    /** A sender that does what the test tells it instead of reaching a mail server. */
    private static final class ScriptedSender extends JavaMailSenderImpl {

        private final List<String> subjects = new CopyOnWriteArrayList<>();
        private final List<String> recipients = new CopyOnWriteArrayList<>();
        private final List<Thread> threads = new CopyOnWriteArrayList<>();
        private final List<ClassLoader> classLoaders = new CopyOnWriteArrayList<>();
        private final AtomicInteger calls = new AtomicInteger();
        private final Semaphore asked = new Semaphore(0);
        private final CountDownLatch released = new CountDownLatch(1);
        private volatile boolean holding;
        private volatile RuntimeException failure;

        @Override
        public void send(MimeMessage... messages) {
            calls.incrementAndGet();
            threads.add(Thread.currentThread());
            classLoaders.add(Thread.currentThread().getContextClassLoader());
            asked.release();
            if (holding) {
                awaitAsASocketDoes(released);
            }
            if (failure != null) {
                throw failure;
            }
            for (MimeMessage message : messages) {
                try {
                    subjects.add(message.getSubject());
                    recipients.add(message.getAllRecipients()[0].toString());
                } catch (MessagingException e) {
                    throw new IllegalStateException(e);
                }
            }
        }

        /** Every mail from now on is held as a mail server that says nothing holds it, until {@link #release()}. */
        void hold() {
            this.holding = true;
        }

        void release() {
            released.countDown();
        }

        void failWith(RuntimeException failure) {
            this.failure = failure;
        }

        boolean asked(int mails) throws InterruptedException {
            return asked.tryAcquire(mails, 10, TimeUnit.SECONDS);
        }

        int calls() {
            return calls.get();
        }

        List<String> subjects() {
            return subjects;
        }

        List<String> recipients() {
            return recipients;
        }

        List<Thread> threads() {
            return threads;
        }

        List<ClassLoader> classLoaders() {
            return classLoaders;
        }

        /** A thread that reads from a socket is not woken by an interrupt. */
        private static void awaitAsASocketDoes(CountDownLatch latch) {
            boolean interrupted = false;
            while (true) {
                try {
                    latch.await();
                    break;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** A mail server that takes every connection and never says a word. */
    private static final class SilentServer implements AutoCloseable {

        private final ServerSocket listening;
        private final List<Socket> taken = new CopyOnWriteArrayList<>();

        SilentServer() throws IOException {
            this.listening = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread accepting = new Thread(() -> {
                while (!listening.isClosed()) {
                    try {
                        taken.add(listening.accept());
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "silent-mail-server");
            accepting.setDaemon(true);
            accepting.start();
        }

        int port() {
            return listening.getLocalPort();
        }

        int connections() {
            return taken.size();
        }

        @Override
        public void close() throws IOException {
            listening.close();
            for (Socket socket : taken) {
                socket.close();
            }
        }
    }
}
