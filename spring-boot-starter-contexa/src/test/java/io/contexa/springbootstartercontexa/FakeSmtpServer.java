/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A mail server of the test's own on one loopback port. It answers as a mail server does, cuts every connection as soon
 * as it is made, takes connections and never says a word, or is down (nothing listens on the port). The port stays the
 * same throughout, as the application's mail settings name one port.
 */
final class FakeSmtpServer implements AutoCloseable {

    enum Mode { ANSWERS, CUTS, SILENT, DOWN }

    private static final String LINE_END = "\r\n";

    private final int port;
    private final List<String> messages = new CopyOnWriteArrayList<>();
    private final List<Socket> held = new CopyOnWriteArrayList<>();
    private final AtomicInteger connections = new AtomicInteger();
    private volatile Mode mode = Mode.ANSWERS;
    private ServerSocket listener;

    FakeSmtpServer() throws IOException {
        this.listener = bind(0);
        this.port = listener.getLocalPort();
        accept(listener);
    }

    int port() {
        return port;
    }

    /** The connections the server took since it started: a fault that cuts or keeps silent was reached when this grows. */
    int connections() {
        return connections.get();
    }

    /** The messages taken, as they came over the wire. */
    List<String> messages() {
        return List.copyOf(messages);
    }

    synchronized void mode(Mode next) throws IOException {
        releaseHeld();
        if (next == Mode.DOWN) {
            if (listener != null) {
                listener.close();
                listener = null;
            }
        } else if (listener == null) {
            listener = bind(port);
            accept(listener);
        }
        mode = next;
    }

    /** Whether a connection to the port is refused, which is what a stopped mail server is. */
    boolean refuses() {
        try (Socket probe = new Socket()) {
            probe.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2_000);
            return false;
        } catch (IOException refused) {
            return true;
        }
    }

    /** The body of a single-part message as a mail client reads it: base64 and quoted-printable are decoded. */
    static String body(String message) {
        String blankLine = LINE_END + LINE_END;
        int split = message.indexOf(blankLine);
        String headers = split < 0 ? "" : message.substring(0, split).toLowerCase(Locale.ROOT);
        String body = split < 0 ? message : message.substring(split + blankLine.length());
        if (headers.contains("content-transfer-encoding: base64")) {
            return new String(Base64.getMimeDecoder().decode(body), StandardCharsets.UTF_8);
        }
        if (headers.contains("content-transfer-encoding: quoted-printable")) {
            return quotedPrintable(body.replace("=" + LINE_END, ""));
        }
        return body;
    }

    private static String quotedPrintable(String text) {
        StringBuilder decoded = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '=' && i + 2 < text.length()) {
                decoded.append((char) Integer.parseInt(text.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                decoded.append(c);
            }
        }
        return decoded.toString();
    }

    @Override
    public synchronized void close() throws IOException {
        releaseHeld();
        if (listener != null) {
            listener.close();
            listener = null;
        }
    }

    private static ServerSocket bind(int port) throws IOException {
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        return socket;
    }

    private void releaseHeld() {
        for (Socket socket : held) {
            closeQuietly(socket);
        }
        held.clear();
    }

    private void accept(ServerSocket socket) {
        Thread acceptor = new Thread(() -> {
            while (!socket.isClosed()) {
                Socket client;
                try {
                    client = socket.accept();
                } catch (IOException closed) {
                    return;
                }
                connections.incrementAndGet();
                Mode now = mode;
                if (now == Mode.CUTS) {
                    closeQuietly(client);
                } else if (now == Mode.SILENT) {
                    held.add(client);
                } else {
                    Thread session = new Thread(() -> converse(client), "fake-smtp-session");
                    session.setDaemon(true);
                    session.start();
                }
            }
        }, "fake-smtp-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    private void converse(Socket client) {
        try (client;
             BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));
             Writer out = new OutputStreamWriter(client.getOutputStream(), StandardCharsets.ISO_8859_1)) {
            reply(out, "220 fake-smtp ESMTP");
            String line;
            while ((line = in.readLine()) != null) {
                String command = line.toUpperCase(Locale.ROOT);
                if (command.startsWith("EHLO")) {
                    reply(out, "250-fake-smtp");
                    reply(out, "250 8BITMIME");
                } else if (command.startsWith("DATA")) {
                    reply(out, "354 End data with <CR><LF>.<CR><LF>");
                    messages.add(data(in));
                    reply(out, "250 OK queued");
                } else if (command.startsWith("QUIT")) {
                    reply(out, "221 Bye");
                    return;
                } else if (command.startsWith("HELO") || command.startsWith("MAIL") || command.startsWith("RCPT")
                        || command.startsWith("RSET") || command.startsWith("NOOP")) {
                    reply(out, "250 OK");
                } else {
                    reply(out, "502 Command not implemented");
                }
            }
        } catch (IOException ended) {
            // the client went away
        }
    }

    private static String data(BufferedReader in) throws IOException {
        StringBuilder message = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null && !".".equals(line)) {
            message.append(line.startsWith("..") ? line.substring(1) : line).append(LINE_END);
        }
        return message.toString();
    }

    private static void reply(Writer out, String line) throws IOException {
        out.write(line + LINE_END);
        out.flush();
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}
