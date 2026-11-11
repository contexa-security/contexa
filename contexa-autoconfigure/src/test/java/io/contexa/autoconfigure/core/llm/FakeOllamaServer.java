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
package io.contexa.autoconfigure.core.llm;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An Ollama server on this machine that answers over real HTTP: a chat answer, a streamed chat answer and an embedding, in the
 * shape Spring AI's {@code OllamaApi} reads. It can be made slow, or made to close the connection without an answer, to see what a
 * call does when the server does not answer.
 */
final class FakeOllamaServer implements AutoCloseable {

    enum Behaviour { ANSWER, SLOW, CLOSE }

    private static final String TIMES = "\"total_duration\":1,\"load_duration\":1,\"prompt_eval_count\":1,"
            + "\"prompt_eval_duration\":1,\"eval_count\":1,\"eval_duration\":1";

    private final HttpServer server;
    private final ExecutorService handlers;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile Behaviour behaviour = Behaviour.ANSWER;
    private volatile long slowMillis = 2_000L;
    private volatile String answer = "ALLOW";

    FakeOllamaServer() throws IOException {
        AtomicInteger number = new AtomicInteger();
        handlers = Executors.newFixedThreadPool(8, task -> {
            Thread thread = new Thread(task, "fake-model-" + number.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(handlers);
        server.createContext("/api/chat", this::chat);
        server.createContext("/api/embed", this::embed);
        server.createContext("/host", exchange -> send(exchange, 200, "text/plain", "the host's backend"));
        server.start();
    }

    /** The address, by name: a name is looked up before the call connects, as the address of a real model server is. */
    String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    void behave(Behaviour behaviour, long slowMillis) {
        this.behaviour = behaviour;
        this.slowMillis = slowMillis;
    }

    void answer(String answer) {
        this.answer = answer;
    }

    int requests() {
        return requests.get();
    }

    private void chat(HttpExchange exchange) throws IOException {
        requests.incrementAndGet();
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if (!behaveBeforeAnswering(exchange)) {
            return;
        }
        if (body.replace(" ", "").contains("\"stream\":true")) {
            exchange.getResponseHeaders().add("Content-Type", "application/x-ndjson");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (String part : new String[]{"The model says ", "ALLOW for this request."}) {
                    out.write((message(part, false) + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    pause(30L);
                }
                out.write((message("", true) + "\n").getBytes(StandardCharsets.UTF_8));
            }
            return;
        }
        send(exchange, 200, "application/json", message(answer, true));
    }

    private void embed(HttpExchange exchange) throws IOException {
        requests.incrementAndGet();
        exchange.getRequestBody().readAllBytes();
        if (!behaveBeforeAnswering(exchange)) {
            return;
        }
        send(exchange, 200, "application/json",
                "{\"model\":\"mxbai-embed-large\",\"embeddings\":[[0.25,0.5,0.75]]," + TIMES.substring(0, TIMES.indexOf(",\"prompt_eval_duration")) + "}");
    }

    /** False when the exchange was ended without an answer. */
    private boolean behaveBeforeAnswering(HttpExchange exchange) {
        if (behaviour == Behaviour.CLOSE) {
            exchange.close();
            return false;
        }
        if (behaviour == Behaviour.SLOW) {
            pause(slowMillis);
        }
        return true;
    }

    private static String message(String content, boolean done) {
        return "{\"model\":\"qwen3:8b\",\"created_at\":\"2026-11-11T00:00:00Z\",\"message\":{\"role\":\"assistant\",\"content\":\""
                + content + "\"}," + (done ? "\"done_reason\":\"stop\",\"done\":true," + TIMES : "\"done\":false") + "}";
    }

    private static void send(HttpExchange exchange, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        server.stop(0);
        handlers.shutdownNow();
    }
}
