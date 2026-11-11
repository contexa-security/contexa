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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A Redis that can stop and freeze, in front of a real one: the address an application connects to stays the same while
 * the real Redis answers, or does not. {@link #freeze()} behaves as a paused container does (connections are accepted, what
 * a client sends is not read, nothing answers, and everything is delivered once {@link #restore()} runs);
 * {@link #refuse()} behaves as a stopped one (connections are refused and the open ones are reset).
 */
final class RedisOutageProxy implements AutoCloseable {

    private final String targetHost;
    private final int targetPort;
    private final int port;
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final Object frozen = new Object();
    private volatile boolean isFrozen;
    private volatile boolean closed;
    private volatile ServerSocket server;

    RedisOutageProxy(String targetHost, int targetPort) {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.server = listen(0);
        this.port = server.getLocalPort();
        accept(server);
    }

    /** The address applications connect to. */
    int port() {
        return port;
    }

    /** Nothing answers and nothing is read, and the connections stay open. */
    void freeze() {
        isFrozen = true;
    }

    /** Connections are refused, and the open ones are reset. */
    void refuse() {
        isFrozen = false;
        synchronized (frozen) {
            frozen.notifyAll();
        }
        ServerSocket current = server;
        server = null;
        close(current);
        sockets.forEach(RedisOutageProxy::close);
        sockets.clear();
    }

    /** The real Redis answers again. */
    void restore() {
        if (server == null && !closed) {
            server = listen(port);
            accept(server);
        }
        isFrozen = false;
        synchronized (frozen) {
            frozen.notifyAll();
        }
    }

    @Override
    public void close() {
        closed = true;
        refuse();
    }

    private static ServerSocket listen(int port) {
        IOException last = null;
        for (int attempt = 0; attempt < 50; attempt++) {
            try {
                ServerSocket socket = new ServerSocket();
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
                return socket;
            } catch (IOException failure) {
                last = failure;
                try {
                    Thread.sleep(100);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        throw new IllegalStateException("The proxy cannot listen on " + port, last);
    }

    private void accept(ServerSocket listening) {
        Thread thread = new Thread(() -> {
            while (!listening.isClosed()) {
                try {
                    Socket client = listening.accept();
                    sockets.add(client);
                    connect(client);
                } catch (IOException stopped) {
                    return;
                }
            }
        }, "redis-outage-proxy-accept");
        thread.setDaemon(true);
        thread.start();
    }

    private void connect(Socket client) {
        Thread thread = new Thread(() -> {
            try {
                Socket redis = new Socket(targetHost, targetPort);
                sockets.add(redis);
                pump(client, redis, "redis-outage-proxy-down");
                pump(redis, client, "redis-outage-proxy-up");
            } catch (IOException unreachable) {
                close(client);
            }
        }, "redis-outage-proxy-connect");
        thread.setDaemon(true);
        thread.start();
    }

    private void pump(Socket from, Socket to, String name) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[8192];
            try {
                InputStream in = from.getInputStream();
                OutputStream out = to.getOutputStream();
                while (true) {
                    awaitUnfrozen();
                    int read = in.read(buffer);
                    if (read < 0) {
                        break;
                    }
                    awaitUnfrozen();
                    out.write(buffer, 0, read);
                    out.flush();
                }
            } catch (IOException | InterruptedException ended) {
                // the connection ended, or the proxy was told to refuse
            } finally {
                close(from);
                close(to);
                sockets.remove(from);
                sockets.remove(to);
            }
        }, name);
        thread.setDaemon(true);
        thread.start();
    }

    private void awaitUnfrozen() throws InterruptedException {
        synchronized (frozen) {
            while (isFrozen) {
                frozen.wait();
            }
        }
    }

    private static void close(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException ignored) {
            // closing is all that is asked
        }
    }
}
