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
package io.contexa.autoconfigure.hostredis;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An application's own Redisson client, connected to a real Redis, that records every call made through it. Only the
 * methods of the client count: the methods of every object (equals, hashCode, toString) are not calls to Redis. Its
 * name keeps it out of the task test, whose class path has no Redisson, as the names of the tests that use it do.
 */
public final class CountedRedissonForDistributedClasspathTests implements AutoCloseable {

    private final RedissonClient real;
    private final RedissonClient client;
    private final List<String> calls = new CopyOnWriteArrayList<>();

    public CountedRedissonForDistributedClasspathTests(String host, int port, int database) {
        Config config = new Config();
        config.useSingleServer().setAddress("redis://" + host + ":" + port).setDatabase(database);
        real = Redisson.create(config);
        client = (RedissonClient) Proxy.newProxyInstance(RedissonClient.class.getClassLoader(),
                new Class<?>[] {RedissonClient.class}, (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method, arguments);
                    }
                    calls.add(method.getName());
                    try {
                        return method.invoke(real, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static Object objectMethod(Object proxy, Method method, Object[] arguments) {
        return switch (method.getName()) {
            case "equals" -> proxy == arguments[0];
            case "hashCode" -> System.identityHashCode(proxy);
            default -> "the application's Redisson client";
        };
    }

    /** The client the application declares as its bean. */
    public RedissonClient client() {
        return client;
    }

    /** The names of the methods called through the client, in order. */
    public List<String> calls() {
        return List.copyOf(calls);
    }

    @Override
    public void close() {
        real.shutdown();
    }
}
