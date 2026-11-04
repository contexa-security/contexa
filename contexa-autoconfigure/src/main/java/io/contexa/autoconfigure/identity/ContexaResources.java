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

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Contexa's own SQL files, found among the files of the same name on the class path. An application may have a {@code db/schema.sql} or a
 * {@code db/data.sql} of its own; the first file of that name on the class path would be the application's, and it must never run in
 * Contexa's database. Of the files with the name, the one that names Contexa's tables ({@code ctxa_}) is Contexa's.
 */
final class ContexaResources {

    private static final Map<String, Resource> FOUND = new ConcurrentHashMap<>();
    /** Not the thread's context class loader: a context closed earlier on this thread leaves its stopped web class loader there. */
    private static final ClassLoader LOADER = ContexaResources.class.getClassLoader();

    private ContexaResources() {
    }

    static Resource sql(String location) {
        return FOUND.computeIfAbsent(location, name -> sql(new PathMatchingResourcePatternResolver(LOADER), name));
    }

    static Resource sql(PathMatchingResourcePatternResolver resolver, String location) {
        try {
            for (Resource candidate : resolver.getResources("classpath*:" + location)) {
                if (namesContexaTables(candidate)) {
                    return candidate;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return new ClassPathResource(location, LOADER);
    }

    private static boolean namesContexaTables(Resource candidate) {
        try (InputStream in = candidate.getInputStream()) {
            return new String(in.readNBytes(2 * 1024 * 1024), StandardCharsets.UTF_8).contains("ctxa_");
        } catch (IOException e) {
            return false;
        }
    }
}
