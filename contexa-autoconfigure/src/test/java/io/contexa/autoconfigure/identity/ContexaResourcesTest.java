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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** An application's own META-INF/contexa/db/schema.sql, found first on the class path, never stands in for Contexa's. */
class ContexaResourcesTest {

    @Test
    void contexasSchemaIsChosenWhenTheApplicationHasAFileOfTheSameNameInFront(@TempDir Path application) throws Exception {
        Files.createDirectories(application.resolve("db"));
        Files.writeString(application.resolve("META-INF/contexa/db/schema.sql"), "create table orders (id bigint);");
        try (HostFirst loader = new HostFirst(new URL[] {application.toUri().toURL()}, getClass().getClassLoader())) {
            Resource hosts = new UrlResource(loader.getResource("META-INF/contexa/db/schema.sql"));
            assertThat(hosts.getContentAsString(StandardCharsets.UTF_8)).as("the application's file is the first on the class path").contains("orders");

            Resource chosen = ContexaResources.sql(new PathMatchingResourcePatternResolver(loader), "META-INF/contexa/db/schema.sql");

            assertThat(chosen.getContentAsString(StandardCharsets.UTF_8)).contains("ctxa_").doesNotContain("create table orders");
        }
    }

    /** A class loader that puts the application's files in front of everything else, as an application's own classes are on a class path. */
    private static final class HostFirst extends URLClassLoader {
        HostFirst(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        public URL getResource(String name) {
            URL own = findResource(name);
            return own != null ? own : super.getResource(name);
        }

        @Override
        public Enumeration<URL> getResources(String name) throws IOException {
            List<URL> all = new ArrayList<>(Collections.list(findResources(name)));
            all.addAll(Collections.list(getParent().getResources(name)));
            return Collections.enumeration(all);
        }
    }

    @Test
    void contexasSchemaIsFoundWhenTheApplicationHasNone() throws Exception {
        assertThat(ContexaResources.sql("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)).contains("ctxa_");
    }

    @Test
    void theClassLoaderAContextLeftStoppedOnTheThreadIsNotAsked() {
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
            @Override
            public URL getResource(String name) {
                throw new IllegalStateException("this web application instance has been stopped already");
            }

            @Override
            public Enumeration<URL> getResources(String name) {
                throw new IllegalStateException("this web application instance has been stopped already");
            }
        });
        try {
            assertThat(ContexaResources.sql("db/no-such-file-of-contexa.sql").exists()).isFalse();
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }
}
