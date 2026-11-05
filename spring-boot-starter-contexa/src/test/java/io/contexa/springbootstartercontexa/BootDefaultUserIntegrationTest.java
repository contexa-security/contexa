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
package io.contexa.springbootstartercontexa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-5, measured on a real application: with Spring Security and only the starter added, Boot's generated password was gone
 * and nobody could sign in. This starts a real application on a real port and signs in with the password Boot wrote.
 */
@ExtendWith(OutputCaptureExtension.class)
@Timeout(180)
class BootDefaultUserIntegrationTest {

    private static final Pattern GENERATED_PASSWORD = Pattern.compile("Using generated security password: (\\S+)");

    @Test
    void anApplicationOnBootsUserSignsInWithOnlyTheStarterAdded(CapturedOutput output) throws Exception {
        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(ApplicationOnBootsUser.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0")
                .run()) {
            int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
            Matcher generated = GENERATED_PASSWORD.matcher(output.getOut());

            assertThat(generated.find()).as("Boot wrote its password").isTrue();
            assertThat(statusSignedInAs(port, "user", "not-the-password")).isEqualTo(401);
            assertThat(statusSignedInAs(port, "user", generated.group(1))).isEqualTo(200);
        }
    }

    private static int statusSignedInAs(int port, String name, String password) throws IOException, InterruptedException {
        String credentials = Base64.getEncoder().encodeToString((name + ":" + password).getBytes(StandardCharsets.UTF_8));
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/ping"))
                        .header("Authorization", "Basic " + credentials).GET().build(),
                HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import(Ping.class)
    static class ApplicationOnBootsUser {
    }

    @RestController
    static class Ping {

        @GetMapping("/ping")
        String ping() {
            return "pong";
        }
    }
}
