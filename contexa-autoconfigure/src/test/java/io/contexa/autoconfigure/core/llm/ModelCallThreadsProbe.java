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

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SingleThreadEventLoop;
import io.netty.util.concurrent.EventExecutor;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.http.client.HttpClientAutoConfiguration;
import org.springframework.boot.autoconfigure.http.client.reactive.ClientHttpConnectorAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.client.RestClientAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.HttpResources;
import reactor.netty.resources.LoopResources;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * A servlet application with Contexa's model clients, in a JVM of its own, so that every thread it has is the application's or
 * Contexa's: it makes Contexa's three kinds of model call (a chat answer, a streamed answer with its time limit and timed buffer,
 * an embedding) against an Ollama server on this machine and prints the threads of the JVM before, after and once the application
 * has closed. With {@code host-webclient} the application first calls a backend of its own with Boot's WebClient, as an application
 * that uses WebClient does; with {@code no-contexa} it is the same application without Contexa, started and closed, the control.
 * {@link ContexaModelCallThreadsTest} reads what it prints.
 */
public final class ModelCallThreadsProbe {

    private static final String RESOURCES = "io.contexa.contexacore.infra.ContexaReactorResources";
    private static final String HOLDER_CONFIGURATION = "io.contexa.autoconfigure.core.infra.ContexaReactorResourcesAutoConfiguration";

    private ModelCallThreadsProbe() {
    }

    public static void main(String[] args) throws Exception {
        boolean hostWebClient = args.length > 0 && "host-webclient".equals(args[0]);
        boolean contexa = args.length == 0 || !"no-contexa".equals(args[0]);
        // the application's backend is a server of its own, so that its connections are not the model server's
        try (FakeOllamaServer model = new FakeOllamaServer(); FakeOllamaServer backend = new FakeOllamaServer()) {
            print("THREADS before " + threads());
            ConfigurableApplicationContext context = new SpringApplicationBuilder(contexa ? sources() : new Class<?>[]{HostApplication.class})
                    .web(WebApplicationType.SERVLET)
                    .initializers(application -> application.getEnvironment().getPropertySources()
                            .addFirst(new MapPropertySource(AiSecurityImportSelector.ACTIVATION_SOURCE, Map.of())))
                    .properties("spring.main.banner-mode=off", "server.port=0", "logging.level.root=ERROR",
                            "contexa.llm.chat.ollama.base-url=" + model.baseUrl(),
                            "contexa.llm.chat.ollama.model=qwen3:8b",
                            "contexa.llm.embedding.ollama.model=mxbai-embed-large",
                            "contexa.llm.selection.chat.priority=ollama",
                            "contexa.llm.selection.embedding.priority=ollama")
                    .run();
            print("THREADS started " + threads());
            if (hostWebClient) {
                WebClient host = context.getBean(WebClient.Builder.class).build();
                for (int i = 0; i < 3; i++) {
                    String thread = host.get().uri(backend.baseUrl() + "/host").retrieve().bodyToMono(String.class)
                            .map(body -> Thread.currentThread().getName()).block(Duration.ofSeconds(10));
                    print("HOSTCALL " + thread);
                }
                print("THREADS host " + threads());
                print("CHANNELS host global=" + channels(HttpResources.get()) + " contexa=" + contexaChannels());
            }

            if (!contexa) {
                context.close();
                Thread.sleep(500L);
                print("THREADS closed " + threads());
                System.out.flush();
                System.exit(0);
            }
            UnifiedLLMOrchestrator orchestrator = context.getBean(UnifiedLLMOrchestrator.class);
            String chat = orchestrator.execute(ExecutionContext.from(new Prompt("decide"))).block(Duration.ofSeconds(30));
            ExecutionContext streamed = ExecutionContext.builder().prompt(new Prompt("decide")).tier(2).timeoutMs(10_000).build();
            List<String> chunks = orchestrator.stream(streamed).collectList().block(Duration.ofSeconds(30));
            float[] vector = context.getBean("contexaPrimaryEmbeddingModel", EmbeddingModel.class).embed("a text");
            print("RESULT chat=" + chat + " stream=" + String.join("", chunks != null ? chunks : List.of())
                    + " embedding=" + vector.length + " requests=" + model.requests());
            print("THREADS contexa " + threads());
            if (hostWebClient) {
                print("CHANNELS contexa global=" + channels(HttpResources.get()) + " contexa=" + contexaChannels());
            }

            context.close();
            long until = System.currentTimeMillis() + 10_000L;
            while (System.currentTimeMillis() < until && (threads().contains("contexa-ai-") || threads().contains("contexa-timer-"))) {
                Thread.sleep(50L);
            }
            Thread.sleep(500L);
            print("THREADS closed " + threads());
        } catch (Throwable failure) {
            print("FAILED " + failure);
            failure.printStackTrace(System.out);
            System.out.flush();
            System.exit(2);
        }
        System.out.flush();
        System.exit(0);
    }

    private static Class<?>[] sources() {
        List<Class<?>> sources = new ArrayList<>(List.of(ProbeApplication.class));
        try {
            sources.add(Class.forName(HOLDER_CONFIGURATION));
        } catch (ClassNotFoundException e) {
            print("NOTE no " + HOLDER_CONFIGURATION);
        }
        return sources.toArray(new Class<?>[0]);
    }

    /** The names of the live threads, sorted, separated by a bar. */
    static String threads() {
        TreeSet<String> names = new TreeSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.isAlive()) {
                names.add(thread.getName());
            }
        }
        return String.join("|", names);
    }

    /** The channels registered on the client event loops of these resources: the connections, and a name lookup's socket. */
    private static int channels(LoopResources resources) {
        EventLoopGroup group = resources.onClient(LoopResources.DEFAULT_NATIVE);
        int channels = 0;
        for (EventExecutor executor : group) {
            if (executor instanceof SingleThreadEventLoop loop) {
                channels += loop.registeredChannels();
            }
        }
        return channels;
    }

    private static String contexaChannels() {
        try {
            Method eventLoops = Class.forName(RESOURCES).getMethod("eventLoops");
            return String.valueOf(channels((LoopResources) eventLoops.invoke(null)));
        } catch (ReflectiveOperationException e) {
            return "none";
        }
    }

    private static void print(String line) {
        System.out.println("PROBE " + line);
    }

    /** The application: a servlet application with Boot's HTTP clients, on the class path Contexa brings. */
    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration({PropertyPlaceholderAutoConfiguration.class, ServletWebServerFactoryAutoConfiguration.class,
            DispatcherServletAutoConfiguration.class, WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
            HttpMessageConvertersAutoConfiguration.class, HttpClientAutoConfiguration.class, RestClientAutoConfiguration.class,
            ClientHttpConnectorAutoConfiguration.class, WebClientAutoConfiguration.class})
    static class HostApplication {
    }

    /** The application with Contexa's model clients. */
    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration({PropertyPlaceholderAutoConfiguration.class, ServletWebServerFactoryAutoConfiguration.class,
            DispatcherServletAutoConfiguration.class, WebMvcAutoConfiguration.class, JacksonAutoConfiguration.class,
            HttpMessageConvertersAutoConfiguration.class, HttpClientAutoConfiguration.class, RestClientAutoConfiguration.class,
            ClientHttpConnectorAutoConfiguration.class, WebClientAutoConfiguration.class, CoreLLMTieredAutoConfiguration.class})
    @EnableConfigurationProperties(ContexaProperties.class)
    static class ProbeApplication {

        @Bean
        AdvisorRegistry contexaAdvisorRegistry() {
            return new AdvisorRegistry();
        }

        @Bean
        JsonStreamingProcessor contexaJsonStreamingProcessor() {
            return new JsonStreamingProcessor();
        }
    }
}
