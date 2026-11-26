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
package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.AnnotatedGenericBeanDefinition;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * R-9 (F-04): Contexa's screens bring Thymeleaf to an application's class path, and Spring Boot then configures a Thymeleaf
 * view resolver for every view name, which is asked before JSP: an application written for JSP answered its pages with a
 * missing Thymeleaf template. Spring Boot's Thymeleaf support is left out of an application that does not use Thymeleaf
 * itself (no {@code spring.thymeleaf} setting, no template of its own, no class of its own that names Thymeleaf), switched
 * on or not; Contexa's screens have a template engine of their own. An application that uses Thymeleaf keeps it.
 */
@DisplayName("Thymeleaf를 쓰지 않는 앱에는 Spring Boot의 Thymeleaf 자동 구성을 넣지 않는다")
class StandaloneAutoConfigurationFilterThymeleafTest {

    private static final String[] THYMELEAF = {
            "org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration",
            "org.springframework.boot.thymeleaf.autoconfigure.ThymeleafAutoConfiguration"
    };

    @TempDir
    Path classPath;

    @Test
    @DisplayName("Thymeleaf를 쓰지 않는 앱은 켜져 있든 아니든 Spring Boot의 Thymeleaf 자동 구성을 받지 않는다")
    void anApplicationWithoutThymeleafGetsNoneOfSpringBootsThymeleaf() throws IOException {
        DefaultListableBeanFactory application = applicationOn(classPathWith(), NoThymeleaf.class);

        assertThat(filter(switchedOn(new MockEnvironment()), application).match(THYMELEAF, null))
                .containsExactly(false, false);
        assertThat(filter(new MockEnvironment(), application).match(THYMELEAF, null)).containsExactly(false, false);
    }

    @Test
    @DisplayName("Contexa 화면 템플릿(templates/contexa)만 있는 앱은 Thymeleaf를 쓰는 앱이 아니다")
    void contexasOwnTemplatesAreNotTheApplications() throws IOException {
        DefaultListableBeanFactory application = applicationOn(
                classPathWith("templates/contexa/admin/users.html", "templates/contexa.html"), NoThymeleaf.class);

        assertThat(filter(switchedOn(new MockEnvironment()), application).match(THYMELEAF, null))
                .containsExactly(false, false);
    }

    @Test
    @DisplayName("spring.thymeleaf 설정이 있는 앱은 Spring Boot의 Thymeleaf 자동 구성을 그대로 갖는다")
    void aThymeleafSettingKeepsIt() throws IOException {
        DefaultListableBeanFactory application = applicationOn(classPathWith(), NoThymeleaf.class);

        assertThat(filter(switchedOn(new MockEnvironment().withProperty("spring.thymeleaf.cache", "false")), application)
                .match(THYMELEAF, null)).containsExactly(true, true);
    }

    @Test
    @DisplayName("Contexa 밖의 템플릿이 있는 앱은 Spring Boot의 Thymeleaf 자동 구성을 그대로 갖는다")
    void aTemplateOfTheApplicationsKeepsIt() throws IOException {
        DefaultListableBeanFactory application = applicationOn(classPathWith("templates/orders/list.html"),
                NoThymeleaf.class);

        assertThat(filter(new MockEnvironment(), application).match(THYMELEAF, null)).containsExactly(true, true);
    }

    @Test
    @DisplayName("앱의 코드가 Thymeleaf를 부르면 Spring Boot의 Thymeleaf 자동 구성을 그대로 갖는다")
    void aClassOfTheApplicationsThatNamesThymeleafKeepsIt() {
        DefaultListableBeanFactory application = applicationOn(getClass().getClassLoader(), MailWithThymeleaf.class);
        DefaultListableBeanFactory control = applicationOn(getClass().getClassLoader(), NoThymeleaf.class);

        assertThat(filter(switchedOn(new MockEnvironment()), application).match(THYMELEAF, null))
                .containsExactly(true, true);
        assertThat(filter(switchedOn(new MockEnvironment()), control).match(THYMELEAF, null))
                .as("the test class path has Contexa's templates only").containsExactly(false, false);
    }

    @Test
    @DisplayName("읽을 수 없는 클래스는 아무것도 말하지 않고 기동을 막지 않는다")
    void aClassThatCannotBeReadSaysNothing() throws IOException {
        DefaultListableBeanFactory application = applicationOn(new URLClassLoader(new URL[]{classPathWith().toUri().toURL()},
                getClass().getClassLoader()) {
            @Override
            public InputStream getResourceAsStream(String name) {
                return name.endsWith(".class") ? null : super.getResourceAsStream(name);
            }
        }, MailWithThymeleaf.class);

        assertThat(filter(new MockEnvironment(), application).match(THYMELEAF, null)).containsExactly(false, false);
    }

    /**
     * A JSP application: with Spring Boot's Thymeleaf support where the filter lets it in, its page is a Thymeleaf template
     * that does not exist; without it, the page is its JSP.
     */
    @Test
    @DisplayName("JSP 앱의 화면은 Contexa가 있어도 JSP로 간다")
    void aJspApplicationsPageGoesToItsJsp() throws IOException {
        StandaloneAutoConfigurationFilter filter = filter(switchedOn(new MockEnvironment()),
                applicationOn(classPathWith(), JspController.class));
        List<Class<?>> configurations = new ArrayList<>(List.of(WebMvcAutoConfiguration.class,
                HttpMessageConvertersAutoConfiguration.class));
        if (filter.match(new String[]{ThymeleafAutoConfiguration.class.getName()}, null)[0]) {
            configurations.add(ThymeleafAutoConfiguration.class);
        }

        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(configurations.toArray(new Class<?>[0])))
                .withUserConfiguration(JspController.class)
                .withPropertyValues("spring.mvc.view.prefix=/WEB-INF/jsp/", "spring.mvc.view.suffix=.jsp")
                .run(context -> {
                    MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();
                    mvc.perform(get("/orders")).andExpect(status().isOk())
                            .andExpect(forwardedUrl("/WEB-INF/jsp/orders.jsp"));
                });
    }

    private Path classPathWith(String... templates) throws IOException {
        Path root = Files.createTempDirectory(classPath, "cp");
        for (String template : templates) {
            Path file = root.resolve(template);
            Files.createDirectories(file.getParent());
            Files.writeString(file, "<p>x</p>");
        }
        return root;
    }

    private DefaultListableBeanFactory applicationOn(Path root, Class<?>... classes) throws IOException {
        return applicationOn(new URLClassLoader(new URL[]{root.toUri().toURL()}, null), classes);
    }

    private static DefaultListableBeanFactory applicationOn(ClassLoader classLoader, Class<?>... classes) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.setBeanClassLoader(classLoader);
        for (Class<?> each : classes) {
            beanFactory.registerBeanDefinition(each.getName(), new AnnotatedGenericBeanDefinition(each));
        }
        return beanFactory;
    }

    private static StandaloneAutoConfigurationFilter filter(MockEnvironment environment,
                                                            DefaultListableBeanFactory application) {
        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter();
        filter.setEnvironment(environment);
        filter.setBeanFactory(application);
        return filter;
    }

    private static MockEnvironment switchedOn(MockEnvironment environment) {
        environment.getPropertySources().addFirst(new MapPropertySource(
                AiSecurityImportSelector.ACTIVATION_SOURCE, Map.of("contexa.ai.security.mode", "SANDBOX")));
        return environment;
    }

    static class NoThymeleaf {
        String greeting() {
            return "hello";
        }
    }

    /** Writes its mails with the application's template engine. */
    static class MailWithThymeleaf {

        private final SpringTemplateEngine mails;

        MailWithThymeleaf(SpringTemplateEngine mails) {
            this.mails = mails;
        }
    }

    @Controller
    static class JspController {
        @GetMapping("/orders")
        String orders() {
            return "orders";
        }
    }
}
