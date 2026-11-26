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
package io.contexa.autoconfigure.iam;

import io.contexa.autoconfigure.iam.admin.IamAdminSeedTextAutoConfiguration;
import io.contexa.contexaiam.admin.web.i18n.SeedTextDialect;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.thymeleaf.extras.springsecurity6.dialect.SpringSecurityDialect;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * R-9 (F-04): Contexa's screens are written by a template engine of Contexa's that reads only Contexa's views
 * ({@code contexa/...}). An application's own Thymeleaf is configured as Spring Boot configures it without Contexa: no
 * dialect, template resolver or view of Contexa's in it. An application written for JSP keeps its views.
 */
@DisplayName("Contexa 화면은 Contexa 전용 템플릿 엔진이 쓰고 앱의 Thymeleaf에는 손대지 않는다")
class ContexaScreenTemplatesTest {

    private static final String PROBE = "contexa/m5-screen-probe";

    private final WebApplicationContextRunner applicationWithThymeleaf = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ThymeleafAutoConfiguration.class,
                    IamAdminSeedTextAutoConfiguration.class, IamScreenTemplatesAutoConfiguration.class,
                    WebMvcAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class));

    @Test
    @DisplayName("앱의 Thymeleaf 엔진에는 Contexa의 dialect도 템플릿 리졸버도 들어가지 않는다")
    void theApplicationsEngineHasNothingOfContexas() {
        applicationWithThymeleaf.run(context -> {
            assertThat(context).hasNotFailed();
            SpringTemplateEngine engine = context.getBean("templateEngine", SpringTemplateEngine.class);

            assertThat(engine.getDialects()).noneMatch(SeedTextDialect.class::isInstance);
            assertThat(engine.getTemplateResolvers())
                    .containsExactly(context.getBean("defaultTemplateResolver", ITemplateResolver.class));
        });
    }

    @Test
    @DisplayName("Contexa 화면 엔진은 contexa 뷰만 받고 콘솔 문구·Spring Security dialect를 갖는다")
    void contexasEngineTakesContexasViewsOnly() {
        applicationWithThymeleaf.run(context -> {
            ThymeleafViewResolver screens = context.getBean("contexaScreensViewResolver", ThymeleafViewResolver.class);
            SpringTemplateEngine engine = (SpringTemplateEngine) screens.getTemplateEngine();

            assertThat(engine).isNotSameAs(context.getBean("templateEngine"));
            assertThat(engine.getDialects()).anyMatch(SeedTextDialect.class::isInstance)
                    .anyMatch(SpringSecurityDialect.class::isInstance);
            assertThat(screens.resolveViewName(PROBE, Locale.KOREAN)).isNotNull();
            assertThat(screens.resolveViewName("orders", Locale.KOREAN)).isNull();
            assertThat(screens.resolveViewName("redirect:/orders", Locale.KOREAN)).as("the application's redirect").isNull();
            assertThat(screens.resolveViewName("forward:/orders", Locale.KOREAN)).as("the application's forward").isNull();
        });
    }

    /**
     * Spring MVC asks every view resolver and takes the first view of the best type: Contexa's view goes to Contexa's
     * engine and the application's view to the application's. The application's injection of its view resolver by type
     * gets its own.
     */
    @Test
    @DisplayName("앱이 Thymeleaf를 써도 contexa 뷰는 Contexa 엔진이, 앱 뷰는 앱 엔진이 쓰고 앱의 해석기 주입은 앱 것이다")
    void eachViewGoesToItsOwnEngine() {
        applicationWithThymeleaf.withUserConfiguration(ViewResolverUser.class).run(context -> {
            ThymeleafViewResolver screens = context.getBean("contexaScreensViewResolver", ThymeleafViewResolver.class);
            ContentNegotiatingViewResolver dispatcher = context.getBean("viewResolver", ContentNegotiatingViewResolver.class);
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
            try {
                View contexas = dispatcher.resolveViewName(PROBE, Locale.KOREAN);
                View applications = dispatcher.resolveViewName("orders", Locale.KOREAN);

                assertThat(ReflectionTestUtils.getField(contexas, "templateEngine")).isSameAs(screens.getTemplateEngine());
                assertThat(ReflectionTestUtils.getField(applications, "templateEngine"))
                        .isSameAs(context.getBean("templateEngine"));
            } finally {
                RequestContextHolder.resetRequestAttributes();
            }
            assertThat(context.getBean(ViewResolverUser.class).resolver)
                    .isSameAs(context.getBean("thymeleafViewResolver"));
        });
    }

    /** No Spring Boot Thymeleaf (the application uses JSP): its views are its JSPs, and Contexa's screens are written. */
    @Test
    @DisplayName("JSP 앱에서도 Contexa 화면은 Contexa 엔진으로 쓰이고 앱의 화면은 JSP로 간다")
    void aJspApplicationKeepsItsViewsAndGetsContexasScreens() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IamScreenTemplatesAutoConfiguration.class,
                        WebMvcAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class))
                .withUserConfiguration(Pages.class)
                .withPropertyValues("spring.mvc.view.prefix=/WEB-INF/jsp/", "spring.mvc.view.suffix=.jsp")
                .run(context -> {
                    MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).build();

                    mvc.perform(get("/orders")).andExpect(status().isOk())
                            .andExpect(forwardedUrl("/WEB-INF/jsp/orders.jsp"));
                    mvc.perform(get("/contexa/probe")).andExpect(status().isOk())
                            .andExpect(content().string(containsString("hello from contexa")));
                });
    }

    @Controller
    static class Pages {

        @GetMapping("/orders")
        String orders() {
            return "orders";
        }

        @GetMapping("/contexa/probe")
        String probe(Model model) {
            model.addAttribute("greeting", "hello from contexa");
            return PROBE;
        }
    }

    @Component
    static class ViewResolverUser {

        final ThymeleafViewResolver resolver;

        ViewResolverUser(ThymeleafViewResolver resolver) {
            this.resolver = resolver;
        }
    }
}
