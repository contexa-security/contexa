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
package io.contexa.contexaiam.admin.web.i18n;

import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.GenericApplicationContext;
import org.thymeleaf.IEngineConfiguration;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.expression.ThymeleafEvaluationContext;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.AbstractConfigurableTemplateResolver;
import org.thymeleaf.templateresource.ITemplateResource;
import org.thymeleaf.templateresource.StringTemplateResource;

import static org.assertj.core.api.Assertions.assertThat;

class SeedTextDialectTest {

    private static final String GROUP_KO = "개발본부";

    private static final String PAGE = "<ul><li th:text=\"${name}\">x</li><li>  " + GROUP_KO + "  </li></ul>"
            + "<input name=\"name\" th:value=\"${name}\"/><textarea name=\"description\" th:text=\"${name}\"></textarea>"
            + "<script>var name = '" + GROUP_KO + "';</script>"
            + "<p th:text=\"${quoted}\">x</p>";

    private final GenericApplicationContext application = new GenericApplicationContext();

    @AfterEach
    void close() {
        application.close();
    }

    @Test
    @DisplayName("D31: the text a console page shows is written in its language; fields, text areas and scripts are not")
    void theTextOfAConsolePageIsWrittenInItsLanguage() {
        String html = render("contexa/admin/groups", Locale.ENGLISH);

        assertThat(html).contains("<li>Development division</li>", "<li>  Development division  </li>",
                "<input name=\"name\" value=\"" + GROUP_KO + "\"/>",
                "<textarea name=\"description\">" + GROUP_KO + "</textarea>",
                "var name = '" + GROUP_KO + "';",
                "<p>Auto-synchronized policy for role &#39;ROLE_USER&#39;</p>");
        assertThat(render("contexa/admin/groups", Locale.KOREAN)).contains("<li>" + GROUP_KO + "</li>",
                "<p>역할 &#39;ROLE_USER&#39; 의 자동 동기화 정책</p>");
    }

    @Test
    @DisplayName("D31: a page of the application itself is written as it is")
    void aPageOfTheApplicationIsWrittenAsItIs() {
        assertThat(render("site/home", Locale.ENGLISH)).contains("<li>" + GROUP_KO + "</li>");
    }

    private String render(String template, Locale locale) {
        if (!application.isActive()) {
            application.registerBean(SeedTexts.class, () -> new SeedTexts(Map.of(
                    "group.development.name", Map.of("ko", GROUP_KO, "en", "Development division"),
                    "policy.automatic.description", Map.of(
                            "ko", "역할 '{0}' 의 자동 동기화 정책",
                            "en", "Auto-synchronized policy for role '{0}'"))));
            application.refresh();
        }
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(new PageResolver());
        engine.addDialect(new SeedTextDialect());
        Context context = new Context(locale);
        context.setVariable("name", GROUP_KO);
        context.setVariable("quoted", "Auto-synchronized policy for role 'ROLE_USER'");
        context.setVariable(ThymeleafEvaluationContext.THYMELEAF_EVALUATION_CONTEXT_CONTEXT_VARIABLE_NAME,
                new ThymeleafEvaluationContext(application, null));
        return engine.process(template, context);
    }

    /** Every template name stands for the same page. */
    private static final class PageResolver extends AbstractConfigurableTemplateResolver {

        private PageResolver() {
            setTemplateMode(TemplateMode.HTML);
            setCacheable(false);
        }

        @Override
        protected ITemplateResource computeTemplateResource(IEngineConfiguration configuration, String ownerTemplate,
                String template, String resourceName, String characterEncoding,
                Map<String, Object> templateResolutionAttributes) {
            return new StringTemplateResource(PAGE);
        }
    }
}
