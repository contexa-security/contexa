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
import java.util.Set;

import org.springframework.context.ApplicationContext;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.dialect.AbstractDialect;
import org.thymeleaf.dialect.IPostProcessorDialect;
import org.thymeleaf.engine.AbstractTemplateHandler;
import org.thymeleaf.model.ICloseElementTag;
import org.thymeleaf.model.IOpenElementTag;
import org.thymeleaf.model.IText;
import org.thymeleaf.postprocessor.IPostProcessor;
import org.thymeleaf.postprocessor.PostProcessor;
import org.thymeleaf.spring6.context.SpringContextUtils;
import org.thymeleaf.templatemode.TemplateMode;
import org.unbescape.html.HtmlEscape;

/**
 * Shows the seed texts of a console page in the language of the page (IAM-D31): a text of the page that is a seed text
 * in any language is written in the page's language. Only the console's own templates ({@value #CONSOLE_TEMPLATES}...)
 * and only text the page shows: the value of a field, a text area, a script or a style stays as it is, so what a form
 * sends back is what is stored.
 */
public final class SeedTextDialect extends AbstractDialect implements IPostProcessorDialect {

    static final String CONSOLE_TEMPLATES = "contexa/";

    private static final int PRECEDENCE = 1000;

    public SeedTextDialect() {
        super("contexa-seed-texts");
    }

    @Override
    public int getDialectPostProcessorPrecedence() {
        return PRECEDENCE;
    }

    @Override
    public Set<IPostProcessor> getPostProcessors() {
        return Set.of(new PostProcessor(TemplateMode.HTML, Handler.class, PRECEDENCE));
    }

    /** Made by the template engine for each page it writes. */
    public static final class Handler extends AbstractTemplateHandler {

        private static final Set<String> KEPT_ELEMENTS = Set.of("textarea", "script", "style");

        private SeedTexts seedTexts;
        private Locale locale;
        private int keptDepth;

        public Handler() {
        }

        @Override
        public void setContext(ITemplateContext context) {
            super.setContext(context);
            String template = context.getTemplateData() != null ? context.getTemplateData().getTemplate() : null;
            ApplicationContext application = SpringContextUtils.getApplicationContext(context);
            SeedTexts texts = application != null ? application.getBeanProvider(SeedTexts.class).getIfAvailable() : null;
            boolean console = template != null && template.startsWith(CONSOLE_TEMPLATES);
            this.seedTexts = console && texts != null && !texts.isEmpty() ? texts : null;
            this.locale = context.getLocale();
        }

        @Override
        public void handleOpenElement(IOpenElementTag tag) {
            if (seedTexts != null && kept(tag.getElementCompleteName())) {
                keptDepth++;
            }
            super.handleOpenElement(tag);
        }

        @Override
        public void handleCloseElement(ICloseElementTag tag) {
            if (seedTexts != null && keptDepth > 0 && kept(tag.getElementCompleteName())) {
                keptDepth--;
            }
            super.handleCloseElement(tag);
        }

        @Override
        public void handleText(IText text) {
            super.handleText(seedTexts == null || keptDepth > 0 ? text : translated(text));
        }

        private IText translated(IText text) {
            String written = text.getText();
            String shown = written.strip();
            if (shown.isEmpty()) {
                return text;
            }
            String plain = HtmlEscape.unescapeHtml(shown);
            String translated = seedTexts.translate(plain, locale);
            if (translated.equals(plain)) {
                return text;
            }
            int at = written.indexOf(shown);
            // escaped as th:text escapes
            String rewritten = written.substring(0, at) + HtmlEscape.escapeHtml4Xml(translated)
                    + written.substring(at + shown.length());
            return getContext().getModelFactory().createText(rewritten);
        }

        private static boolean kept(String elementName) {
            return elementName != null && KEPT_ELEMENTS.contains(elementName.toLowerCase(Locale.ROOT));
        }
    }
}
