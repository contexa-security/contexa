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

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.lang.Nullable;

/**
 * The texts the seed data puts in the database (the names and descriptions of the groups, roles, permissions, policies
 * and the role hierarchy) in each language (IAM-D31). A column holds one language, so a console in another language
 * showed them as they were stored; a stored text that is one of these is shown in the language of the page instead.
 * A text an administrator changed is no longer one of them and is shown as it is.
 *
 * <p>Each module brings its own {@value #LOCATION}: {@code <id>.<language>=<text>}, one line per language of an id. A
 * text may hold one {@code {0}}, which stands for any value (a generated description that names its role).
 */
@Slf4j
public final class SeedTexts {

    public static final String LOCATION = "classpath*:META-INF/contexa/seed-texts.properties";

    private static final String PLACEHOLDER = "{0}";

    /** id -> language -> text. */
    private final Map<String, Map<String, String>> textsById;

    /** a fixed text in any language -> its id. */
    private final Map<String, String> idByText = new HashMap<>();

    /** the texts that hold a value, in any language. */
    private final List<Template> templates = new ArrayList<>();

    SeedTexts(Map<String, Map<String, String>> textsById) {
        this.textsById = textsById;
        textsById.forEach((id, texts) -> texts.values().forEach(text -> {
            if (text.contains(PLACEHOLDER)) {
                templates.add(new Template(id, text));
            } else {
                idByText.putIfAbsent(text, id);
            }
        }));
    }

    /** The seed texts of every module on the class path. */
    public static SeedTexts load(ResourcePatternResolver resolver) {
        Map<String, Map<String, String>> textsById = new LinkedHashMap<>();
        Resource[] resources;
        try {
            resources = resolver.getResources(LOCATION);
        } catch (IOException e) {
            log.warn("The seed texts could not be listed; stored texts are shown as they are: {}", e.toString());
            return new SeedTexts(textsById);
        }
        for (Resource resource : resources) {
            Properties properties = new Properties();
            try (Reader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
                properties.load(reader);
            } catch (IOException e) {
                log.warn("Seed texts {} could not be read and are skipped: {}", resource, e.toString());
                continue;
            }
            for (String key : properties.stringPropertyNames()) {
                int dot = key.lastIndexOf('.');
                String text = properties.getProperty(key).strip();
                if (dot <= 0 || dot == key.length() - 1 || text.isEmpty()) {
                    continue;
                }
                textsById.computeIfAbsent(key.substring(0, dot), id -> new HashMap<>())
                        .put(key.substring(dot + 1).toLowerCase(Locale.ROOT), text);
            }
        }
        return new SeedTexts(textsById);
    }

    public boolean isEmpty() {
        return textsById.isEmpty();
    }

    /**
     * The text in the language of the locale when it is a seed text in any language; otherwise, and when the seed text
     * has no text in that language, the text as given.
     */
    public String translate(@Nullable String text, @Nullable Locale locale) {
        if (text == null || locale == null || textsById.isEmpty()) {
            return text;
        }
        String language = locale.getLanguage();
        String id = idByText.get(text);
        if (id != null) {
            String translated = textsById.get(id).get(language);
            return translated != null ? translated : text;
        }
        for (Template template : templates) {
            Matcher matcher = template.pattern.matcher(text);
            if (matcher.matches()) {
                String translated = textsById.get(template.id).get(language);
                return translated != null ? translated.replace(PLACEHOLDER, matcher.group(1)) : text;
            }
        }
        // "<seed text> (<name>)": a label that names the seed text and what it belongs to, as the list of default roles does
        int open = text.lastIndexOf(" (");
        if (open > 0 && text.endsWith(")")) {
            String headId = idByText.get(text.substring(0, open));
            String translated = headId != null ? textsById.get(headId).get(language) : null;
            if (translated != null) {
                return translated + text.substring(open);
            }
        }
        return text;
    }

    private static final class Template {

        private final String id;
        private final Pattern pattern;

        private Template(String id, String text) {
            int at = text.indexOf(PLACEHOLDER);
            this.id = id;
            this.pattern = Pattern.compile(Pattern.quote(text.substring(0, at)) + "(.+)"
                    + Pattern.quote(text.substring(at + PLACEHOLDER.length())), Pattern.DOTALL);
        }
    }
}
