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

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.contexa.contexaiam.admin.web.center.AccessCenterController;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
import io.contexa.contexaiam.admin.web.center.PolicyCenterOperationsController;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * The lists the access center and the policy center draw with their scripts show the seed texts in the language of the
 * page too (IAM-D31), as {@link SeedTextDialect} does for the pages the server writes. Only the answers of reads: what
 * a script reads to send back is not read this way. The answer is written from a copy, so nothing it was made from
 * changes.
 */
@ControllerAdvice(assignableTypes = {AccessCenterController.class, PolicyCenterController.class,
        PolicyCenterOperationsController.class})
public final class SeedTextResponseAdvice implements ResponseBodyAdvice<Object> {

    private final SeedTexts seedTexts;
    private final ObjectMapper objectMapper;

    public SeedTextResponseAdvice(SeedTexts seedTexts, @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        this.seedTexts = seedTexts;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return !seedTexts.isEmpty() && AbstractJackson2HttpMessageConverter.class.isAssignableFrom(converterType);
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request,
            ServerHttpResponse response) {
        if (body == null || body instanceof MappingJacksonValue || !HttpMethod.GET.equals(request.getMethod())) {
            return body;
        }
        JsonNode tree;
        try {
            tree = objectMapper.valueToTree(body);
        } catch (IllegalArgumentException e) {
            // The converter writes it as before and answers its own failure.
            return body;
        }
        return translate(tree, LocaleContextHolder.getLocale()) ? tree : body;
    }

    /** Writes the seed texts of the tree in the language of the locale; whether any was. */
    private boolean translate(JsonNode node, Locale locale) {
        boolean changed = false;
        if (node instanceof ObjectNode object) {
            Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                JsonNode value = field.getValue();
                if (value.isTextual()) {
                    String translated = translated(value.textValue(), locale);
                    if (translated != null) {
                        field.setValue(TextNode.valueOf(translated));
                        changed = true;
                    }
                } else {
                    changed |= translate(value, locale);
                }
            }
        } else if (node instanceof ArrayNode array) {
            for (int i = 0; i < array.size(); i++) {
                JsonNode value = array.get(i);
                if (value.isTextual()) {
                    String translated = translated(value.textValue(), locale);
                    if (translated != null) {
                        array.set(i, TextNode.valueOf(translated));
                        changed = true;
                    }
                } else {
                    changed |= translate(value, locale);
                }
            }
        }
        return changed;
    }

    /** The text in the language of the locale, or null when it is no seed text or already in that language. */
    private String translated(String text, Locale locale) {
        String shown = text.strip();
        if (shown.isEmpty()) {
            return null;
        }
        String translated = seedTexts.translate(shown, locale);
        return translated.equals(shown) ? null : translated;
    }
}
