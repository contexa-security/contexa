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
package io.contexa.contexaidentity.security.filter;

import java.util.LinkedHashMap;
import java.util.Map;

public class MfaHtmlTemplates {

    private MfaHtmlTemplates() {
        
    }

    public static Builder fromTemplate(String template) {
        return new Builder(template);
    }

    public static class Builder {
        private final String template;
        private final Map<String, String> replacements = new LinkedHashMap<>();

        Builder(String template) {
            this.template = template;
        }

        public Builder withValue(String key, String value) {
            this.replacements.put("{{" + key + "}}", escapeHtml(value));
            return this;
        }

        public Builder withRawHtml(String key, String value) {
            this.replacements.put("{{" + key + "}}", value);
            return this;
        }

        public String render() {
            String result = this.template;
            for (Map.Entry<String, String> entry : this.replacements.entrySet()) {
                result = result.replace(entry.getKey(), entry.getValue());
            }
            return result;
        }

        private String escapeHtml(String input) {
            if (input == null) {
                return "";
            }
            return input.replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;")
                       .replace("\"", "&quot;")
                       .replace("'", "&#x27;");
        }
    }
}
