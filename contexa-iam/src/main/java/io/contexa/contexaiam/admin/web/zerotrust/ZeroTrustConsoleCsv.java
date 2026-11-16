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
package io.contexa.contexaiam.admin.web.zerotrust;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Console plan 5-2 ⑥: a screen's numbers as a CSV, as the AI monitor exported each of its tabs. Every number of the
 * screen is one row: a metric with its definition's parts (numerator, denominator, unit, the reason it has none), a share
 * with its count and ratio, a ranked item with its count and its parts, any other value under its place on the screen.
 */
final class ZeroTrustConsoleCsv {

    static final String HEADER = "section,item,value,numerator,denominator,ratio,unit,note\n";

    private ZeroTrustConsoleCsv() {
    }

    /** The screen's answer as CSV rows under {@link #HEADER}, the cells defused as the decision records' CSV does. */
    static String of(Object screen, ObjectMapper objectMapper) {
        StringBuilder csv = new StringBuilder("﻿").append(HEADER);
        List<String[]> rows = new ArrayList<>();
        walk(objectMapper.valueToTree(screen), "", rows);
        for (String[] row : rows) {
            List<String> cells = new ArrayList<>(row.length);
            for (String value : row) {
                cells.add(ZeroTrustConsoleController.cell(value));
            }
            csv.append(String.join(",", cells)).append('\n');
        }
        return csv.toString();
    }

    private static void walk(JsonNode node, String section, List<String[]> rows) {
        if (node == null || node.isNull()) {
            return;
        }
        if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                walk(node.get(i), section + "[" + i + "]", rows);
            }
            return;
        }
        if (!node.isObject()) {
            rows.add(new String[] {parent(section), last(section), node.asText(), "", "", "", "", ""});
            return;
        }
        if (node.has("label") && node.has("value") && node.has("unit")) {
            rows.add(new String[] {section, text(node, "label"), text(node, "value"), text(node, "numerator"),
                    text(node, "denominator"), "", text(node, "unit"), text(node, "noDataReason")});
            return;
        }
        if (node.has("key") && node.has("count") && node.has("ratio") && node.size() == 3) {
            rows.add(new String[] {section, text(node, "key"), text(node, "count"), "", "", text(node, "ratio"), "", ""});
            return;
        }
        if (node.has("item") && node.has("count") && node.has("byDetail")) {
            rows.add(new String[] {section, text(node, "item"), text(node, "count"), "", "", "", "",
                    parts(node.get("byDetail"))});
            return;
        }
        Iterator<Map.Entry<String, JsonNode>> fields = node.properties().iterator();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            walk(field.getValue(), section.isEmpty() ? field.getKey() : section + "." + field.getKey(), rows);
        }
    }

    private static String parts(JsonNode byDetail) {
        if (byDetail == null || !byDetail.isObject()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        byDetail.properties().forEach(part -> parts.add(part.getKey() + "=" + part.getValue().asText()));
        return String.join("; ", parts);
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? "" : value.asText();
    }

    private static String parent(String section) {
        int at = Math.max(section.lastIndexOf('.'), section.lastIndexOf('['));
        return at < 0 ? "" : section.substring(0, at);
    }

    private static String last(String section) {
        int at = Math.max(section.lastIndexOf('.'), section.lastIndexOf('['));
        return at < 0 ? section : section.substring(at + (section.charAt(at) == '.' ? 1 : 0));
    }
}
