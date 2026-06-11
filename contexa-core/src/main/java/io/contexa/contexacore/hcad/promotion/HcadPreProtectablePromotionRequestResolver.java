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
package io.contexa.contexacore.hcad.promotion;

import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class HcadPreProtectablePromotionRequestResolver {

    private HcadPreProtectablePromotionRequestResolver() {
    }

    public static HcadPreProtectablePromotionAssessment resolve(HttpServletRequest request) {
        if (request == null) {
            return HcadPreProtectablePromotionAssessment.unavailable("HCAD pre-protectable promotion assessment was not available.");
        }
        Map<String, Object> rawSignals = castMap(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_RAW_SIGNALS));
        if (rawSignals.isEmpty()) {
            return HcadPreProtectablePromotionAssessment.unavailable("HCAD pre-protectable promotion assessment was not projected onto the request.");
        }
        return new HcadPreProtectablePromotionAssessment(
                castInt(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SCORE)),
                castBand(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND)),
                castBoolean(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE)),
                castStringList(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ANCHOR_SIGNALS)),
                castStringList(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_CORROBORATING_SIGNALS)),
                castStringList(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_REASON_CODES)),
                castString(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SUMMARY)),
                castString(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_VERSION)),
                rawSignals);
    }

    private static HcadPreProtectablePromotionBand castBand(Object value) {
        if (value instanceof HcadPreProtectablePromotionBand band) {
            return band;
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return HcadPreProtectablePromotionBand.valueOf(text.trim().toUpperCase());
            } catch (IllegalArgumentException ignored) {
                return HcadPreProtectablePromotionBand.LOW;
            }
        }
        return HcadPreProtectablePromotionBand.LOW;
    }

    private static boolean castBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value instanceof String text && Boolean.parseBoolean(text);
    }

    private static int castInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && text.matches("-?\\d+")) {
            return Integer.parseInt(text);
        }
        return 0;
    }

    private static String castString(Object value) {
        return value == null ? "" : value.toString();
    }

    private static List<String> castStringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private static Map<String, Object> castMap(Object value) {
        if (!(value instanceof Map<?, ?> rawMap)) {
            return Map.of();
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        rawMap.forEach((key, mapValue) -> copy.put(String.valueOf(key), mapValue));
        return copy;
    }
}