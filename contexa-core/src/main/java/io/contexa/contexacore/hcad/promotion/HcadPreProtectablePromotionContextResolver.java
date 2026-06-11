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

import io.contexa.contexacommon.hcad.domain.HCADContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class HcadPreProtectablePromotionContextResolver {

    private HcadPreProtectablePromotionContextResolver() {
    }

    public static HcadPreProtectablePromotionAssessment resolve(HCADContext context) {
        if (context == null || context.getAdditionalAttributes() == null) {
            return HcadPreProtectablePromotionAssessment.unavailable("HCAD context did not carry a pre-protectable promotion assessment.");
        }
        Map<String, Object> attrs = context.getAdditionalAttributes();
        Object rawSignals = attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_RAW_SIGNALS);
        if (!(rawSignals instanceof Map<?, ?> rawMap) || rawMap.isEmpty()) {
            return HcadPreProtectablePromotionAssessment.unavailable("HCAD context did not carry a populated pre-protectable promotion assessment.");
        }
        Map<String, Object> rawSignalSnapshot = new LinkedHashMap<>();
        rawMap.forEach((key, value) -> rawSignalSnapshot.put(String.valueOf(key), value));
        return new HcadPreProtectablePromotionAssessment(
                castInt(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_SCORE)),
                castBand(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_BAND)),
                castBoolean(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_ELIGIBLE)),
                castStringList(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_ANCHOR_SIGNALS)),
                castStringList(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_CORROBORATING_SIGNALS)),
                castStringList(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_REASON_CODES)),
                castString(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_SUMMARY)),
                castString(attrs.get(HcadPreProtectablePromotionAttributes.CONTEXT_VERSION)),
                rawSignalSnapshot);
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
}