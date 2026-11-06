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
package io.contexa.contexaiam.admin.web.menu.dto;

import java.util.regex.Pattern;

/**
 * What a menu may carry as its icon. A value that opens with a tag reaches the console as markup, so it has to be a
 * plain drawing of the kind the seeded menus use: an {@code svg} element holding self-closed shapes, with presentation
 * attributes whose values are numbers, words and colours. Anything else that opens with a tag is refused on save and
 * shown as no icon. A value that opens with no tag is a CSS class, which the screens write as a class.
 */
public final class AdminMenuIcon {

    /** The width of the column that stores the icon. */
    private static final int MAX_MARKUP_LENGTH = 2000;

    private static final String VALUE = "\"[A-Za-z0-9 .,#%-]*+\"";

    private static final String SVG_ATTRIBUTE = "(?:xmlns=\"http://www\\.w3\\.org/2000/svg\""
            + "|(?:viewBox|width|height|fill|stroke|stroke-width|class)=" + VALUE + ")";

    private static final String SHAPE_ATTRIBUTE = "(?:d|points|cx|cy|r|rx|ry|x|y|x1|y1|x2|y2|width|height|fill|fill-rule"
            + "|clip-rule|stroke|stroke-width|stroke-linecap|stroke-linejoin)=" + VALUE;

    private static final String SHAPE = "<(?:path|circle|ellipse|rect|line|polyline|polygon)"
            + "(?:\\s++" + SHAPE_ATTRIBUTE + ")*+\\s*+/>";

    private static final Pattern DRAWING = Pattern.compile(
            "<svg(?:\\s++" + SVG_ATTRIBUTE + ")*+\\s*+>(?:\\s*+" + SHAPE + ")*+\\s*+</svg>");

    private AdminMenuIcon() {
    }

    /** Whether the value may be stored and shown: no icon, a class, or a plain drawing. */
    public static boolean isAllowed(String icon) {
        if (icon == null || !icon.startsWith("<")) {
            return true;
        }
        return icon.length() <= MAX_MARKUP_LENGTH && DRAWING.matcher(icon).matches();
    }

    /** The value as the screens may show it: itself when allowed, otherwise no icon. */
    public static String displayable(String icon) {
        return isAllowed(icon) ? icon : "";
    }
}
