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

import io.contexa.contexacommon.repository.AdminMenuRepository;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AdminMenuIconTest {

    private static final Pattern SEEDED_DRAWING = Pattern.compile("'(<svg.*?</svg>)'");

    @Test
    @DisplayName("every drawing of the seed script is allowed as it is")
    void everyDrawingOfTheSeedScriptIsAllowed() throws IOException {
        String seed = new ClassPathResource("META-INF/contexa/db/data-menu.sql").getContentAsString(StandardCharsets.UTF_8);
        List<String> drawings = new ArrayList<>();
        Matcher matcher = SEEDED_DRAWING.matcher(seed);
        while (matcher.find()) {
            drawings.add(matcher.group(1));
        }

        assertThat(drawings).hasSizeGreaterThanOrEqualTo(8);
        assertThat(drawings).allSatisfy(drawing -> {
            assertThat(AdminMenuIcon.isAllowed(drawing)).as(drawing).isTrue();
            assertThat(AdminMenuIcon.displayable(drawing)).isEqualTo(drawing);
        });
    }

    @Test
    @DisplayName("every drawing the service seeds is allowed as it is")
    void everyDrawingTheServiceSeedsIsAllowed() throws Exception {
        AdminMenuService service = new AdminMenuService(
                mock(AdminMenuRepository.class), mock(AdminMenuQueryCache.class), false, false);
        List<Method> drawings = Arrays.stream(AdminMenuService.class.getDeclaredMethods())
                .filter(method -> method.getName().startsWith("svg"))
                .toList();

        assertThat(drawings).hasSizeGreaterThanOrEqualTo(9);
        for (Method drawing : drawings) {
            drawing.setAccessible(true);
            String icon = (String) drawing.invoke(service);
            assertThat(icon).startsWith("<svg");
            assertThat(AdminMenuIcon.isAllowed(icon)).as(drawing.getName()).isTrue();
        }
    }

    @Test
    @DisplayName("a common drawing with its namespace and a class is allowed")
    void aCommonDrawingIsAllowed() {
        String drawing = "<svg xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\" stroke-width=\"1.5\" "
                + "stroke=\"currentColor\" class=\"w-6 h-6\">\n  <path stroke-linecap=\"round\" d=\"M4 6h16\" />\n"
                + "  <circle cx=\"12\" cy=\"12\" r=\"3\" fill=\"#334155\"/>\n</svg>";

        assertThat(AdminMenuIcon.isAllowed(drawing)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"fas fa-home", "bi bi-house", "", " "})
    @DisplayName("a value that opens with no tag is a class, which the screens write as one")
    void aClassIsAllowed(String icon) {
        assertThat(AdminMenuIcon.isAllowed(icon)).isTrue();
        assertThat(AdminMenuIcon.displayable(icon)).isEqualTo(icon);
    }

    @Test
    @DisplayName("no icon is allowed and stays no icon")
    void noIconIsAllowed() {
        assertThat(AdminMenuIcon.isAllowed(null)).isTrue();
        assertThat(AdminMenuIcon.displayable(null)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "<b>Sales & Ops</b>",
            "<svg data-name=\"R&D\"><path d=\"M0 0\"/></svg>",
            "<svg><text>Sales \"Ops\"</text></svg>",
            "<svg width=\"1>2\"><path d=\"M0 0\"/></svg>",
            "<svg><path d=\"M0 0\" title=\"Ops\"/></svg>",
            "<svg><path d=\"M0 0\"/></svg><p>Ops</p>",
            "<SVG></SVG>",
            "<svg>",
            "<"
    })
    @DisplayName("anything else that opens with a tag is refused and never shown")
    void anythingElseThatOpensWithATagIsRefused(String icon) {
        assertThat(AdminMenuIcon.isAllowed(icon)).isFalse();
        assertThat(AdminMenuIcon.displayable(icon)).isEmpty();
    }

    @Test
    @DisplayName("a drawing longer than the column that stores it is refused")
    void aDrawingLongerThanTheColumnIsRefused() {
        String drawing = "<svg><path d=\"" + "M0 0 ".repeat(500) + "\"/></svg>";

        assertThat(AdminMenuIcon.isAllowed(drawing)).isFalse();
    }
}
