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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.repository.AdminMenuRepository;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService.MenuNode;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Quality plan 3.8: the menus the seed puts in the prompt quality assurance group are the menus of the screens' menu
 * bar, at the same addresses and in the same order. In the open source edition the side menu shows them; with the
 * enterprise edition on, the rule that hides the open source prompt quality menus (the enterprise edition brings its
 * own) hides the new menus as it hides the earlier ones.
 */
class PromptQualityMenusTest {

    private static final Pattern GROUP_ROW = Pattern.compile("\\('(menu\\.[^']+)',\\s*'([^']*)',\\s*'',\\s*"
            + "'prompt-quality',\\s*(\\d+),\\s*TRUE,\\s*'(CORE)',\\s*'([^']+)'\\)");

    @Test
    void theSeededMenusOfTheGroupAreTheMenusOfTheBarInItsOrder() throws IOException {
        List<AdminMenu> seeded = seededGroup();

        assertThat(seeded).extracting(AdminMenu::getUrl).containsExactlyElementsOf(PromptQualityScreens.MENUS.stream()
                .map(PromptQualityScreens.Menu::path).toList());
        assertThat(seeded).extracting(AdminMenu::getDataPage).containsExactly("prompt-quality-cases",
                "prompt-quality-measure", "prompt-quality-versions", "prompt-inspection-packages");
    }

    @Test
    void theOpenSourceEditionShowsTheMenusAndTheEnterpriseEditionHidesThemAsItHidesTheEarlierOnes() throws IOException {
        List<AdminMenu> menus = new ArrayList<>();
        menus.add(AdminMenu.builder().id(1L).name("menu.nav.pqa").menuOrder(8).menuType("CORE")
                .dataPage("prompt-quality").build());
        menus.addAll(seededGroup());

        assertThat(tree(menus, false)).singleElement().satisfies(group -> assertThat(group.children())
                .extracting(MenuNode::name).containsExactly("menu.pqa.cases", "menu.pqa.measure", "menu.pqa.versions",
                        "menu.pqa.inspection.packages"));
        assertThat(tree(menus, true)).singleElement().satisfies(group -> assertThat(group.children()).isEmpty());
    }

    private static List<MenuNode> tree(List<AdminMenu> menus, boolean enterprise) {
        AdminMenuQueryCache cache = mock(AdminMenuQueryCache.class);
        when(cache.findAllWithRoles()).thenReturn(menus);
        return new AdminMenuService(mock(AdminMenuRepository.class), cache, enterprise, false)
                .getMenuTreeForUser(List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    /** The rows of the seed under the prompt quality group, in their order. */
    private static List<AdminMenu> seededGroup() throws IOException {
        String seed = new ClassPathResource("META-INF/contexa/db/data-menu.sql").getContentAsString(StandardCharsets.UTF_8);
        List<AdminMenu> menus = new ArrayList<>();
        Matcher row = GROUP_ROW.matcher(seed);
        long id = 10L;
        while (row.find()) {
            menus.add(AdminMenu.builder().id(id++).name(row.group(1)).url(row.group(2)).parentId(1L)
                    .menuOrder(Integer.parseInt(row.group(3))).menuType(row.group(4)).dataPage(row.group(5)).build());
        }
        menus.sort((left, right) -> Integer.compare(left.getMenuOrder(), right.getMenuOrder()));
        return menus;
    }
}
