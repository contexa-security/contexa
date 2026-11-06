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

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.repository.AdminMenuRepository;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AdminMenuUrlTest {

    private static final Pattern SEEDED_PATH = Pattern.compile("'(/[^']*)'");

    @Test
    @DisplayName("every address of the seed script is a link as it is")
    void everyAddressOfTheSeedScriptIsALink() throws IOException {
        String seed = new ClassPathResource("META-INF/contexa/db/data-menu.sql").getContentAsString(StandardCharsets.UTF_8);
        List<String> addresses = new ArrayList<>();
        Matcher matcher = SEEDED_PATH.matcher(seed);
        while (matcher.find()) {
            addresses.add(matcher.group(1));
        }

        assertThat(addresses).hasSizeGreaterThanOrEqualTo(20);
        assertThat(addresses).allSatisfy(address -> {
            assertThat(AdminMenuUrl.isAllowed(address)).as(address).isTrue();
            assertThat(AdminMenuUrl.linkable(address)).isEqualTo(address);
        });
    }

    @Test
    @DisplayName("every address the service seeds, in every edition, is a link as it is")
    void everyAddressTheServiceSeedsIsALink() {
        AdminMenuRepository repository = mock(AdminMenuRepository.class);
        AtomicLong ids = new AtomicLong();
        List<AdminMenu> saved = new ArrayList<>();
        when(repository.save(any(AdminMenu.class))).thenAnswer(invocation -> {
            AdminMenu menu = invocation.getArgument(0);
            if (menu.getId() == null) {
                menu.setId(ids.incrementAndGet());
            }
            saved.add(menu);
            return menu;
        });
        new AdminMenuService(repository, mock(AdminMenuQueryCache.class), true, true).initializeDefaultMenusIfEmpty();

        List<String> addresses = saved.stream().map(AdminMenu::getUrl).filter(Objects::nonNull).toList();
        assertThat(addresses).hasSizeGreaterThanOrEqualTo(30);
        assertThat(addresses).allSatisfy(address -> assertThat(AdminMenuUrl.linkable(address)).as(address).isEqualTo(address));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/contexa/admin/custom", "/contexa/admin/policy-center?tab=list#top", "/reports/2026/%EB%B3%B4%EA%B3%A0"})
    @DisplayName("a path inside the application is a link as it is")
    void aPathInsideTheApplicationIsALink(String url) {
        assertThat(AdminMenuUrl.isAllowed(url)).isTrue();
        assertThat(AdminMenuUrl.linkable(url)).isEqualTo(url);
    }

    @Test
    @DisplayName("no address is allowed and stays no link, as a group has")
    void noAddressIsAllowed() {
        assertThat(AdminMenuUrl.isAllowed(null)).isTrue();
        assertThat(AdminMenuUrl.isAllowed("")).isTrue();
        assertThat(AdminMenuUrl.linkable(null)).isNull();
        assertThat(AdminMenuUrl.linkable("")).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example/",
            "\\\\evil.example",
            "/\t/evil.example",
            "/\n/evil.example",
            "/\r/evil.example",
            " /contexa/admin/users",
            "/contexa/admin/users ",
            "/contexa admin",
            "/contexa\u0000/admin",
            "contexa/admin/users",
            "?tab=1",
            "#top"
    })
    @DisplayName("an address that may leave the application is refused and never a link")
    void anAddressThatMayLeaveTheApplicationIsRefused(String url) {
        assertThat(AdminMenuUrl.isAllowed(url)).isFalse();
        assertThat(AdminMenuUrl.linkable(url)).isNull();
    }

    @Test
    @DisplayName("an address longer than the column that stores it is refused")
    void anAddressLongerThanTheColumnIsRefused() {
        assertThat(AdminMenuUrl.isAllowed("/" + "a".repeat(254))).isTrue();
        assertThat(AdminMenuUrl.isAllowed("/" + "a".repeat(255))).isFalse();
    }
}
