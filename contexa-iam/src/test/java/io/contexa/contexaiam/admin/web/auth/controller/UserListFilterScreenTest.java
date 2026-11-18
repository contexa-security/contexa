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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserListFilters;
import io.contexa.contexaiam.admin.web.auth.service.UserListFilters.Filter;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.domain.dto.UserListDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * K92 and K100 on the drawn list of users: each number of the dashboard opens its filter, chosen among the console's
 * filter chips with how many users it holds; a user's row opens that user by exact name, never the word search; and the
 * pages keep the filter or the name the list was opened with. A search for a word is what it was.
 */
class UserListFilterScreenTest {

    private static final Pattern HREF = Pattern.compile("href=\"(/contexa/admin/users[^\"]*)\"");

    private final UserManagementService users = mock(UserManagementService.class);
    private final UserListFilters filters = mock(UserListFilters.class);
    private MockMvc mvc;

    @BeforeEach
    void aConsole() {
        RoleService roles = mock(RoleService.class);
        GroupService groups = mock(GroupService.class);
        ThymeleafViewResolver views = new ThymeleafViewResolver();
        views.setTemplateEngine(engine());
        views.setCharacterEncoding("UTF-8");
        UserManagementController controller = new UserManagementController(users, roles, groups,
                mock(PasswordPolicyService.class), messages());
        controller.setUserListFilters(filters);
        mvc = MockMvcBuilders.standaloneSetup(controller).setViewResolvers(views)
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver()).build();
        Page<Long> ids = new PageImpl<>(List.of(1L), PageRequest.of(0, 15), 40);
        when(filters.ids(any(), anyInt(), anyInt())).thenReturn(ids);
        when(filters.named(any(), anyInt(), anyInt())).thenReturn(ids);
        when(users.getUsers(eq(ids))).thenReturn(threePages());
        when(users.getUsers(any(), any(Pageable.class))).thenReturn(threePages());
    }

    @Test
    @DisplayName("K92: a filter of the dashboard opens chosen, with how many users it holds, and stays on the pages")
    void aFilterOpensChosenAndStaysOnThePages() throws Exception {
        String page = page("filter=LOCKED", Locale.KOREAN);

        verify(filters).ids(Filter.LOCKED, 0, 15);
        assertThat(chips(page)).containsExactly("", "ADMIN", "ADMIN_NO_MFA", "NO_FACTOR", "LOCKED", "DORMANT");
        assertThat(chosen(page)).containsExactly("LOCKED");
        assertThat(page).contains(">잠긴 계정<", ">MFA 를 켜지 않은 관리자<", ">인증 수단이 없는 사용자<", ">90일 미로그인<",
                "40명");
        assertThat(pageLinks(page)).hasSize(7).allMatch(link -> link.contains("filter=LOCKED"));
        assertThat(page("filter=ADMIN_NO_MFA", Locale.ENGLISH)).contains(">Administrators without MFA<", "40 users");
    }

    @Test
    @DisplayName("K100: a user's row opens that user by exact name, named on the list, and the pages keep the name")
    void aUserOpensByExactName() throws Exception {
        String page = page("user=alice", Locale.KOREAN);

        verify(filters).named("alice", 0, 15);
        verify(users, never()).getUsers(any(), any(Pageable.class));
        assertThat(page).contains("사용자: alice").contains("40명");
        assertThat(chosen(page)).isEmpty();
        assertThat(pageLinks(page)).hasSize(7).allMatch(link -> link.contains("user=alice"));
    }

    @Test
    @DisplayName("a search for a word is what it was: a filter word of no list is the word search")
    void aSearchForAWordIsWhatItWas() throws Exception {
        String page = page("keyword=ali&filter=ANYTHING", Locale.KOREAN);

        verify(users).getUsers(eq("ali"), any(Pageable.class));
        assertThat(chosen(page)).containsExactly("");
        assertThat(page).doesNotContain("40명");
        assertThat(pageLinks(page)).allMatch(link -> link.contains("keyword=ali") && !link.contains("filter=ANYTHING"));
    }

    @Test
    @DisplayName("S10: millions of users draw the pages near the current one, the first and the last, the filter kept")
    void millionsOfUsersDrawTheNearPagesOnly() throws Exception {
        Page<Long> ids = new PageImpl<>(List.of(1L), PageRequest.of(4000, 15), 9_999_999);
        when(filters.ids(Filter.DORMANT, 4000, 15)).thenReturn(ids);
        when(users.getUsers(eq(ids))).thenReturn(new PageImpl<>(threePages().getContent(), PageRequest.of(4000, 15),
                9_999_999));

        String page = page("filter=DORMANT&page=4000", Locale.KOREAN);

        // the first, the previous, page 1, pages 3999 to 4003, the last page, the next and the last
        List<String> links = pageLinks(page);
        assertThat(links).hasSize(11).allMatch(link -> link.contains("filter=DORMANT") && link.contains("size=15"));
        assertThat(links).extracting(link -> link.replaceAll(".*[?&]page=(\\d+).*", "$1")).containsExactly("0", "3999",
                "0", "3998", "3999", "4000", "4001", "4002", "666666", "4001", "666666");
        assertThat(page).contains(">666667<", "9,999,999명").containsPattern("aria-current=\"page\"[^>]*>4001<");
        assertThat(page.length()).isLessThan(200_000);
    }

    // ----- the drawn page -----

    private static Page<UserListDto> threePages() {
        List<UserListDto> rows = LongStream.rangeClosed(1, 15).mapToObj(id -> {
            UserListDto row = new UserListDto();
            row.setId(id);
            row.setUsername("user" + id);
            row.setName("User " + id);
            return row;
        }).toList();
        return new PageImpl<>(rows, PageRequest.of(0, 15), 40);
    }

    private String page(String query, Locale locale) throws Exception {
        return mvc.perform(get("/contexa/admin/users?" + query).locale(locale)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private static String chipsPart(String page) {
        int start = page.indexOf("id=\"userFilters\"");
        return start < 0 ? "" : page.substring(start, page.indexOf("</div>", start));
    }

    private static final Pattern CHIP = Pattern.compile("<a href=\"(/contexa/admin/users[^\"]*)\"([^>]*)>");

    /** The filter of each filter chip ("" for every user), in their order; the chip of a name is not one. */
    private static List<String> chips(String page) {
        return chipTags(page, false);
    }

    /** The filter chips drawn as chosen, by their filter ("" for every user). */
    private static List<String> chosen(String page) {
        return chipTags(page, true);
    }

    private static List<String> chipTags(String page, boolean chosenOnly) {
        List<String> chips = new ArrayList<>();
        Matcher matcher = CHIP.matcher(chipsPart(page));
        while (matcher.find()) {
            String attributes = matcher.group(2);
            if (attributes.contains("userFilterExact") || chosenOnly && !attributes.contains("filter-active")) {
                continue;
            }
            String link = decode(matcher.group(1));
            chips.add(link.contains("filter=") ? link.replaceAll(".*filter=([A-Z_]+).*", "$1") : "");
        }
        return chips;
    }

    private static List<String> pageLinks(String page) {
        List<String> links = new ArrayList<>();
        Matcher matcher = HREF.matcher(page.substring(page.indexOf("</table>")));
        while (matcher.find()) {
            links.add(decode(matcher.group(1)));
        }
        return links;
    }

    private static String decode(String link) {
        return URLDecoder.decode(link.replace("&amp;", "&"), StandardCharsets.UTF_8);
    }

    private static ResourceBundleMessageSource messages() {
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        return messages;
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        engine.setTemplateEngineMessageSource(messages());
        return engine;
    }

    private static ClassLoaderTemplateResolver resolver(String prefix, int order) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix(prefix);
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCheckExistence(true);
        resolver.setOrder(order);
        return resolver;
    }
}
