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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * K93, K108 and K92 on the drawn security event log: its periods run to the dashboard's longest, a dashboard link of any
 * period opens with its period chosen; the pages, the CSV, the search's clearing and the periods keep every filter the
 * list was opened with; the seal filter opens the records the dashboard counts and the list says how many it holds.
 */
class SecurityMonitorLinksScreenTest {

    private static final Pattern HREF = Pattern.compile("href=\"(/contexa/admin/security-monitor[^\"]*)\"");

    private final AuditLogRepository auditLogs = mock(AuditLogRepository.class);
    private final DashboardQueries queries = mock(DashboardQueries.class);
    private MockMvc mvc;

    @BeforeEach
    void aConsole() {
        ThymeleafViewResolver views = new ThymeleafViewResolver();
        views.setTemplateEngine(engine());
        views.setCharacterEncoding("UTF-8");
        SecurityMonitorController controller = new SecurityMonitorController(auditLogs, mock(CsvExportService.class));
        controller.setDashboardQueries(queries);
        mvc = MockMvcBuilders.standaloneSetup(controller).setViewResolvers(views).build();
        List<AuditLog> rows = IntStream.range(0, 20).mapToObj(i -> AuditLog.builder().id((long) i + 1)
                .eventCategory("AUTHENTICATION_FAILURE").principalName("bob").timestamp(LocalDateTime.now()).build())
                .toList();
        PageImpl<AuditLog> threePages = new PageImpl<>(rows, PageRequest.of(0, 20), 60);
        when(auditLogs.findByTimestampAfter(any(), any())).thenReturn(threePages);
        when(auditLogs.findByTimestampAfterAndSubjectKind(any(), any(), any())).thenReturn(threePages);
        when(auditLogs.findByTimestampAfterAndCategoryAndPrincipalNameLike(any(), any(), any(), any()))
                .thenReturn(threePages);
        when(auditLogs.findByTimestampAfterAndCategory(any(), any(), any())).thenReturn(threePages);
        when(auditLogs.findByCategoryAndDecision(any(), any(), any(), any())).thenReturn(threePages);
    }

    @ParameterizedTest
    @ValueSource(ints = {24, 168, 720, 2160})
    @DisplayName("K93: the periods run to 90 days, and each period of the dashboard opens with its chip chosen")
    void eachPeriodOfTheDashboardOpensWithItsChipChosen(int hours) throws Exception {
        String page = page("hours=" + hours, Locale.KOREAN);

        assertThat(chips(page)).containsExactly(1, 6, 24, 72, 168, 720, 2160);
        assertThat(chosenChips(page)).containsExactly(hours);
        assertThat(page).contains(">7일<", ">30일<", ">90일<");
        assertThat(page("hours=" + hours, Locale.ENGLISH)).contains(">7 Days<", ">30 Days<", ">90 Days<");
    }

    @Test
    @DisplayName("K93: the seal link that names its start keeps its period chosen, and every link keeps the start")
    void aLinkThatNamesItsStartKeepsItsPeriodChosen() throws Exception {
        String from = Instant.now().minus(169, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS).toString();
        when(queries.sealMismatchRecordCount(any())).thenReturn(0L);

        String page = page("category=SECURITY_DECISION&filter=SEAL_MISMATCH&hours=168&from=" + from, Locale.KOREAN);

        assertThat(chosenChips(page)).containsExactly(168);
        // a period names its own hours; the CSV and the seal chip keep the start the link named
        assertThat(periodLinks(page)).noneMatch(link -> link.contains("from=" + from));
        assertThat(csv(page)).contains("from=" + from, "filter=SEAL_MISMATCH");
        List<String> periods = periodLinks(page);
        assertThat(links(page)).filteredOn(link -> link.contains("filter=SEAL_MISMATCH") && !link.contains("/export")
                        && !periods.contains(link))
                .isNotEmpty().allMatch(link -> link.contains("from=" + from));
    }

    @Test
    @DisplayName("K108: a subject chip stays on the pages, the CSV, the search's clearing and the periods")
    void aSubjectStaysOnEveryLinkOfTheList() throws Exception {
        String page = page("subject=DELEGATED_AGENT&hours=72", Locale.KOREAN);

        assertThat(pageLinks(page)).hasSize(7).allMatch(link -> link.contains("subject=DELEGATED_AGENT"));
        assertThat(csv(page)).contains("subject=DELEGATED_AGENT");
        assertThat(clear(page)).contains("subject=DELEGATED_AGENT");
        assertThat(periodLinks(page)).hasSize(7).allMatch(link -> link.contains("subject=DELEGATED_AGENT"));
    }

    @Test
    @DisplayName("K108: a user name and a category stay on the pages and the CSV; a filter stays on the periods")
    void aNameACategoryAndAFilterStayOnTheirLinks() throws Exception {
        String named = page("category=AUTHENTICATION_FAILURE&keyword=bob&hours=24", Locale.KOREAN);
        String filtered = page("filter=ZT_BLOCK&hours=24", Locale.KOREAN);

        assertThat(pageLinks(named)).hasSize(7)
                .allMatch(link -> link.contains("keyword=bob") && link.contains("category=AUTHENTICATION_FAILURE"));
        assertThat(csv(named)).contains("keyword=bob", "category=AUTHENTICATION_FAILURE");
        assertThat(periodLinks(named)).allMatch(link -> link.contains("keyword=bob"));
        assertThat(periodLinks(filtered)).hasSize(7).allMatch(link -> link.contains("filter=ZT_BLOCK"));
        assertThat(pageLinks(filtered)).allMatch(link -> link.contains("filter=ZT_BLOCK"));
        assertThat(csv(filtered)).contains("filter=ZT_BLOCK");
    }

    @Test
    @DisplayName("K92: the seal chip opens the seal filter, chosen, and the list says how many records it holds")
    void theSealChipOpensTheRecordsCounted() throws Exception {
        when(queries.sealMismatchRecordCount(any())).thenReturn(1234L);
        when(queries.sealMismatchRecordIds(any(), anyLong(), anyInt())).thenReturn(List.of(7L));
        when(auditLogs.findAllById(eq(List.of(7L)))).thenReturn(List.of(AuditLog.builder().id(7L)
                .eventCategory("SECURITY_DECISION").principalName("alice").timestamp(LocalDateTime.now()).build()));

        String page = page("category=SECURITY_DECISION&filter=SEAL_MISMATCH&hours=168", Locale.KOREAN);

        assertThat(links(page)).anyMatch(link -> link.contains("filter=SEAL_MISMATCH")
                && link.contains("category=SECURITY_DECISION"));
        assertThat(page).contains("rgba(248,113,113,0.3)").contains("봉인 불일치").contains("1,234건");
        assertThat(page("hours=24", Locale.ENGLISH)).contains("Seal mismatch").contains("60 events");
    }

    @Test
    @DisplayName("S10: millions of records draw the pages near the current one, the first and the last, every filter kept")
    void millionsOfRecordsDrawTheNearPagesOnly() throws Exception {
        String from = Instant.now().minus(169, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS).toString();
        when(queries.sealMismatchRecordCount(any())).thenReturn(9_999_999L);
        when(queries.sealMismatchRecordIds(any(), anyLong(), anyInt())).thenReturn(List.of(7L));
        when(auditLogs.findAllById(eq(List.of(7L)))).thenReturn(List.of(AuditLog.builder().id(7L)
                .eventCategory("SECURITY_DECISION").principalName("alice").timestamp(LocalDateTime.now()).build()));

        String page = page("category=SECURITY_DECISION&filter=SEAL_MISMATCH&hours=2160&from=" + from + "&page=5000",
                Locale.KOREAN);

        // the first, the previous, page 1, pages 4999 to 5003, the last page, the next and the last
        List<String> links = pageLinks(page);
        assertThat(links).hasSize(11).allMatch(link -> link.contains("filter=SEAL_MISMATCH")
                && link.contains("category=SECURITY_DECISION") && link.contains("hours=2160") && link.contains("from=" + from));
        assertThat(links).extracting(link -> link.replaceAll(".*\\?page=(\\d+).*", "$1")).containsExactly("0", "4999",
                "0", "4998", "4999", "5000", "5001", "5002", "499999", "5001", "499999");
        assertThat(page).contains(">500000<").containsPattern("aria-current=\"page\"[^>]*>5001<");
        assertThat(page.length()).isLessThan(200_000);
    }

    // ----- the drawn page -----

    private String page(String query, Locale locale) throws Exception {
        return mvc.perform(get("/contexa/admin/security-monitor?" + query).locale(locale)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private static List<String> links(String page) {
        List<String> links = new ArrayList<>();
        Matcher matcher = HREF.matcher(page);
        while (matcher.find()) {
            links.add(URLDecoder.decode(matcher.group(1).replace("&amp;", "&"), StandardCharsets.UTF_8));
        }
        return links;
    }

    /** The period chips, each tag whole. */
    private static List<String> periodTags(String page) {
        List<String> tags = new ArrayList<>();
        Matcher matcher = Pattern.compile("<a data-period=\"\\d+\"[^>]*>").matcher(page);
        while (matcher.find()) {
            tags.add(matcher.group());
        }
        return tags;
    }

    private static List<String> periodLinks(String page) {
        return periodTags(page).stream().flatMap(tag -> links(tag).stream()).toList();
    }

    private static int hoursOf(String tag) {
        return Integer.parseInt(tag.replaceAll("(?s)^<a data-period=\"(\\d+)\".*", "$1"));
    }

    private static List<Integer> chips(String page) {
        return periodTags(page).stream().map(SecurityMonitorLinksScreenTest::hoursOf).toList();
    }

    /** The periods marked as chosen (aria-current), by their hours. */
    private static List<Integer> chosenChips(String page) {
        return periodTags(page).stream().filter(tag -> tag.contains("aria-current=\"true\""))
                .map(SecurityMonitorLinksScreenTest::hoursOf).toList();
    }

    private static List<String> pageLinks(String page) {
        return links(page).stream().filter(link -> link.contains("?page=")).toList();
    }

    private static String csv(String page) {
        return links(page).stream().filter(link -> link.contains("/export")).findFirst().orElseThrow();
    }

    /** The search's clearing: the link the form holds beside its field. */
    private static String clear(String page) {
        String form = page.substring(page.indexOf("name=\"keyword\""));
        Matcher matcher = HREF.matcher(form);
        assertThat(matcher.find()).isTrue();
        return URLDecoder.decode(matcher.group(1).replace("&amp;", "&"), StandardCharsets.UTF_8);
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
        resolver.setOrder(order);
        resolver.setCheckExistence(true);
        return resolver;
    }
}
