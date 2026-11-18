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
package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * K92 and its neighbour on the drawn policy list: the dashboard's links (waiting for approval, approved, active, the
 * conflicts and duplicates) open their filter chosen in the list's filter box, the policy check's filter says the counts
 * of the report the dashboard counts from, and every page link keeps every filter the list was opened with.
 */
class PolicyListFiltersScreenTest {

    private static final Pattern PAGE_LINK = Pattern.compile("class=\"page-link\"[^>]*href=\"([^\"]*)\"|"
            + "href=\"([^\"]*)\"[^>]*class=\"page-link\"");

    private final PolicyService policies = mock(PolicyService.class);
    private final PolicyValidationService validation = mock(PolicyValidationService.class);
    private MockMvc mvc;

    @BeforeEach
    void aConsole() {
        ResourceRegistryService resources = mock(ResourceRegistryService.class);
        PolicyCombiningProperties combining = mock(PolicyCombiningProperties.class);
        when(combining.getCombiningAlgorithm()).thenReturn(CombiningAlgorithm.DENY_OVERRIDES);
        when(resources.findResources(any(), any())).thenReturn(Page.empty());
        when(resources.getAllServiceOwners()).thenReturn(Set.of());
        PolicyCenterPageService pages = new PolicyCenterPageService(resources, policies, combining);
        pages.setPolicyValidation(validation);
        when(validation.validateAllForDashboard()).thenReturn(new FullValidationReport(9, "WARNING",
                List.of(new PolicyConflictDto(1L, "a", 2L, "b", "overlap")),
                List.of(new DuplicatePolicyDto("same", List.of(3L, 4L), "sig"))));
        when(policies.searchPolicies(any(), any(), any(), any(Pageable.class))).thenReturn(fivePages());
        when(policies.searchPolicies(any(), any(), any(), eq(Set.of(1L, 2L, 3L, 4L)), any(Pageable.class)))
                .thenReturn(fivePages());
        ThymeleafViewResolver views = new ThymeleafViewResolver();
        views.setTemplateEngine(engine());
        views.setCharacterEncoding("UTF-8");
        mvc = MockMvcBuilders.standaloneSetup(new PolicyCenterController(messages(), pages,
                        mock(PolicyCenterQueryService.class), mock(PolicyCenterCommandService.class),
                        mock(PolicyCenterAnalysisService.class)))
                .setViewResolvers(views).setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver()).build();
    }

    @Test
    @DisplayName("every page link keeps the approval, the active state, the policy check and the search the list has")
    void everyPageLinkKeepsEveryFilter() throws Exception {
        String page = page("tab=list&approvalStatus=PENDING&activeFilter=true&health=ISSUES&policyKeyword=orders&policyPage=2",
                Locale.KOREAN);

        List<String> links = pageLinks(page);
        assertThat(links).hasSizeGreaterThanOrEqualTo(7).allMatch(link -> link.contains("tab=list")
                && link.contains("approvalStatus=PENDING") && link.contains("activeFilter=true")
                && link.contains("health=ISSUES") && link.contains("policyKeyword=orders"));
    }

    @Test
    @DisplayName("the dashboard's waiting policies open chosen in the filter box, and their pages keep the filter")
    void theWaitingPoliciesOpenChosen() throws Exception {
        String page = page("tab=list&approvalStatus=PENDING", Locale.KOREAN);

        assertThat(page).containsPattern("<option value=\"PENDING\"\\s+selected=\"selected\">대기 중</option>");
        assertThat(page).doesNotContain("id=\"policy-health-filter\"");
        assertThat(pageLinks(page)).allMatch(link -> link.contains("approvalStatus=PENDING")
                && !link.contains("activeFilter=true"));
    }

    @Test
    @DisplayName("K92: the conflicts and duplicates open the policies of the dashboard's report, with its counts")
    void theConflictsOpenThePoliciesOfTheReport() throws Exception {
        String korean = page("tab=list&health=ISSUES", Locale.KOREAN);
        String english = page("tab=list&health=ISSUES&activeFilter=true", Locale.ENGLISH);

        assertThat(korean).containsPattern("<option value=\"ISSUES\"\\s+selected=\"selected\">충돌·중복 있음</option>")
                .contains("정책 충돌 1건 · 중복 1건, 걸린 정책 47개");
        assertThat(english).contains("1 policy conflicts · 1 duplicates: 47 policies involved")
                .containsPattern("<option value=\"true\"\\s+selected=\"selected\">Active</option>");
    }

    // ----- the drawn page -----

    private static Page<Policy> fivePages() {
        List<Policy> rows = LongStream.rangeClosed(1, 10).mapToObj(id -> {
            Policy policy = Policy.builder().name("Policy " + id).effect(Policy.Effect.ALLOW).priority((int) id)
                    .approvalStatus(Policy.ApprovalStatus.PENDING).build();
            policy.setId(id);
            policy.setTargets(Set.of(PolicyTarget.builder().targetType("URL").httpMethod("GET")
                    .targetIdentifier("/api/orders/**").build()));
            return policy;
        }).toList();
        return new PageImpl<>(rows, PageRequest.of(2, 10), 47);
    }

    private String page(String query, Locale locale) throws Exception {
        return mvc.perform(get("/contexa/admin/policy-center?" + query).locale(locale)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private static List<String> pageLinks(String page) {
        List<String> links = new ArrayList<>();
        Matcher matcher = PAGE_LINK.matcher(page);
        while (matcher.find()) {
            String link = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
            links.add(URLDecoder.decode(link.replace("&amp;", "&"), StandardCharsets.UTF_8));
        }
        return links;
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
