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
package io.contexa.contexaiam.admin.web.company.controller;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Assignment;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.NetworkZone;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Person;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Policy;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Ticket;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexaiam.admin.web.company.controller.CompanyRecordsApiController.DeleteBody;
import io.contexa.contexaiam.admin.web.company.controller.CompanyRecordsApiController.RecordView;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService.Recorded;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** docs/agent OC-2: the company's integrations put, list and delete company records; the console shows them. */
class CompanyRecordsAdminTest {

    private static final Instant NOW = Instant.parse("2026-10-23T06:00:00Z");
    /** The console writes times on the server's clock, as the other console screens do. */
    private static final String PUT_AT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .format(NOW.atZone(ZoneId.systemDefault()));

    private final InMemoryCompanyRecordStore store = new InMemoryCompanyRecordStore();
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final CompanyRecordsAdminService service = new CompanyRecordsAdminService(store, audit,
            Clock.fixed(NOW, ZoneOffset.UTC));
    private final CompanyRecordsApiController api = new CompanyRecordsApiController(service);
    private final Authentication integration = new UsernamePasswordAuthenticationToken("hr-sync", null, List.of());

    @Test
    void anIntegrationPutsListsAndDeletesRecordsAndEveryChangeIsAudited() {
        ResponseEntity<?> put = api.put(null, records(), integration);

        assertThat(put.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat((Recorded) put.getBody()).satisfies(recorded -> {
            assertThat(recorded.records()).isEqualTo(5);
            assertThat(recorded.integratedKinds()).containsExactly("ASSIGNMENT", "TICKET");
        });
        @SuppressWarnings("unchecked")
        List<RecordView> tickets = (List<RecordView>) api.list(null, "ticket", null, null, 50).getBody();
        assertThat(tickets).singleElement().satisfies(view -> {
            assertThat(view.key()).isEqualTo("TCK-1");
            assertThat(view.subject()).isEqualTo("alice");
            assertThat(view.target()).isEqualTo("HX-310");
            assertThat(view.ingestedBy()).isEqualTo("hr-sync");
            assertThat(view.ingestedAt()).isEqualTo(NOW);
        });
        @SuppressWarnings("unchecked")
        List<RecordView> alice = (List<RecordView>) api.list(null, null, "alice", null, 50).getBody();
        assertThat(alice).extracting(RecordView::kind).containsExactlyInAnyOrder("PERSON", "ASSIGNMENT", "TICKET");

        assertThat(api.delete(new DeleteBody(null, "TICKET", List.of("TCK-1", "TCK-9")), integration).getBody())
                .isEqualTo(Map.of("removed", 1));
        assertThat(store.ofSubject(null, "alice").tickets()).isEmpty();

        ArgumentCaptor<AuditRecord> audited = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit, times(2)).recordAsync(audited.capture());
        assertThat(audited.getAllValues()).extracting(AuditRecord::getEventCategory).containsExactly(
                AuditEventCategory.COMPANY_RECORDS_RECORDED, AuditEventCategory.COMPANY_RECORDS_DELETED);
        assertThat(audited.getAllValues()).extracting(AuditRecord::getPrincipalName).containsOnly("hr-sync");
    }

    @Test
    void recordsThatCannotBeKeptAreRefusedWithEveryProblem() {
        CompanyRecordSet invalid = new CompanyRecordSet(null, null, List.of(new Assignment("alice", null, null, null,
                null)), null, null, null, null, null, null, null, List.of(new NetworkZone("office", "CORPORATE")));

        ResponseEntity<?> refused = api.put(null, invalid, integration);

        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(((Map<?, ?>) refused.getBody()).get("problems")).isEqualTo(List.of(
                "assignment alice||| names no target", "network 'office' is not a valid network block"));
        assertThat(api.put(null, null, integration).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.list(null, "salary", null, null, 10).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(api.delete(new DeleteBody(null, "TICKET", List.of(" ")), integration).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(store.list(null, null, null, null, 10)).isEmpty();
    }

    @Test
    void onlyAdministratorsReachTheApiAndTheConsole() {
        assertThat(CompanyRecordsApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasRole('ADMIN')");
        assertThat(CompanyRecordsApiController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/contexa/admin/api/company-records");
        assertThat(CompanyRecordsAdminController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasRole('ADMIN')");
    }

    @Test
    void theConsoleShowsEachRecordWithItsValuesAndWhoPutIt() {
        service.put("hr-sync", null, records());
        CompanyRecordsAdminController console = new CompanyRecordsAdminController(service);
        ExtendedModelMap model = new ExtendedModelMap();

        assertThat(console.list(null, "alice", null, null, model)).isEqualTo("contexa/admin/company-records");
        String html = render(Locale.KOREAN, model);

        assertThat(html).contains(">업무 기록<", ">티켓<", ">배정<", "TCK-1", "CHANGE · OPEN · DESIGN_CHANGE",
                "approver pm-11", "actions READ", "DESIGN · 2026-01-01 .. ", "hr-sync", PUT_AT,
                "company-records?target=HX-310").doesNotContain("??");
        assertThat(render(Locale.ENGLISH, model)).contains(">Company records<", ">Ticket<", ">Assignment<")
                .doesNotContain("??");

        ExtendedModelMap rules = new ExtendedModelMap();
        console.list("POLICY", null, null, null, rules);
        assertThat(render(Locale.KOREAN, rules)).contains("DOCUMENT_ACCESS_APPROVAL",
                "TICKET · actions READ, DOWNLOAD · categories PROJECT_DOCUMENTS · exceptions ASSIGNED, RECENT_WORK 90");
        ExtendedModelMap wrong = new ExtendedModelMap();
        console.list("salary", null, null, null, wrong);
        assertThat(wrong.get("errorMessage")).isEqualTo("'salary' is not a kind of company record");
    }

    private static CompanyRecordSet records() {
        return new CompanyRecordSet(List.of(new Person("alice", "eng-k", "Alice")), null,
                List.of(new Assignment("alice", "HX-310", "DESIGN", LocalDate.parse("2026-01-01"), null)),
                null, List.of(new Ticket("TCK-1", "alice", "CHANGE", "pm-11", "HX-310", "DESIGN_CHANGE",
                List.of("READ"), "OPEN", NOW.minusSeconds(3600), NOW.plusSeconds(3600), null, null)), null, null, null,
                null, List.of(new Policy("DOCUMENT_ACCESS_APPROVAL", "A document is read by an assigned person.",
                "TICKET", null, List.of("READ", "DOWNLOAD"), List.of("PROJECT_DOCUMENTS"), List.of(
                new Policy.Rule("ASSIGNED", null), new Policy.Rule("RECENT_WORK", 90)), null, null)),
                List.of(new NetworkZone("10.40.12.0/24", "CORPORATE")));
    }

    private static String render(Locale locale, ExtendedModelMap model) {
        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET",
                "/contexa/admin/company-records");
        WebContext context = new WebContext(JakartaServletWebApplication.buildApplication(servletContext)
                .buildExchange(request, new MockHttpServletResponse()), locale, model);
        return engine().process("contexa/admin/company-records", context);
    }

    private static SpringTemplateEngine engine() {
        ClassLoaderTemplateResolver fragments = resolver("test-templates/", 1);
        fragments.setResolvablePatterns(Set.of("contexa/fragments/*"));
        ClassLoaderTemplateResolver templates = resolver("templates/", 2);
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("i18n/messages");
        messages.setFallbackToSystemLocale(false);
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolvers(Set.of(fragments, templates));
        engine.setTemplateEngineMessageSource(messages);
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
