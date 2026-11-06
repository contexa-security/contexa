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

import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionReferences;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.data.domain.PageImpl;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.ConcurrentModel;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * What a node not yet on references wrote since the last read is turned into references before the console lists,
 * exports or ends the sessions: the session is named by its reference, and only a row stored by it can be found.
 */
class SessionManagementReadsTest {

    private final SessionManagementService sessions = mock(SessionManagementService.class);
    private final SessionManagementController controller = new SessionManagementController(sessions,
            I18nTestSupport.englishMessageSource(), new CsvExportService());

    @Test
    void theListTurnsTheRawRowsIntoReferencesBeforeItReadsThem() {
        when(sessions.searchActiveSessions(any(), any())).thenReturn(new PageImpl<>(List.of()));

        controller.list(0, null, new ConcurrentModel());

        InOrder order = inOrder(sessions);
        order.verify(sessions).referenceRawSessions();
        order.verify(sessions).searchActiveSessions(any(), any());
    }

    @Test
    void endingASessionTurnsTheRawRowsIntoReferencesFirst() {
        controller.invalidateSession("sid-0123456789abcdef01234567", new RedirectAttributesModelMap());

        InOrder order = inOrder(sessions);
        order.verify(sessions).referenceRawSessions();
        order.verify(sessions).invalidateSession("sid-0123456789abcdef01234567");
    }

    @Test
    void theExportTurnsTheRawRowsIntoReferencesBeforeItReadsThem() throws Exception {
        when(sessions.getAllActiveSessions()).thenReturn(List.of());

        controller.export(new MockHttpServletResponse());

        InOrder order = inOrder(sessions);
        order.verify(sessions).referenceRawSessions();
        order.verify(sessions).getAllActiveSessions();
    }

    @Test
    void theServiceMovesTheRowsThroughTheReferencesItWasGiven() {
        ActiveSessionReferences references = mock(ActiveSessionReferences.class);
        when(references.whenRead()).thenReturn(3);

        assertThat(new SessionManagementService(mock(ActiveSessionRepository.class), references).referenceRawSessions())
                .isEqualTo(3);
    }

    @Test
    void withoutReferencesTheServiceLeavesTheRowsToTheNextStart() {
        ActiveSessionRepository repository = mock(ActiveSessionRepository.class);

        assertThat(new SessionManagementService(repository).referenceRawSessions()).isZero();
        assertThat(new SessionManagementService(repository, null).referenceRawSessions()).isZero();
        verifyNoInteractions(repository);
    }
}
