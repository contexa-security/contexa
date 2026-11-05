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
package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SessionTrackingFilterTest {

    private final SessionTrackingFilter filter =
            new SessionTrackingFilter(mock(SessionManagementService.class), mock(ActiveSessionRepository.class));

    /** PR-65: a session forced out kept reaching these paths of the application. */
    @ParameterizedTest
    @ValueSource(strings = {"/favicon-report", "/faviconreport", "/actuator/env", "/demo/export", "/webjars-report",
            "/contexa/js/..;/..;/owners/1", "/contexa/admin/api/guided-audit"})
    void aPathOfTheApplicationMeetsTheForcedInvalidation(String path) {
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", path))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/favicon.ico", "/contexa/js/toast.js", "/contexa/css/main.css", "/contexa/img/logo.png",
            "/webjars/app.js", "/contexa/admin/test/guided", "/contexa/admin/api/guided/run"})
    void aFileOrAPathOfContexasIsNotTracked(String path) {
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", path))).isTrue();
    }

    @Test
    void theContextPathIsNotPartOfThePath() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/favicon.ico");
        request.setContextPath("/app");

        assertThat(filter.shouldNotFilter(request)).isTrue();
    }
}
