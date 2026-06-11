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

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.PolicyHealthDto;
import io.contexa.contexaiam.admin.web.monitoring.service.DashboardService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("DashboardController")
class DashboardControllerTest {

    @Mock
    private DashboardService dashboardService;

    @InjectMocks
    private DashboardController controller;

    @Nested
    @DisplayName("dashboard")
    class Dashboard {

        @Test
        @DisplayName("should return dashboard view with data and active page")
        void success() {
            Model model = new ConcurrentModel();
            DashboardDto dashboardData = new DashboardDto(
                    null, Collections.emptyList(), Collections.emptyList(),
                    null, null, null,
                    new PolicyHealthDto("HEALTHY", 0, 0, "FIRST_APPLICABLE"),
                    Collections.emptyList(),
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, Collections.emptyList(),
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0.0,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, Collections.emptyList()
            );
            when(dashboardService.getDashboardData(1)).thenReturn(dashboardData);

            String view = controller.dashboard(1, model);

            assertThat(view).isEqualTo("admin/dashboard");
            assertThat(model.getAttribute("dashboardData")).isEqualTo(dashboardData);
            assertThat(model.getAttribute("activePage")).isEqualTo("dashboard");
            assertThat(model.getAttribute("selectedRange")).isEqualTo(1);
            verify(dashboardService).getDashboardData(1);
        }
    }
}
