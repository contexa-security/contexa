package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;
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
                    null, null, null, Collections.emptyList(),
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, Collections.emptyList(),
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0.0,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, Collections.emptyList()
            );
            when(dashboardService.getDashboardData()).thenReturn(dashboardData);

            String view = controller.dashboard(model);

            assertThat(view).isEqualTo("admin/dashboard");
            assertThat(model.getAttribute("dashboardData")).isEqualTo(dashboardData);
            assertThat(model.getAttribute("activePage")).isEqualTo("dashboard");
            verify(dashboardService).getDashboardData();
        }
    }
}
