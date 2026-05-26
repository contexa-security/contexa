package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexaiam.admin.web.monitoring.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RequestParam;

@RequestMapping("/admin")
@RequiredArgsConstructor
@Controller
public class DashboardController {

    private final DashboardService dashboardService;

    @GetMapping({"", "/", "/dashboard"})
    public String dashboard(@RequestParam(required = false, defaultValue = "1") int days, Model model) {
        model.addAttribute("dashboardData", dashboardService.getDashboardData(days));
        model.addAttribute("activePage", "dashboard");
        model.addAttribute("selectedRange", days);
        return "admin/dashboard";
    }
}
