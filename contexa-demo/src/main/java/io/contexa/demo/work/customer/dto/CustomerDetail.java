package io.contexa.demo.work.customer.dto;

import io.contexa.demo.work.shared.dto.WorkText;

import java.util.List;

public record CustomerDetail(
        CustomerSummary customer,
        String contactName,
        String contactEmail,
        WorkText servicePlan,
        List<CustomerActivity> activities) {

    public CustomerDetail {
        activities = List.copyOf(activities);
    }
}
