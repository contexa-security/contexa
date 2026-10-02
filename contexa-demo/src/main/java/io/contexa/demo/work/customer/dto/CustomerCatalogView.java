package io.contexa.demo.work.customer.dto;

import java.util.List;

public record CustomerCatalogView(
        List<CustomerSummary> customers,
        List<String> assignedProjects) {

    public CustomerCatalogView {
        customers = List.copyOf(customers);
        assignedProjects = List.copyOf(assignedProjects);
    }
}
