package io.contexa.demo.work.customer.service.impl;

import io.contexa.demo.work.customer.dto.CustomerCatalogView;
import io.contexa.demo.work.customer.dto.CustomerSummary;
import io.contexa.demo.work.customer.repository.CustomerRepository;
import io.contexa.demo.work.customer.service.CustomerCatalog;
import io.contexa.demo.work.project.repository.ProjectRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@Profile({"baseline", "contexa"})
public class DefaultCustomerCatalog implements CustomerCatalog {

    private final CustomerRepository customers;
    private final ProjectRepository projects;

    public DefaultCustomerCatalog(CustomerRepository customers, ProjectRepository projects) {
        this.customers = customers;
        this.projects = projects;
    }

    @Override
    public CustomerCatalogView search(String username, String projectId, String search) {
        if (search.length() > 120 || projectId.length() > 40) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_SEARCH");
        }
        return new CustomerCatalogView(customers.search(projectId.strip(), search.strip()),
                projects.assignedProjects(username));
    }

    @Override
    public CustomerSummary customer(String id) {
        CustomerSummary summary = customers.find(id);
        if (summary == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return summary;
    }
}
