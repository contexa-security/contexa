package io.contexa.demo.work.customer.service;

import io.contexa.demo.work.customer.dto.CustomerCatalogView;
import io.contexa.demo.work.customer.dto.CustomerSummary;

public interface CustomerCatalog {

    CustomerCatalogView search(String username, String projectId, String search);

    CustomerSummary customer(String id);
}
