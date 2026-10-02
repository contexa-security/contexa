package io.contexa.demo.work.customer.repository;

import io.contexa.demo.work.customer.dto.CustomerDetail;
import io.contexa.demo.work.customer.dto.CustomerSummary;

import java.util.List;

public interface CustomerRepository {

    List<CustomerSummary> search(String projectId, String search);

    CustomerSummary find(String id);

    CustomerDetail read(String id, int version);
}
