package io.contexa.demo.work.customer.repository;

import io.contexa.demo.work.customer.dto.CustomerReadResult;

public interface CustomerReadRepository {

    void append(CustomerReadResult result);
}
