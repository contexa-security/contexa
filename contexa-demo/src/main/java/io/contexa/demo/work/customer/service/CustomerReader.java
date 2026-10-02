package io.contexa.demo.work.customer.service;

import io.contexa.demo.work.customer.dto.CustomerReadResult;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;

public interface CustomerReader {

    CustomerReadResult read(CustomerRequestSnapshot snapshot);
}
