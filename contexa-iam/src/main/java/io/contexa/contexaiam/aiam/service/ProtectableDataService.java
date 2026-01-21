package io.contexa.contexaiam.aiam.service;

import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexacore.repository.CustomerDataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class ProtectableDataService {

    private final CustomerDataRepository customerDataRepository;

    @Transactional(readOnly = true)
    public Optional<CustomerData> getCustomerData(String customerId) {
        
        Optional<CustomerData> customerData = customerDataRepository.findById(customerId);

        if (customerData.isPresent()) {
                        
            logDataAccess(customerId, customerData.get());
        } else {
            log.warn("Customer data not found for ID: {}", customerId);
        }

        return customerData;
    }

    @Transactional(readOnly = true)
    public List<CustomerData> getAllCustomerData() {
        log.warn("Attempting to access ALL customer data - CRITICAL operation");

        List<CustomerData> allData = customerDataRepository.findAll();
        
        return allData;
    }

    @Transactional
    public CustomerData updateCustomerData(String customerId, CustomerData newData) {
        log.warn("Attempting to UPDATE customer data for ID: {}", customerId);

        Optional<CustomerData> existing = customerDataRepository.findById(customerId);
        if (existing.isPresent()) {
            CustomerData customer = existing.get();
            customer.setName(newData.getName());
            customer.setEmail(newData.getEmail());
            customer.setPhoneNumber(newData.getPhoneNumber());
            customer.setAddress(newData.getAddress());
            customer.setCreditCardNumber(newData.getCreditCardNumber());
            customer.setSocialSecurityNumber(newData.getSocialSecurityNumber());

            CustomerData saved = customerDataRepository.save(customer);
                        return saved;
        } else {
            throw new RuntimeException("Customer not found: " + customerId);
        }
    }

    @Transactional
    public void deleteCustomerData(String customerId) {
        log.error("Attempting to DELETE customer data for ID: {}", customerId);

        if (customerDataRepository.existsById(customerId)) {
            customerDataRepository.deleteById(customerId);
            log.error("Customer data DELETED for ID: {}", customerId);
        } else {
            log.warn("Customer not found for deletion: {}", customerId);
        }
    }

    public Optional<CustomerData> getCustomerDataDirect(String customerId) {
        log.error("DIRECT ACCESS to customer data (bypassing security) for ID: {}", customerId);
        return customerDataRepository.findById(customerId);
    }

    private void logDataAccess(String customerId, CustomerData data) {
        
            }
}