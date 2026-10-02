package io.contexa.demo.platform.context;

import io.contexa.contexacore.autonomous.context.model.ResourceContextDescriptor;
import io.contexa.contexacore.autonomous.context.registry.ResourceContextRegistry;
import io.contexa.demo.work.customer.repository.CustomerRepository;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
@Profile("contexa")
public class BusinessResourceContextRegistry implements ResourceContextRegistry {

    private final DocumentRepository documents;
    private final CustomerRepository customers;
    private final BusinessRequestRepository requests;

    public BusinessResourceContextRegistry(DocumentRepository documents, CustomerRepository customers,
            BusinessRequestRepository requests) {
        this.documents = documents;
        this.customers = customers;
        this.requests = requests;
    }

    @Override
    public Optional<ResourceContextDescriptor> findByResourceId(String resourceId) {
        if (resourceId == null) {
            return Optional.empty();
        }
        if (resourceId.startsWith("export:")) {
            try {
                return requests.find(UUID.fromString(resourceId.substring(7))).map(snapshot -> {
                    var resource = snapshot.resourceFacts();
                    return new ResourceContextDescriptor(resource.id(), resource.type(), resource.label(),
                            resource.sensitivity(), List.of("USER", "ADMIN"), resource.allowedActions(), false,
                            "CONFIDENTIAL".equals(resource.sensitivity()));
                });
            } catch (IllegalArgumentException invalidResource) {
                return Optional.empty();
            }
        }
        Optional<ResourceContextDescriptor> documentContext = Optional.ofNullable(documents.find(resourceId)).map(document -> new ResourceContextDescriptor(document.id(),
                "DOCUMENT", document.title().en(), document.sensitivity(), List.of("USER", "ADMIN"),
                List.of("READ", "DOWNLOAD"), false, "CONFIDENTIAL".equals(document.sensitivity())));
        if (documentContext.isPresent()) {
            return documentContext;
        }
        return Optional.ofNullable(customers.find(resourceId)).map(customer -> new ResourceContextDescriptor(customer.id(),
                "CUSTOMER", customer.name().en(), customer.sensitivity(), List.of("USER", "ADMIN"),
                List.of("READ", "EXPORT"), false, true));
    }
}
