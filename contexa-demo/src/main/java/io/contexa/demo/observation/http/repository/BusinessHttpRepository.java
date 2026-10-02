package io.contexa.demo.observation.http.repository;

import io.contexa.demo.observation.http.dto.BusinessHttpObservation;

import java.util.Optional;
import java.util.UUID;

public interface BusinessHttpRepository {

    void append(BusinessHttpObservation observation);

    Optional<BusinessHttpObservation> find(UUID requestId, UUID visitorId);
}
