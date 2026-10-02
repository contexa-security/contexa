package io.contexa.demo.work.customer.controller;

import io.contexa.demo.work.customer.dto.CustomerReadInput;
import io.contexa.demo.work.customer.dto.CustomerReadResult;
import io.contexa.demo.work.customer.dto.CustomerRequestSnapshot;
import io.contexa.demo.work.customer.service.CustomerReader;
import io.contexa.demo.work.customer.service.CustomerRequestPreparation;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import io.contexa.demo.work.shared.web.AbstractWorkController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/customers")
public class CustomerReadController extends AbstractWorkController {

    private final CustomerRequestPreparation preparation;
    private final CustomerReader reader;

    public CustomerReadController(WorkParticipantQuery participants, CustomerRequestPreparation preparation,
            CustomerReader reader) {
        super(participants);
        this.preparation = preparation;
        this.reader = reader;
    }

    @PostMapping("/{id}/read")
    public ResponseEntity<CustomerReadResult> read(@PathVariable String id, @Valid @RequestBody CustomerReadInput input,
            HttpServletRequest request, Authentication authentication) {
        CustomerRequestSnapshot snapshot = preparation.prepare(BusinessContextAttributes.requestId(request),
                participant(request, authentication), id, input.purpose(), input.approvalId());
        BusinessContextAttributes.attach(request, snapshot);
        return result(reader.read(snapshot));
    }
}
