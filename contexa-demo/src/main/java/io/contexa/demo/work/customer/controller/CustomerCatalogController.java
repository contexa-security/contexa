package io.contexa.demo.work.customer.controller;

import io.contexa.demo.work.customer.dto.CustomerCatalogView;
import io.contexa.demo.work.customer.dto.CustomerSummary;
import io.contexa.demo.work.customer.service.CustomerCatalog;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.shared.web.AbstractWorkController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/customers")
public class CustomerCatalogController extends AbstractWorkController {

    private final CustomerCatalog catalog;

    public CustomerCatalogController(WorkParticipantQuery participants, CustomerCatalog catalog) {
        super(participants);
        this.catalog = catalog;
    }

    @GetMapping
    public ResponseEntity<CustomerCatalogView> search(@RequestParam(defaultValue = "") String project,
            @RequestParam(defaultValue = "") String search, HttpServletRequest request, Authentication authentication) {
        var participant = participant(request, authentication);
        return result(catalog.search(participant.username(), project, search));
    }

    @GetMapping("/{id}")
    public ResponseEntity<CustomerSummary> customer(@PathVariable String id, HttpServletRequest request,
            Authentication authentication) {
        participant(request, authentication);
        return result(catalog.customer(id));
    }
}
