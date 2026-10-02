package io.contexa.demo.observation.receipt.controller;

import io.contexa.demo.observation.receipt.dto.ClientReceiptInput;
import io.contexa.demo.observation.receipt.dto.ClientReceiptView;
import io.contexa.demo.observation.receipt.service.ClientReceiptService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/workspaces/requests")
public class ClientReceiptController extends AbstractVisitorController {

    private final ClientReceiptService receipts;

    public ClientReceiptController(ClientReceiptService receipts) {
        this.receipts = receipts;
    }

    @PostMapping("/{arm}/{id}/receipts")
    public ResponseEntity<ClientReceiptView> record(@PathVariable String arm, @PathVariable UUID id,
            @Valid @RequestBody ClientReceiptInput input, HttpServletRequest request) {
        return result(receipts.record(arm, id, visitorId(request), input));
    }

    @GetMapping("/{arm}/{id}/receipts")
    public ResponseEntity<List<ClientReceiptView>> find(@PathVariable String arm, @PathVariable UUID id,
            HttpServletRequest request) {
        return result(receipts.find(arm, id, visitorId(request)));
    }

}
