package io.contexa.showcase.portal.combination;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Visitor API of the exploration grid (deck p.13): the map of stored real runs and one cell's run. Reading is free;
 * running a new cell goes through the live space and its gate.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class CombinationController {

    private final CombinationService combinations;

    public CombinationController(CombinationService combinations) {
        this.combinations = combinations;
    }

    @GetMapping("/api/combinations")
    public ResponseEntity<Map<String, Object>> grid(@RequestParam("employee") String employee,
                                                    @RequestParam("ticket") String ticket,
                                                    @RequestParam("device") String device) {
        try {
            List<CombinationService.CellView> cells = combinations.grid(employee, Combination.Ticket.valueOf(ticket),
                    Combination.Device.valueOf(device));
            return ResponseEntity.ok(Map.of("catalogVersion", CombinationCatalog.VERSION, "employees",
                    Combination.EMPLOYEES, "items", Combination.ITEMS, "cells", cells));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }

    @GetMapping("/api/combinations/{key}")
    public ResponseEntity<CombinationService.CombinationView> combination(@PathVariable("key") String key) {
        try {
            return ResponseEntity.ok(combinations.view(Combination.parse(key)));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }
}
