package io.contexa.contexastarted.controller;

import io.contexa.contexastarted.domain.Order;
import io.contexa.contexastarted.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;

    @GetMapping
    public List<Order> listOrders() {
        return orderService.findAll();
    }

    @GetMapping("/customer/{customerId}")
    public List<Order> listByCustomer(@PathVariable Long customerId) {
        return orderService.findByCustomer(customerId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Order createOrder(@RequestBody Order order) {
        return orderService.createOrder(order);
    }

    @DeleteMapping("/{orderId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteOrder(@RequestParam Long customerId, @PathVariable Long orderId) {
        orderService.deleteOrder(customerId, orderId);
    }
}
