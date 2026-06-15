package io.contexa.contexastarted.service;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexastarted.domain.Order;
import io.contexa.contexastarted.domain.OrderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Demonstrates four @Protectable usage patterns.
 *
 * Each pattern applies a different level of AI-driven security:
 *
 *   Pattern 1: @Protectable              — async evaluation, immediate response
 *   Pattern 2: @Protectable(ownerField)  — owner-based access check (async)
 *   Pattern 3: @Protectable(sync=true)   — blocks until AI decision is made
 *   Pattern 4: @Protectable(ownerField, sync=true) — strongest protection
 */
@Service
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;

    /**
     * Pattern 1: Basic protection (async).
     * AI evaluates in the background. The response returns immediately.
     */
    @Protectable(verificationRequired = false)
    public List<Order> findAll() {
        return orderRepository.findAll();
    }

    /**
     * Pattern 2: Owner-based protection (async).
     * AI verifies that the current user matches the customerId.
     */
    @Protectable(ownerField = "customerId")
    public List<Order> findByCustomer(Long customerId) {
        return orderRepository.findByCustomerId(customerId);
    }

    /**
     * Pattern 3: Synchronous protection.
     * Waits for AI evaluation before executing. Use for data-modifying operations.
     *
     * Possible ZeroTrustAction results:
     *   ALLOW (200)            — order is created
     *   BLOCK (403)            — request denied
     *   CHALLENGE (401)        — MFA required
     *   ESCALATE (423)         — manual review required
     *   PENDING_ANALYSIS (503) — AI analysis in progress
     */
    @Protectable(verificationRequired = false)
    public Order createOrder(Order order) {
        return orderRepository.save(order);
    }

    /**
     * Pattern 4: Synchronous + owner-based protection.
     * Strongest protection level. Use for sensitive delete/update operations.
     */
    @Protectable(ownerField = "customerId", sync = true)
    public void deleteOrder(Long customerId, Long orderId) {
        Order order = orderRepository.findById(orderId)
                .orElseThrow(() -> new RuntimeException("Order not found: " + orderId));
        orderRepository.delete(order);
    }
}
