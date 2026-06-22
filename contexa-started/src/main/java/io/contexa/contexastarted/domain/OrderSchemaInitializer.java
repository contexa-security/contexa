package io.contexa.contexastarted.domain;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OrderSchemaInitializer {

    private final JdbcTemplate jdbcTemplate;

    @PostConstruct
    public void initialize() {
        jdbcTemplate.execute("""
                create table if not exists orders (
                    id bigserial primary key,
                    customer_id bigint,
                    product_name varchar(255),
                    amount numeric(19, 2),
                    created_at timestamp
                )
                """);

        Integer count = jdbcTemplate.queryForObject("select count(*) from orders", Integer.class);
        if (count != null && count == 0) {
            jdbcTemplate.update("""
                    insert into orders (customer_id, product_name, amount, created_at)
                    values
                        (1, 'Starter sample order', 49.99, now()),
                        (2, 'Starter review order', 79.50, now())
                    """);
        }
    }
}
