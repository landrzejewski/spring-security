package pl.training.shop.integration;

import org.javamoney.moneta.Money;
import pl.training.shop.payments.adapters.persistence.jpa.PaymentEntity;
import pl.training.shop.payments.domain.PaymentStatus;

import java.time.Instant;

import static pl.training.shop.payments.domain.PaymentStatus.STARTED;

public class PaymentFixtures {

    public static final String TEST_ID = "4828124d-e43e-4f59-a5f6-3cbfecc9898f";
    public static final String TEST_CURRENCY_CODE = "PLN";
    public static final Money TEST_MONEY_VALUE = Money.of(1_000, TEST_CURRENCY_CODE);
    public static final PaymentStatus TEST_STATUS = STARTED;
    public static final Instant TEST_TIMESTAMP = Instant.now();
    public static final Money TEST_FEE = Money.of(10, TEST_CURRENCY_CODE);
    public static Money TEST_MONEY_VALUE_WITH_FEE = TEST_MONEY_VALUE.add(TEST_FEE);

    public static PaymentEntity createEntity(String status) {
        var entity = new PaymentEntity();
        entity.setId(TEST_ID);
        entity.setValue(TEST_MONEY_VALUE_WITH_FEE.getNumber().doubleValueExact());
        entity.setCurrencyCode(TEST_CURRENCY_CODE);
        entity.setTimestamp(TEST_TIMESTAMP);
        entity.setStatus(status);
        return entity;
    }

}
