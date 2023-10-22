package pl.training.shop.payments.domain;

import lombok.Builder;
import lombok.Value;
import org.javamoney.moneta.Money;
import pl.training.shop.payments.domain.PaymentStatus;

import java.time.Instant;

@Builder
@Value
public class Payment {

    String id;
    Money value;
    Instant timestamp;
    PaymentStatus status;

}
