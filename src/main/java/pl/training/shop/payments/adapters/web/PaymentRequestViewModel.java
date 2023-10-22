package pl.training.shop.payments.adapters.web;

import lombok.Data;
import pl.training.shop.commons.data.validation.Money;

@Data
public class PaymentRequestViewModel {

    @Money(minValue = 10)
    private String value;

}
