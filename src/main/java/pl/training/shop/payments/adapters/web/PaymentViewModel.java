
package pl.training.shop.payments.adapters.web;

import lombok.Data;

import java.io.Serializable;
import java.time.Instant;

@Data
public class PaymentViewModel implements Serializable {

    private String value;
    private String status;

}
