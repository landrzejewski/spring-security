package pl.training.shop.payments.adapters.rest;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.Value;
import pl.training.shop.commons.data.validation.Base;
import pl.training.shop.commons.data.validation.Extended;
import pl.training.shop.commons.data.validation.Money;

@Data
public class PaymentRequestDto {

    @Min(value = 1, groups = {Base.class, Extended.class})
    private Long id;
    @Pattern(regexp = "\\d+ [A-Z]+", groups = Base.class)
    @NotBlank(groups = Base.class)
    @Money(minValue = 10, groups = Extended.class)
    private String value;

}
