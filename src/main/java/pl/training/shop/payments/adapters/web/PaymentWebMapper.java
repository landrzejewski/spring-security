package pl.training.shop.payments.adapters.web;

import org.mapstruct.Mapper;
import pl.training.shop.commons.data.MoneyMapper;
import pl.training.shop.payments.domain.Payment;
import pl.training.shop.payments.domain.PaymentRequest;

@Mapper(componentModel = "spring", uses = MoneyMapper.class)
public interface PaymentWebMapper {

    PaymentRequest toDomain(PaymentRequestViewModel paymentRequestViewModel);

    PaymentViewModel toViewModel(Payment payment);

}
