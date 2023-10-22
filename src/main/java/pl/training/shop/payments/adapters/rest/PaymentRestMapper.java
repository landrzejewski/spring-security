package pl.training.shop.payments.adapters.rest;

import org.mapstruct.Mapper;
import pl.training.shop.commons.data.MoneyMapper;
import pl.training.shop.commons.data.ResultPage;
import pl.training.shop.payments.domain.Payment;
import pl.training.shop.payments.domain.PaymentRequest;

@Mapper(componentModel = "spring", uses = MoneyMapper.class)
public interface PaymentRestMapper {

    PaymentRequest toDomain(PaymentRequestDto paymentRequestDto);

    PaymentDto toDto(Payment payment);

    ResultPage<PaymentDto> toDto(ResultPage<Payment> paymentResultPage);

}
