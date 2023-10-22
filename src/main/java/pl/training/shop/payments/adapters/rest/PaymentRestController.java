package pl.training.shop.payments.adapters.rest;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import pl.training.shop.commons.data.Page;
import pl.training.shop.commons.data.ResultPage;
import pl.training.shop.commons.data.validation.Base;
import pl.training.shop.commons.web.LocationUri;
import pl.training.shop.payments.ports.PaymentService;

import static pl.training.shop.payments.domain.PaymentStatus.STARTED;

@RequestMapping("/api/payments")
@RestController
@RequiredArgsConstructor
public class PaymentRestController {

    //private final RestExceptionResponseBuilder exceptionResponseBuilder;
    private final PaymentService paymentService;
    private final PaymentRestMapper mapper;

    @PostMapping
    public ResponseEntity<PaymentDto> process(@RequestBody @Validated(Base.class) /*@Valid*/ PaymentRequestDto paymentRequestDto) {
        var paymentRequest = mapper.toDomain(paymentRequestDto);
        var payment = paymentService.process(paymentRequest);
        var paymentDto = mapper.toDto(payment);
        var locationUri = LocationUri.fromRequest(paymentDto.getId());
        return ResponseEntity.created(locationUri)
                .body(paymentDto);
    }

    @GetMapping("{id:\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}}")
    public PaymentDto getById(@PathVariable String id) {
        var payment = paymentService.getById(id);
        return mapper.toDto(payment);
    }

    @GetMapping("started")
    public ResponseEntity<ResultPage<PaymentDto>> getStartedPayments(
            @RequestParam(required = false, defaultValue = "0") int pageNumber,
            @RequestParam(required = false, defaultValue = "10") int pageSize
    ) {
        var resultPage = paymentService.getByStatus(STARTED, new Page(pageNumber, pageSize));
        var resultPageDto = mapper.toDto(resultPage);
        return ResponseEntity.ok(resultPageDto);
    }

    /*@ExceptionHandler(PaymentNotFoundException.class)
    public ResponseEntity<ExceptionDto> onPaymentNotFoundException(PaymentNotFoundException paymentNotFoundException, Locale locale) {
        *//*return ResponseEntity.status(NOT_FOUND)
                .body(new ExceptionDto("Payment not found"));*//*
        return exceptionResponseBuilder.build(paymentNotFoundException, NOT_FOUND, locale);
    }*/

}
