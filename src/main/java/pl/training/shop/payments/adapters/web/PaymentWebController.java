package pl.training.shop.payments.adapters.web;

import jakarta.annotation.security.RolesAllowed;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import pl.training.shop.payments.ports.PaymentService;

@RequestMapping("payments")
@Controller
@RequiredArgsConstructor
public class PaymentWebController {

    private final PaymentService paymentService;
    private final PaymentWebMapper mapper;

    @GetMapping("process")
    public String showPaymentForm(Model model) {
        var paymentRequestViewModel = new PaymentRequestViewModel();
        paymentRequestViewModel.setValue("100 PLN");
        model.addAttribute("paymentRequest", paymentRequestViewModel);
        return "payments/payment-form";
    }

    //@PreFilter("filterObject.owner == authentication.name") // can be uses on jpa repositories its better to use spel
    //@PostFilter("filterObject.owner == authentication.name")

    //@PreAuthorize("#paymentRequestViewModel.value > 10")
    //@PostAuthorize("returnObject.contains('payment-summary')")

    //@Secured("ROLE_SUPER_ADMIN")
    //@RolesAllowed("SUPER_ADMIN")
    @PostMapping("process")
    public String process(@Valid @ModelAttribute("paymentRequest") PaymentRequestViewModel paymentRequestViewModel,
                          BindingResult bindingResult,
                          RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            return "payments/payment-form";
        }
        var paymentRequest = mapper.toDomain(paymentRequestViewModel);
        var payment = paymentService.process(paymentRequest);
        var paymentViewModel = mapper.toViewModel(payment);
        redirectAttributes.addFlashAttribute("payment", paymentViewModel);
        return "redirect:/payments/payment-summary";
    }

    @GetMapping("payment-summary")
    public String showSummary(Model model) {
        if (!model.containsAttribute("payment")) {
            return "redirect:/";
        }
        return "payments/payment-summary";
    }

}
