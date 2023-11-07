package pl.training.shop.integration;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import pl.training.shop.Application;
import pl.training.shop.payments.adapters.persistence.jpa.PaymentEntity;

import java.util.Locale;

import static org.hamcrest.core.Is.is;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.DEFINED_PORT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static pl.training.shop.integration.PaymentFixtures.*;

@WithMockUser(roles = "ADMIN")
@SpringBootTest(classes = Application.class, webEnvironment = DEFINED_PORT)
@AutoConfigureMockMvc
@ExtendWith(SpringExtension.class)
class PaymentRestAdapterIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private EntityManager entityManager;

    @Transactional
    @Test
    void given_payment_when_get_by_id_then_returns_payment() throws Exception {
        var paymentEntity = createEntity(TEST_STATUS.name());
        if (entityManager.find(PaymentEntity.class, paymentEntity.getId()) == null) {
            entityManager.persist(paymentEntity);
            entityManager.flush();
        }
        mockMvc.perform(get("/api/payments/" + TEST_ID)
                        .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(TEST_ID)))
                .andExpect(jsonPath("$.status", is(TEST_STATUS.name())))
                .andExpect(jsonPath("$.value", is(TEST_MONEY_VALUE_WITH_FEE.toString())));
    }

    @Test
    void when_get_by_invalid_id_then_returns_not_found_status() throws Exception {
        mockMvc.perform(get("/api/payments/1")
                        .accept(APPLICATION_JSON)
                        .locale(new Locale("pl", "PL")))
                .andExpect(status().isForbidden());
    }

}
