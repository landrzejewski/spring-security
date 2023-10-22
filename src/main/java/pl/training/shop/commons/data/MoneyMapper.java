package pl.training.shop.commons.data;

import org.javamoney.moneta.Money;
import org.mapstruct.Mapper;

import java.util.Optional;
import java.util.function.Function;

@Mapper(componentModel = "spring")
public interface MoneyMapper {

    default String toText(Money money) {
        return map(money, Money::toString);
    }

    default Money toMoney(String text) {
        return map(text, Money::parse);
    }

    private <I, O> O map(I input, Function<I, O> mapper) {
        return Optional.ofNullable(input)
                .map(mapper)
                .orElseThrow(IllegalArgumentException::new);
    }

}
