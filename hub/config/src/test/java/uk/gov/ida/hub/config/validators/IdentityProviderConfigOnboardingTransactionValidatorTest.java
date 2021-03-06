package uk.gov.ida.hub.config.validators;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.ida.hub.config.data.LocalConfigRepository;
import uk.gov.ida.hub.config.domain.IdentityProviderConfig;
import uk.gov.ida.hub.config.domain.TransactionConfig;
import uk.gov.ida.hub.config.exceptions.ConfigValidationException;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.when;
import static uk.gov.ida.hub.config.domain.builders.IdentityProviderConfigDataBuilder.anIdentityProviderConfigData;
import static uk.gov.ida.hub.config.domain.builders.TransactionConfigBuilder.aTransactionConfigData;
import static uk.gov.ida.hub.config.exceptions.ConfigValidationException.createAbsentOnboardingTransactionConfigException;

@RunWith(MockitoJUnitRunner.class)
public class IdentityProviderConfigOnboardingTransactionValidatorTest {

    IdentityProviderConfigOnboardingTransactionValidator identityProviderConfigOnboardingTransactionValidator;

    @Mock
    private LocalConfigRepository<TransactionConfig> transactionConfigRepository;

    @Before
    public void setUp() {
        identityProviderConfigOnboardingTransactionValidator = new IdentityProviderConfigOnboardingTransactionValidator(
                transactionConfigRepository
        );
    }

    @Test
    public void validate_shouldNotThrowExceptionWhenOnboardingTransactionEntityIdExists() {
        String transactionEntityID = "transactionEntityID";
        IdentityProviderConfig identityProviderConfig = anIdentityProviderConfigData().withOnboarding(List.of(transactionEntityID)).build();

        TransactionConfig transactionConfigEntity = aTransactionConfigData().build();
        when(transactionConfigRepository.getData(transactionEntityID)).thenReturn(Optional.ofNullable(transactionConfigEntity));

        identityProviderConfigOnboardingTransactionValidator.validate(identityProviderConfig);
    }

    @Test
    public void validate_shouldNotThrowExceptionWhenOnboardingTransactionEntityIsNotSpecified() {
        IdentityProviderConfig identityProviderConfig = anIdentityProviderConfigData().withoutOnboarding().build();
        identityProviderConfigOnboardingTransactionValidator.validate(identityProviderConfig);
    }

    @Test
    public void validate_shouldThrowExceptionWhenOnboardingTransactionDoesNotExist() {
        String transactionEntityID = "transactionEntityID";
        String idpEntityId = "idpEntityId";
        IdentityProviderConfig identityProviderConfig = anIdentityProviderConfigData()
                .withEntityId(idpEntityId)
                .withOnboarding(List.of(transactionEntityID))
                .build();

        when(transactionConfigRepository.getData(transactionEntityID))
                .thenReturn(Optional.empty());

        try {
            identityProviderConfigOnboardingTransactionValidator.validate(identityProviderConfig);
            fail("fail");
        } catch (ConfigValidationException e) {
            final ConfigValidationException expectedException = createAbsentOnboardingTransactionConfigException(transactionEntityID, idpEntityId);

            assertThat(expectedException.getMessage()).isEqualTo(e.getMessage());
        }
    }
}
