package uk.gov.ida.saml.hub.validators.response.matchingservice;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.Appender;
import com.google.common.collect.ImmutableList;
import io.prometheus.client.Counter;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.AttributeAuthorityDescriptor;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.core.security.AssertionsDecrypters;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.SamlAssertionsSignatureValidator;
import uk.gov.ida.saml.security.exception.SamlFailedToDecryptException;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

@RunWith(MockitoJUnitRunner.class)
public class MatchingServiceResponseValidatorTest {
    @Mock
    private SamlResponseSignatureValidator samlResponseSignatureValidator;
    @Mock
    private AssertionDecrypter assertionDecrypter;
    @Mock
    private AssertionDecrypter badAssertionDecrypter;
    @Mock
    private SamlAssertionsSignatureValidator samlAssertionsSignatureValidator;
    @Mock
    private EncryptedResponseFromMatchingServiceValidator encryptedResponseFromMatchingServiceValidator;
    @Mock
    private ResponseAssertionsFromMatchingServiceValidator responseAssertionsFromMatchingServiceValidator;
    @Mock
    private Response response;
    @Mock
    private Appender<ILoggingEvent> mockAppender;

    @Captor
    private ArgumentCaptor<LoggingEvent> captorLoggingEvent;
    @Rule
    public final ExpectedException samlValidationException = ExpectedException.none();

    private MatchingServiceResponseValidator validator;

    @Before
    public void setUp() {
        validator = new MatchingServiceResponseValidator(
            encryptedResponseFromMatchingServiceValidator,
            samlResponseSignatureValidator, 
            new AssertionsDecrypters(
                    List.of(
                            assertionDecrypter,
                            badAssertionDecrypter
                    )
            ),
            samlAssertionsSignatureValidator,
            responseAssertionsFromMatchingServiceValidator);
        final Logger logger = (Logger) LoggerFactory.getLogger(MatchingServiceResponseValidator.class.getSimpleName());
        logger.addAppender(mockAppender);
        logger.setLevel(Level.WARN);
    }

    @After
    public void tearDown() {
        final Logger logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logger.detachAppender(mockAppender);
    }
    
    @Test
    public void shouldValidateResponseIsEncrypted() {
        validator.validate(response);
        verify(encryptedResponseFromMatchingServiceValidator).validate(response);
    }

    @Test
    public void shouldValidateSamlResponseSignature() {
        validator.validate(response);
        verify(samlResponseSignatureValidator).validate(response, AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
    }

    @Test
    public void shouldValidateSamlAssertionSignature() {
        Assertion assertion = mock(Assertion.class);
        List<Assertion> assertions = ImmutableList.of(assertion);
        ValidatedResponse validatedResponse = mock(ValidatedResponse.class);
        
        when(samlResponseSignatureValidator.validate(response, AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME)).thenReturn(validatedResponse);
        when(assertionDecrypter.decryptAssertions(validatedResponse)).thenReturn(assertions);

        validator.validate(response);

        verify(samlAssertionsSignatureValidator).validate(assertions, AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);
    }
    
    @Test
    public void shouldIncrementCounterWheneverADecrypterFailsToDecrypt() throws Exception {
        String issuerValue = "issuerValue";
        Assertion assertion = mock(Assertion.class);
        List<Assertion> assertions = ImmutableList.of(assertion);
        ValidatedResponse validatedResponse = mock(ValidatedResponse.class);

        Issuer responseIssuer = mock(Issuer.class);
        Counter msaDecryptionErrorCounter = mock(Counter.class);
        Counter.Child childCounter = mock(Counter.Child.class);

        setFinalStatic(MatchingServiceResponseValidator.class.getDeclaredField("msaDecryptionErrorCounter"), msaDecryptionErrorCounter);

        when(validatedResponse.getIssuer()).thenReturn(responseIssuer);
        when(responseIssuer.getValue()).thenReturn(issuerValue);
        when(samlResponseSignatureValidator.validate(response, AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME)).thenReturn(validatedResponse);
        when(assertionDecrypter.decryptAssertions(validatedResponse)).thenThrow(SamlFailedToDecryptException.class);
        when(badAssertionDecrypter.decryptAssertions(validatedResponse)).thenReturn(assertions);
        when(msaDecryptionErrorCounter.labels(anyString())).thenReturn(childCounter);
        doNothing().when(childCounter).inc();

        validator.validate(response);

        String expectedMessage = String.format("MatchingServiceResponseValidator failed to decrypt assertions from issuerValue with one of the decrypters", issuerValue);
        verify(mockAppender).doAppend(captorLoggingEvent.capture());
        LoggingEvent loggingEvent = captorLoggingEvent.getValue();
        assertThat(loggingEvent.getLevel()).isEqualTo(Level.WARN);
        assertThat(loggingEvent.getFormattedMessage()).isEqualTo(expectedMessage);

        verify(msaDecryptionErrorCounter).labels(validatedResponse.getIssuer().getValue());
        verify(childCounter).inc();
    }

    @Test
    public void shouldThrowIfAllDecryptersFail() throws Exception {
        String issuerValue = "issuerValue";
        ValidatedResponse validatedResponse = mock(ValidatedResponse.class);

        Issuer responseIssuer = mock(Issuer.class);
        Counter msaDecryptionErrorCounter = mock(Counter.class);
        Counter.Child childCounter = mock(Counter.Child.class);
        setFinalStatic(MatchingServiceResponseValidator.class.getDeclaredField("msaDecryptionErrorCounter"), msaDecryptionErrorCounter);

        when(validatedResponse.getIssuer()).thenReturn(responseIssuer);
        when(responseIssuer.getValue()).thenReturn(issuerValue);
        when(samlResponseSignatureValidator.validate(response, AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME)).thenReturn(validatedResponse);
        when(assertionDecrypter.decryptAssertions(validatedResponse)).thenThrow(SamlFailedToDecryptException.class);
        when(badAssertionDecrypter.decryptAssertions(validatedResponse)).thenThrow(SamlFailedToDecryptException.class);
        when(msaDecryptionErrorCounter.labels(anyString())).thenReturn(childCounter);
        doNothing().when(childCounter).inc();

        SamlFailedToDecryptException exception = assertThrows(SamlFailedToDecryptException.class, () -> validator.validate(response));
        assertEquals(exception.getMessage(), String.format("MatchingServiceResponseValidator could not decrypt assertions from %s with any of the decrypters", issuerValue));

        verify(msaDecryptionErrorCounter, times(2)).labels(validatedResponse.getIssuer().getValue());
        verify(childCounter, times(2)).inc();
    }

    private static void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }
}
