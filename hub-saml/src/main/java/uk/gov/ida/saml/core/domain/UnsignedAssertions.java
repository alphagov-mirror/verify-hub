package uk.gov.ida.saml.core.domain;

import java.util.Optional;

public interface UnsignedAssertions {
    Optional<EidasCountrySignedResponseWithEncryptedKeys> getUnsignedAssertions() ;
    void setUnisgnedAssertions(EidasCountrySignedResponseWithEncryptedKeys unsignedAssertions);
}
