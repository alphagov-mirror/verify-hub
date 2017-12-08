package uk.gov.ida.hub.config.dto;

import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Test;
import uk.gov.ida.hub.config.domain.Certificate;
import uk.gov.ida.hub.config.domain.builders.EncryptionCertificateBuilder;
import uk.gov.ida.shared.utils.datetime.DateTimeFreezer;

import static org.assertj.core.api.Assertions.assertThat;

public class CertificateHealthCheckDtoTest{

    @After
    public void tearDown(){
        DateTimeFreezer.unfreezeTime();
    }

    @Test
     public void testCreateCertificateHealthCheckDto() throws Exception {
        DateTimeFreezer.freezeTime(new DateTime(2117, 1, 1, 00, 00));

        Certificate certificate = new EncryptionCertificateBuilder().build();
        CertificateHealthCheckDto checked = CertificateHealthCheckDto.createCertificateHealthCheckDto("entityId", certificate, org.joda.time.Duration.millis(1000));
        assertThat(checked.getEntityId()).isEqualTo("entityId");
        assertThat(checked.getStatus()).isEqualTo(CertificateExpiryStatus.CRITICAL);
        assertThat(checked.getMessage()).isEqualTo("EXPIRED");
    }

    @Test
    public void testCreateCertificateHealthCheckDto_forwarning() throws Exception {
        DateTimeFreezer.freezeTime(new DateTime(2116, 6, 1, 00, 00));

        Certificate certificate = new EncryptionCertificateBuilder().build();
        CertificateHealthCheckDto checked = CertificateHealthCheckDto.createCertificateHealthCheckDto("entityId", certificate, org.joda.time.Duration.standardDays(30));
        assertThat(checked.getEntityId()).isEqualTo("entityId");
        assertThat(checked.getStatus()).isEqualTo(CertificateExpiryStatus.WARNING);
        assertThat(checked.getMessage()).isEqualTo("Expires on Fri 12 Jun 2116");
    }


    @Test
    public void testCreateCertificateHealthCheckDto_returnsOK() throws Exception {
        DateTimeFreezer.freezeTime(new DateTime(2017, 1, 1, 00, 00));

        Certificate certificate = new EncryptionCertificateBuilder().build();
        CertificateHealthCheckDto checked = CertificateHealthCheckDto.createCertificateHealthCheckDto("entityId", certificate, org.joda.time.Duration.standardDays(30));
        assertThat(checked.getEntityId()).isEqualTo("entityId");
        assertThat(checked.getStatus()).isEqualTo(CertificateExpiryStatus.OK);
        assertThat(checked.getMessage()).isEmpty();
    }


}