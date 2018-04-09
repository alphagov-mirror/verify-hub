package uk.gov.ida.hub.samlengine.proxy;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import uk.gov.ida.saml.metadata.EidasMetadataResolverRepository;

import java.net.URI;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CountrySingleSignOnServiceHelperTest {
    @InjectMocks
    private CountrySingleSignOnServiceHelper service;

    @Mock
    private MetadataResolver metadataResolver;

    @Mock
    private EidasMetadataResolverRepository eidasMetadataResolverRepository;

    private String entityId = "the-entity-id";

    @Before
    public void setUp(){
        when(eidasMetadataResolverRepository.getMetadataResolver(entityId)).thenReturn(Optional.of(metadataResolver));
    }

    @Test
    public void getSingleSignOn() throws Exception {
        // Given
        SingleSignOnServiceBuilder singleSignOnServiceBuilder = new SingleSignOnServiceBuilder();
        SingleSignOnService singleSignOnService = singleSignOnServiceBuilder.buildObject();
        singleSignOnService.setLocation("http://the-sso-location");

        IDPSSODescriptorBuilder idpssoDescriptorBuilder = new IDPSSODescriptorBuilder();
        IDPSSODescriptor idpssoDescriptor = idpssoDescriptorBuilder.buildObject();
        idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService);
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        EntityDescriptorBuilder entityDescriptorBuilder = new EntityDescriptorBuilder();
        EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
        entityDescriptor.setEntityID(entityId);
        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

        when(metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityDescriptor.getEntityID())))).thenReturn(entityDescriptor);

        // When
        URI singleSignOnUri = service.getSingleSignOn(entityDescriptor.getEntityID());

        // Then
        assertThat(singleSignOnUri.toString(), equalTo(singleSignOnService.getLocation()));
        verify(metadataResolver).resolveSingle(any(CriteriaSet.class));
    }
}
