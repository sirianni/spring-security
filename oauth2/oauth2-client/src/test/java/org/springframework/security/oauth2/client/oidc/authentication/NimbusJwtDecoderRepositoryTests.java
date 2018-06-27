package org.springframework.security.oauth2.client.oidc.authentication;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

@PrepareForTest(ClientRegistration.class)
@RunWith(PowerMockRunner.class)
public class NimbusJwtDecoderRepositoryTests {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private ClientRegistration clientRegistration;

	private NimbusJwtDecoderRepository jwtDecoderRepository = new NimbusJwtDecoderRepository();

	@Before
	public void setUp() throws Exception {
		this.clientRegistration = mock(ClientRegistration.class);
		ClientRegistration.ProviderDetails providerDetails = mock(ClientRegistration.ProviderDetails.class);

		when(clientRegistration.getRegistrationId()).thenReturn("client-registration-id-1");
		when(clientRegistration.getProviderDetails()).thenReturn(providerDetails);
	}

	@Test
	public void authenticateWhenJwkSetUriNotSetThenThrowOAuth2AuthenticationException() {
		this.exception.expect(OAuth2AuthenticationException.class);
		this.exception.expectMessage(containsString("missing_signature_verifier"));

		jwtDecoderRepository.getJwtDecoder(clientRegistration);
	}
}
