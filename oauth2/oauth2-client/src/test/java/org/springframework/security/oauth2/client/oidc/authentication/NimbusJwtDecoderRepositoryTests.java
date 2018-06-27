/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.client.oidc.authentication;

import static org.hamcrest.CoreMatchers.*;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

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
