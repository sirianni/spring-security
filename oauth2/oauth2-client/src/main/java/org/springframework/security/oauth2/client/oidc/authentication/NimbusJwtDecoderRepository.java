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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.util.StringUtils;

public class NimbusJwtDecoderRepository implements JwtDecoderRepository {

	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

	@Override
	public JwtDecoder getJwtDecoder(ClientRegistration clientRegistration) {
		JwtDecoder jwtDecoder = this.jwtDecoders.get(clientRegistration.getRegistrationId());
		if (jwtDecoder == null) {
			if (!StringUtils.hasText(clientRegistration.getProviderDetails().getJwkSetUri())) {
				OAuth2Error oauth2Error = new OAuth2Error(
						MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
						"Failed to find a Signature Verifier for Client Registration: '" +
								clientRegistration.getRegistrationId() + "'. Check to ensure you have configured the JwkSet URI.",
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			jwtDecoder = new NimbusJwtDecoderJwkSupport(clientRegistration.getProviderDetails().getJwkSetUri());
			this.jwtDecoders.put(clientRegistration.getRegistrationId(), jwtDecoder);
		}
		return jwtDecoder;
	}

}
