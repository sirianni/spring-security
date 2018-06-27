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
