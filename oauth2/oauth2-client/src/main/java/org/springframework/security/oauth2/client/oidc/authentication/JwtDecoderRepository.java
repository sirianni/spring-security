package org.springframework.security.oauth2.client.oidc.authentication;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

public interface JwtDecoderRepository {

	static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";

	JwtDecoder getJwtDecoder(ClientRegistration clientRegistration);
}
