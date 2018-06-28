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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.List;

/**
 * An implementation of an {@link AuthenticationProvider}
 * for the OpenID Connect Core 1.0 Authorization Code Grant Flow.
 * <p>
 * This {@link AuthenticationProvider} is responsible for authenticating
 * an Authorization Code credential with the Authorization Server's Token Endpoint
 * and if valid, exchanging it for an Access Token credential.
 * <p>
 * It will also obtain the user attributes of the End-User (Resource Owner)
 * from the UserInfo Endpoint using an {@link OAuth2UserService},
 * which will create a {@code Principal} in the form of an {@link OidcUser}.
 * The {@code OidcUser} is then associated to the {@link OAuth2LoginAuthenticationToken}
 * to complete the authentication.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2LoginAuthenticationToken
 * @see OAuth2AccessTokenResponseClient
 * @see OidcUserService
 * @see OidcUser
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest">Section 3.1.3.1 Token Request</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">Section 3.1.3.3 Token Response</a>
 */
public class OidcAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
	private static final String INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE = "invalid_redirect_uri_parameter";
	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
	private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	private final OAuth2UserService<OidcUserRequest, OidcUser> userService;
	private JwtDecoderRepository jwtDecoderRepository = new NimbusJwtDecoderRepository();
	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	/**
	 * Constructs an {@code OidcAuthorizationCodeAuthenticationProvider} using the provided parameters.
	 *
	 * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
	 * @param userService the service used for obtaining the user attributes of the End-User from the UserInfo Endpoint
	 */
	public OidcAuthorizationCodeAuthenticationProvider(
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
		OAuth2UserService<OidcUserRequest, OidcUser> userService) {

		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		Assert.notNull(userService, "userService cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2LoginAuthenticationToken authorizationCodeAuthentication =
			(OAuth2LoginAuthenticationToken) authentication;

		// Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		// scope
		// 		REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
		if (!authorizationCodeAuthentication.getAuthorizationExchange()
			.getAuthorizationRequest().getScopes().contains(OidcScopes.OPENID)) {
			// This is NOT an OpenID Connect Authentication Request so return null
			// and let OAuth2LoginAuthenticationProvider handle it instead
			return null;
		}

		OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication
			.getAuthorizationExchange().getAuthorizationRequest();
		OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication
			.getAuthorizationExchange().getAuthorizationResponse();

		if (authorizationResponse.statusError()) {
			throw new OAuth2AuthenticationException(
				authorizationResponse.getError(), authorizationResponse.getError().toString());
		}

		if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		if (!authorizationResponse.getRedirectUri().equals(authorizationRequest.getRedirectUri())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		OAuth2AccessTokenResponse accessTokenResponse =
			this.accessTokenResponseClient.getTokenResponse(
				new OAuth2AuthorizationCodeGrantRequest(
					authorizationCodeAuthentication.getClientRegistration(),
					authorizationCodeAuthentication.getAuthorizationExchange()));

		OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();

		ClientRegistration clientRegistration = authorizationCodeAuthentication.getClientRegistration();

		if (!accessTokenResponse.getAdditionalParameters().containsKey(OidcParameterNames.ID_TOKEN)) {
			OAuth2Error invalidIdTokenError = new OAuth2Error(
				INVALID_ID_TOKEN_ERROR_CODE,
				"Missing (required) ID Token in Token Response for Client Registration: " + clientRegistration.getRegistrationId(),
				null);
			throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
		}

		JwtDecoder jwtDecoder = this.jwtDecoderRepository.getJwtDecoder(clientRegistration);
		Jwt jwt = jwtDecoder.decode((String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));
		OidcIdToken idToken = new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());

		this.validateIdToken(idToken, clientRegistration);

		OidcUser oidcUser = this.userService.loadUser(
			new OidcUserRequest(clientRegistration, accessToken, idToken));

		Collection<? extends GrantedAuthority> mappedAuthorities =
			this.authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());

		OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
			authorizationCodeAuthentication.getClientRegistration(),
			authorizationCodeAuthentication.getAuthorizationExchange(),
			oidcUser,
			mappedAuthorities,
			accessToken);
		authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());

		return authenticationResult;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for mapping {@link OidcUser#getAuthorities()}}
	 * to a new set of authorities which will be associated to the {@link OAuth2LoginAuthenticationToken}.
	 *
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
	 */
	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	public void setJwtDecoderRepository(JwtDecoderRepository jwtDecoderRepository) {
		this.jwtDecoderRepository = jwtDecoderRepository;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private void validateIdToken(OidcIdToken idToken, ClientRegistration clientRegistration) {
		// 3.1.3.7  ID Token Validation
		// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

		// Validate REQUIRED Claims
		URL issuer = idToken.getIssuer();
		if (issuer == null) {
			this.throwInvalidIdTokenException();
		}
		String subject = idToken.getSubject();
		if (subject == null) {
			this.throwInvalidIdTokenException();
		}
		List<String> audience = idToken.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			this.throwInvalidIdTokenException();
		}
		Instant expiresAt = idToken.getExpiresAt();
		if (expiresAt == null) {
			this.throwInvalidIdTokenException();
		}
		Instant issuedAt = idToken.getIssuedAt();
		if (issuedAt == null) {
			this.throwInvalidIdTokenException();
		}

		// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
		// MUST exactly match the value of the iss (issuer) Claim.
		// TODO Depends on gh-4413

		// 3. The Client MUST validate that the aud (audience) Claim contains its client_id value
		// registered at the Issuer identified by the iss (issuer) Claim as an audience.
		// The aud (audience) Claim MAY contain an array with more than one element.
		// The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
		// or if it contains additional audiences not trusted by the Client.
		if (!audience.contains(clientRegistration.getClientId())) {
			this.throwInvalidIdTokenException();
		}

		// 4. If the ID Token contains multiple audiences,
		// the Client SHOULD verify that an azp Claim is present.
		String authorizedParty = idToken.getAuthorizedParty();
		if (audience.size() > 1 && authorizedParty == null) {
			this.throwInvalidIdTokenException();
		}

		// 5. If an azp (authorized party) Claim is present,
		// the Client SHOULD verify that its client_id is the Claim Value.
		if (authorizedParty != null && !authorizedParty.equals(clientRegistration.getClientId())) {
			this.throwInvalidIdTokenException();
		}

		// 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
		// in the id_token_signed_response_alg parameter during Registration.
		// TODO Depends on gh-4413

		// 9. The current time MUST be before the time represented by the exp Claim.
		Instant now = Instant.now();
		if (!now.isBefore(expiresAt)) {
			this.throwInvalidIdTokenException();
		}

		// 10. The iat Claim can be used to reject tokens that were issued too far away from the current time,
		// limiting the amount of time that nonces need to be stored to prevent attacks.
		// The acceptable range is Client specific.
		Instant maxIssuedAt = Instant.now().plusSeconds(30);
		if (issuedAt.isAfter(maxIssuedAt)) {
			this.throwInvalidIdTokenException();
		}

		// 11. If a nonce value was sent in the Authentication Request,
		// a nonce Claim MUST be present and its value checked to verify
		// that it is the same value as the one that was sent in the Authentication Request.
		// The Client SHOULD check the nonce value for replay attacks.
		// The precise method for detecting replay attacks is Client specific.
		// TODO Depends on gh-4442

	}

	private void throwInvalidIdTokenException() {
		OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE);
		throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
	}
}
