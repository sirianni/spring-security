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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.JwtDecoderRepository;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Login,
 * which leverages the OAuth 2.0 Authorization Code Grant Flow.
 *
 * <p>
 * OAuth 2.0 Login provides an application with the capability to have users log in
 * by using their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 * <p>
 * Defaults are provided for all configuration options with the only required configuration
 * being {@link #clientRegistrationRepository(ClientRegistrationRepository)}.
 * Alternatively, a {@link ClientRegistrationRepository} {@code @Bean} may be registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}'s are populated:
 *
 * <ul>
 * <li>{@link OAuth2AuthorizationRequestRedirectFilter}</li>
 * <li>{@link OAuth2LoginAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository} (required)</li>
 * <li>{@link OAuth2AuthorizedClientService} (optional)</li>
 * <li>{@link GrantedAuthoritiesMapper} (optional)</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * <li>{@link OAuth2AuthorizedClientService}</li>
 * <li>{@link GrantedAuthoritiesMapper}</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if {@link #loginPage(String)} is not configured
 * and {@code DefaultLoginPageGeneratingFilter} is available, than a default login page will be made available</li>
 * </ul>
 *
 * @author Joe Grandja
 * @author Kazuki Shimizu
 * @since 5.0
 * @see HttpSecurity#oauth2Login()
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see OAuth2LoginAuthenticationFilter
 * @see ClientRegistrationRepository
 * @see AbstractAuthenticationFilterConfigurer
 */
public final class OAuth2LoginConfigurer<B extends HttpSecurityBuilder<B>> extends
	AbstractAuthenticationFilterConfigurer<B, OAuth2LoginConfigurer<B>, OAuth2LoginAuthenticationFilter> {

	private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();
	private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();
	private final RedirectionEndpointConfig redirectionEndpointConfig = new RedirectionEndpointConfig();
	private final UserInfoEndpointConfig userInfoEndpointConfig = new UserInfoEndpointConfig();
	private String loginPage;

	/**
	 * Sets the repository of client registrations.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OAuth2LoginConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	/**
	 * Sets the service for authorized client(s).
	 *
	 * @param authorizedClientService the authorized client service
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OAuth2LoginConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizedClientService.class, authorizedClientService);
		return this;
	}

	@Override
	public OAuth2LoginConfigurer<B> loginPage(String loginPage) {
		Assert.hasText(loginPage, "loginPage cannot be empty");
		this.loginPage = loginPage;
		return this;
	}

	/**
	 * Returns the {@link AuthorizationEndpointConfig} for configuring the Authorization Server's Authorization Endpoint.
	 *
	 * @return the {@link AuthorizationEndpointConfig}
	 */
	public AuthorizationEndpointConfig authorizationEndpoint() {
		return this.authorizationEndpointConfig;
	}

	/**
	 * Configuration options for the Authorization Server's Authorization Endpoint.
	 */
	public class AuthorizationEndpointConfig {
		private String authorizationRequestBaseUri;
		private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private AuthorizationEndpointConfig() {
		}

		/**
		 * Sets the base {@code URI} used for authorization requests.
		 *
		 * @param authorizationRequestBaseUri the base {@code URI} used for authorization requests
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
			Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
			this.authorizationRequestBaseUri = authorizationRequestBaseUri;
			return this;
		}

		/**
		 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
		 *
		 * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig authorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 *
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	/**
	 * Returns the {@link TokenEndpointConfig} for configuring the Authorization Server's Token Endpoint.
	 *
	 * @return the {@link TokenEndpointConfig}
	 */
	public TokenEndpointConfig tokenEndpoint() {
		return this.tokenEndpointConfig;
	}

	/**
	 * Configuration options for the Authorization Server's Token Endpoint.
	 */
	public class TokenEndpointConfig {
		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

		private TokenEndpointConfig() {
		}

		/**
		 * Sets the client used for requesting the access token credential from the Token Endpoint.
		 *
		 * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
		 * @return the {@link TokenEndpointConfig} for further configuration
		 */
		public TokenEndpointConfig accessTokenResponseClient(
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {

			Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 *
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	/**
	 * Returns the {@link RedirectionEndpointConfig} for configuring the Client's Redirection Endpoint.
	 *
	 * @return the {@link RedirectionEndpointConfig}
	 */
	public RedirectionEndpointConfig redirectionEndpoint() {
		return this.redirectionEndpointConfig;
	}

	/**
	 * Configuration options for the Client's Redirection Endpoint.
	 */
	public class RedirectionEndpointConfig {
		private String authorizationResponseBaseUri;

		private RedirectionEndpointConfig() {
		}

		/**
		 * Sets the {@code URI} where the authorization response will be processed.
		 *
		 * @param authorizationResponseBaseUri the {@code URI} where the authorization response will be processed
		 * @return the {@link RedirectionEndpointConfig} for further configuration
		 */
		public RedirectionEndpointConfig baseUri(String authorizationResponseBaseUri) {
			Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
			this.authorizationResponseBaseUri = authorizationResponseBaseUri;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 *
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	/**
	 * Returns the {@link UserInfoEndpointConfig} for configuring the Authorization Server's UserInfo Endpoint.
	 *
	 * @return the {@link UserInfoEndpointConfig}
	 */
	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	/**
	 * Configuration options for the Authorization Server's UserInfo Endpoint.
	 */
	public class UserInfoEndpointConfig {
		private JwtDecoderRepository jwtDecoderRepository;
		private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
		private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;
		private Map<String, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();

		private UserInfoEndpointConfig() {
		}

		/**
		 * Sets the OAuth 2.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint.
		 *
		 * @param userService the OAuth 2.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig userService(OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
			Assert.notNull(userService, "userService cannot be null");
			this.userService = userService;
			return this;
		}

		/**
		 * Sets the OpenID Connect 1.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint.
		 *
		 * @param oidcUserService the OpenID Connect 1.0 service used for obtaining the user attributes of the End-User from the UserInfo Endpoint
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig oidcUserService(OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) {
			Assert.notNull(oidcUserService, "oidcUserService cannot be null");
			this.oidcUserService = oidcUserService;
			return this;
		}

		/**
		 * Sets a custom {@link OAuth2User} type and associates it to the provided
		 * client {@link ClientRegistration#getRegistrationId() registration identifier}.
		 *
		 * @param customUserType a custom {@link OAuth2User} type
		 * @param clientRegistrationId the client registration identifier
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig customUserType(Class<? extends OAuth2User> customUserType, String clientRegistrationId) {
			Assert.notNull(customUserType, "customUserType cannot be null");
			Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
			this.customUserTypes.put(clientRegistrationId, customUserType);
			return this;
		}

		/**
		 * Sets the {@link GrantedAuthoritiesMapper} used for mapping {@link OAuth2User#getAuthorities()}.
		 *
		 * @param userAuthoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
			Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
			OAuth2LoginConfigurer.this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class, userAuthoritiesMapper);
			return this;
		}

		public UserInfoEndpointConfig jwtDecoderRepository(JwtDecoderRepository jwtDecoderRepository) {
			Assert.notNull(jwtDecoderRepository, "jwtDecoderRepository cannot be null");
			this.jwtDecoderRepository = jwtDecoderRepository;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 *
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}
	}

	@Override
	public void init(B http) throws Exception {
		OAuth2LoginAuthenticationFilter authenticationFilter =
			new OAuth2LoginAuthenticationFilter(
				OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder()),
				OAuth2ClientConfigurerUtils.getAuthorizedClientService(this.getBuilder()),
				OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI);
		this.setAuthenticationFilter(authenticationFilter);
		this.loginProcessingUrl(OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI);
		if (this.loginPage != null) {
			super.loginPage(this.loginPage);
		}
		super.init(http);

		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient =
			this.tokenEndpointConfig.accessTokenResponseClient;
		if (accessTokenResponseClient == null) {
			accessTokenResponseClient = new NimbusAuthorizationCodeTokenResponseClient();
		}

		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = this.userInfoEndpointConfig.userService;
		if (oauth2UserService == null) {
			if (!this.userInfoEndpointConfig.customUserTypes.isEmpty()) {
				List<OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new ArrayList<>();
				userServices.add(new CustomUserTypesOAuth2UserService(this.userInfoEndpointConfig.customUserTypes));
				userServices.add(new DefaultOAuth2UserService());
				oauth2UserService = new DelegatingOAuth2UserService<>(userServices);
			} else {
				oauth2UserService = new DefaultOAuth2UserService();
			}
		}

		OAuth2LoginAuthenticationProvider oauth2LoginAuthenticationProvider =
			new OAuth2LoginAuthenticationProvider(accessTokenResponseClient, oauth2UserService);
		GrantedAuthoritiesMapper userAuthoritiesMapper = this.getGrantedAuthoritiesMapper();
		if (userAuthoritiesMapper != null) {
			oauth2LoginAuthenticationProvider.setAuthoritiesMapper(userAuthoritiesMapper);
		}
		http.authenticationProvider(this.postProcess(oauth2LoginAuthenticationProvider));

		boolean oidcAuthenticationProviderEnabled = ClassUtils.isPresent(
			"org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());

		if (oidcAuthenticationProviderEnabled) {
			OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = this.userInfoEndpointConfig.oidcUserService;
			if (oidcUserService == null) {
				oidcUserService = new OidcUserService();
			}

			OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider =
				new OidcAuthorizationCodeAuthenticationProvider(accessTokenResponseClient, oidcUserService);
			if (userAuthoritiesMapper != null) {
				oidcAuthorizationCodeAuthenticationProvider.setAuthoritiesMapper(userAuthoritiesMapper);
			}
			if (this.userInfoEndpointConfig.jwtDecoderRepository != null) {
				oidcAuthorizationCodeAuthenticationProvider.setJwtDecoderRepository(this.userInfoEndpointConfig.jwtDecoderRepository);
			}
			http.authenticationProvider(this.postProcess(oidcAuthorizationCodeAuthenticationProvider));
		} else {
			http.authenticationProvider(new OidcAuthenticationRequestChecker());
		}

		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(B http) throws Exception {
		String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
		if (authorizationRequestBaseUri == null) {
			authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		}

		OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
			OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder()), authorizationRequestBaseUri);

		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authorizationRequestFilter.setAuthorizationRequestRepository(
				this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		if (requestCache != null) {
			authorizationRequestFilter.setRequestCache(requestCache);
		}
		http.addFilter(this.postProcess(authorizationRequestFilter));

		OAuth2LoginAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();
		if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
			authenticationFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
		}
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authenticationFilter.setAuthorizationRequestRepository(
				this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl);
	}

	private GrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
		GrantedAuthoritiesMapper grantedAuthoritiesMapper =
				this.getBuilder().getSharedObject(GrantedAuthoritiesMapper.class);
		if (grantedAuthoritiesMapper == null) {
			grantedAuthoritiesMapper = this.getGrantedAuthoritiesMapperBean();
			if (grantedAuthoritiesMapper != null) {
				this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class, grantedAuthoritiesMapper);
			}
		}
		return grantedAuthoritiesMapper;
	}

	private GrantedAuthoritiesMapper getGrantedAuthoritiesMapperBean() {
		Map<String, GrantedAuthoritiesMapper> grantedAuthoritiesMapperMap =
			BeanFactoryUtils.beansOfTypeIncludingAncestors(
				this.getBuilder().getSharedObject(ApplicationContext.class),
				GrantedAuthoritiesMapper.class);
		return (!grantedAuthoritiesMapperMap.isEmpty() ? grantedAuthoritiesMapperMap.values().iterator().next() : null);
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || this.isCustomLoginPage()) {
			return;
		}

		Iterable<ClientRegistration> clientRegistrations = null;
		ClientRegistrationRepository clientRegistrationRepository =
			OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder());
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}
		if (clientRegistrations == null) {
			return;
		}

		String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri != null ?
			this.authorizationEndpointConfig.authorizationRequestBaseUri :
			OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
		Map<String, String> authenticationUrlToClientName = new HashMap<>();

		clientRegistrations.forEach(registration -> authenticationUrlToClientName.put(
			authorizationRequestBaseUri + "/" + registration.getRegistrationId(),
			registration.getClientName()));
		loginPageGeneratingFilter.setOauth2LoginEnabled(true);
		loginPageGeneratingFilter.setOauth2AuthenticationUrlToClientName(authenticationUrlToClientName);
		loginPageGeneratingFilter.setLoginPageUrl(this.getLoginPage());
		loginPageGeneratingFilter.setFailureUrl(this.getFailureUrl());
	}

	private static class OidcAuthenticationRequestChecker implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			OAuth2LoginAuthenticationToken authorizationCodeAuthentication =
				(OAuth2LoginAuthenticationToken) authentication;

			// Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// scope
			// 		REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
			if (authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationRequest().getScopes().contains(OidcScopes.OPENID)) {

				OAuth2Error oauth2Error = new OAuth2Error(
					"oidc_provider_not_configured",
					"An OpenID Connect Authentication Provider has not been configured. " +
						"Check to ensure you include the dependency 'spring-security-oauth2-jose'.",
					null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}

			return null;
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
		}
	}
}
