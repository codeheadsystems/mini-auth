package com.codeheadsystems.minioidc.auth;

import com.codeheadsystems.pkauth.api.AssertionResult;
import com.codeheadsystems.pkauth.api.AuthenticationResponseJson;
import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.api.FinishAuthenticationRequest;
import com.codeheadsystems.pkauth.api.FinishRegistrationRequest;
import com.codeheadsystems.pkauth.api.RegistrationResponseJson;
import com.codeheadsystems.pkauth.api.RegistrationResult;
import com.codeheadsystems.pkauth.api.StartAuthenticationRequest;
import com.codeheadsystems.pkauth.api.StartAuthenticationResponse;
import com.codeheadsystems.pkauth.api.StartRegistrationRequest;
import com.codeheadsystems.pkauth.api.StartRegistrationResponse;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.json.PkAuthObjectMappers;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.util.Optional;
import tools.jackson.databind.json.JsonMapper;

/**
 * The pk-auth-backed {@link HumanAuthenticator}: it embeds pk-auth's framework-neutral
 * {@link PasskeyAuthenticationService} to run the real WebAuthn registration and assertion
 * ceremonies (WebAuthn4J under the hood), and reads the authenticated identity straight off the
 * verified assertion — {@link AssertionResult.Success#userHandle()} → {@link UserLookup} → username
 * — so mini-oidc mints its OWN tokens and never depends on pk-auth's JWT.
 *
 * <p>pk-auth's ceremony DTOs are (de)serialized with its own {@link PkAuthObjectMappers} mapper
 * (the custom codecs for {@code byte[]}, {@code UserHandle}, {@code ChallengeId}, …), so the JSON
 * mini-oidc hands the browser is exactly what pk-auth's browser SDK expects.
 */
public final class PkAuthHumanAuthenticator implements HumanAuthenticator {

  private final PasskeyAuthenticationService service;
  private final UserLookup users;
  private final JsonMapper mapper = PkAuthObjectMappers.create();

  public PkAuthHumanAuthenticator(final PasskeyAuthenticationService service, final UserLookup users) {
    this.service = service;
    this.users = users;
  }

  @Override
  public Challenge startRegistration(final String username, final String displayName) {
    final StartRegistrationResponse response = service
        .startRegistration(new StartRegistrationRequest(username, displayName, null, null))
        .responseOrThrow();
    return new Challenge(response.challengeId().value(), mapper.writeValueAsString(response));
  }

  @Override
  public boolean finishRegistration(final String challengeId, final String username,
                                    final String responseJson) {
    try {
      final RegistrationResponseJson body = mapper.readValue(responseJson, RegistrationResponseJson.class);
      final RegistrationResult result = service.finishRegistration(
          new FinishRegistrationRequest(new ChallengeId(challengeId), username, null, body));
      return result instanceof RegistrationResult.Success;
    } catch (final RuntimeException e) {
      return false;
    }
  }

  @Override
  public Challenge startAssertion(final String username) {
    final StartAuthenticationResponse response = service
        .startAuthentication(new StartAuthenticationRequest(username, null))
        .responseOrThrow();
    return new Challenge(response.challengeId().value(), mapper.writeValueAsString(response));
  }

  @Override
  public Optional<String> finishAssertion(final String challengeId, final String responseJson) {
    try {
      final AuthenticationResponseJson body = mapper.readValue(responseJson, AuthenticationResponseJson.class);
      final AssertionResult result = service.finishAuthentication(
          new FinishAuthenticationRequest(new ChallengeId(challengeId), body));
      if (result instanceof AssertionResult.Success success) {
        return users.findViewByHandle(success.userHandle()).map(UserLookup.UserView::username);
      }
      return Optional.empty();
    } catch (final RuntimeException e) {
      // A malformed or failed ceremony is simply "not authenticated" — never an oracle for why.
      return Optional.empty();
    }
  }
}
