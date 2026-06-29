package com.codeheadsystems.miniconsole.harness.flows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.Assignment;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.NewGroup;
import com.codeheadsystems.minidirectory.client.model.NewHuman;
import com.codeheadsystems.minidirectory.client.model.NewRole;
import com.codeheadsystems.minidirectory.client.model.NewServiceAccount;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import com.codeheadsystems.minidirectory.client.model.ServiceAccountCreated;
import com.codeheadsystems.minigateway.client.MiniGatewayClient;
import com.codeheadsystems.minigateway.client.VerifyOutcome;
import com.codeheadsystems.minigateway.client.VerifyRequest;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.miniidp.client.model.DiscoveryDocument;
import com.codeheadsystems.miniidp.client.model.RotationResult;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.model.AuditEntry;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link FullChainFlow} — the headline identity → token → gateway exercise — driven
 * against fake clients so the flow's chaining, its honest SKIP, and its redaction contract are
 * exercised without booting any service.
 */
class FullChainFlowTest {

  private static final String CLIENT = "svc_demo";
  private static final String SECRET = "super-secret-value";
  private static final String TOKEN = "eyJ.header.signature";

  private final FullChainFlow flow = new FullChainFlow();

  @Test
  void wholeChain_resolvesMintsAndIsAuthorized_passes() {
    final FakeDirectory directory = new FakeDirectory(new Resolution(CLIENT, false, List.of()));
    final FakeIdp idp = new FakeIdp(new TokenResponse(TOKEN, "Bearer", 300, "billing"));
    final FakeGateway gateway = new FakeGateway(VerifyOutcome.AUTHORIZED);

    final ExerciseResult result = flow.run(directory, idp, gateway,
        new FullChainFlow.Inputs(CLIENT, SECRET, "/app"));

    assertEquals(Status.PASS, result.status());
    assertEquals(3, result.steps().size());
    assertTrue(result.steps().stream().allMatch(s -> s.status() == Status.PASS));
    // The same minted token reached the gateway (proving the chain is connected end to end).
    assertEquals(TOKEN, gateway.lastBearer);
    assertTrue(lastStep(result).detail().contains("AUTHORIZED"));
  }

  @Test
  void noCredentials_skipsHonestly() {
    final ExerciseResult result = flow.run(new FakeDirectory(null), new FakeIdp(null),
        new FakeGateway(VerifyOutcome.AUTHORIZED), new FullChainFlow.Inputs("", "", "/app"));

    assertEquals(Status.SKIP, result.status());
    assertTrue(result.steps().stream().allMatch(s -> s.status() == Status.SKIP));
  }

  @Test
  void identityDoesNotResolve_failsAtFirstStep_noOracle() {
    final FakeDirectory directory = new FakeDirectory(null); // resolve() throws
    final ExerciseResult result = flow.run(directory, new FakeIdp(null),
        new FakeGateway(VerifyOutcome.AUTHORIZED), new FullChainFlow.Inputs(CLIENT, SECRET, "/app"));

    assertEquals(Status.FAIL, result.status());
    assertEquals(1, result.steps().size());
    assertEquals("Resolve identity (mini-directory)", result.steps().get(0).label());
  }

  @Test
  void gatewayDoesNotAuthorize_failsAtGatewayStep() {
    final FakeDirectory directory = new FakeDirectory(new Resolution(CLIENT, false, List.of()));
    final FakeIdp idp = new FakeIdp(new TokenResponse(TOKEN, "Bearer", 300, "billing"));
    final FakeGateway gateway = new FakeGateway(VerifyOutcome.FORBIDDEN);

    final ExerciseResult result = flow.run(directory, idp, gateway,
        new FullChainFlow.Inputs(CLIENT, SECRET, "/app"));

    assertEquals(Status.FAIL, result.status());
    assertEquals("Gateway verifies the token (mini-gateway)", lastStep(result).label());
    assertTrue(lastStep(result).detail().contains("FORBIDDEN"));
  }

  @Test
  void resultNeverContainsTheSecretOrTheToken() {
    final FakeDirectory directory = new FakeDirectory(new Resolution(CLIENT, false, List.of()));
    final FakeIdp idp = new FakeIdp(new TokenResponse(TOKEN, "Bearer", 300, "billing"));
    final FakeGateway gateway = new FakeGateway(VerifyOutcome.AUTHORIZED);

    final ExerciseResult result = flow.run(directory, idp, gateway,
        new FullChainFlow.Inputs(CLIENT, SECRET, "/app"));

    final String rendered = result.summary() + result.steps().stream()
        .map(s -> s.label() + s.detail()).reduce("", String::concat);
    assertFalse(rendered.contains(SECRET), "the client secret must never appear in the result");
    assertFalse(rendered.contains(TOKEN), "the minted access token must never appear in the result");
  }

  // ---- helpers -------------------------------------------------------------------------------

  private static Step lastStep(final ExerciseResult result) {
    return result.steps().get(result.steps().size() - 1);
  }

  /** A fake directory: returns the canned resolution; {@code resolve()} throws when it is null. */
  private static final class FakeDirectory implements MiniDirectoryClient {
    private final Resolution resolution;

    FakeDirectory(final Resolution resolution) {
      this.resolution = resolution;
    }

    @Override
    public Resolution resolve(final String id) {
      if (resolution == null) {
        throw new ClientException("not found");
      }
      return resolution;
    }

    @Override
    public List<Account> listAccounts() {
      throw new UnsupportedOperationException();
    }

    @Override
    public Account getAccount(final String id) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<Group> listGroups() {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<Role> listRoles() {
      throw new UnsupportedOperationException();
    }

    @Override
    public com.codeheadsystems.minidirectory.client.model.HealthStatus health() {
      throw new UnsupportedOperationException();
    }

    @Override
    public Account createHuman(final NewHuman request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ServiceAccountCreated createServiceAccount(final NewServiceAccount request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Account updateAssignment(final String id, final Assignment request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteAccount(final String id) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Group createGroup(final NewGroup request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteGroup(final String id) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Role createRole(final NewRole request) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteRole(final String id) {
      throw new UnsupportedOperationException();
    }
  }

  /** A fake idp: returns the canned token; {@code token()} throws when it is null. */
  private static final class FakeIdp implements MiniIdpClient {
    private final TokenResponse token;

    FakeIdp(final TokenResponse token) {
      this.token = token;
    }

    @Override
    public TokenResponse token(final String clientId, final String clientSecret) {
      if (token == null) {
        throw new ClientException("refused");
      }
      return token;
    }

    @Override
    public JwkSet jwks() {
      throw new UnsupportedOperationException();
    }

    @Override
    public DiscoveryDocument discovery() {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<AuditEntry> audit() {
      throw new UnsupportedOperationException();
    }

    @Override
    public RotationResult rotateSigningKey() {
      throw new UnsupportedOperationException();
    }

    @Override
    public com.codeheadsystems.miniidp.client.model.HealthStatus health() {
      throw new UnsupportedOperationException();
    }
  }

  /** A fake gateway: returns the canned outcome and records the last bearer it was handed. */
  private static final class FakeGateway implements MiniGatewayClient {
    private final VerifyOutcome outcome;
    private String lastBearer;

    FakeGateway(final VerifyOutcome outcome) {
      this.outcome = outcome;
    }

    @Override
    public VerifyOutcome verify(final VerifyRequest request) {
      this.lastBearer = request.bearerToken();
      return outcome;
    }

    @Override
    public com.codeheadsystems.minigateway.client.model.HealthStatus health() {
      throw new UnsupportedOperationException();
    }
  }
}
