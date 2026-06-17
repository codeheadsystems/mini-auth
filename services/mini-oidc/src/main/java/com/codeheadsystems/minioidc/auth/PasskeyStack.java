package com.codeheadsystems.minioidc.auth;

import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationService;
import com.codeheadsystems.pkauth.ceremony.PasskeyAuthenticationServices;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.codeheadsystems.pkauth.testkit.InMemoryChallengeStore;
import com.codeheadsystems.pkauth.testkit.InMemoryCredentialRepository;
import com.codeheadsystems.pkauth.testkit.InMemoryUserLookup;

/**
 * Assembles the embedded pk-auth stack: the WebAuthn ceremony service, the backup-code recovery
 * service, and the two mini-oidc adapters ({@link HumanAuthenticator} / {@link RecoveryAuthenticator})
 * built over them — all sharing one {@link UserLookup} so a passkey login and a backup-code recovery
 * resolve to the same identity.
 *
 * <p>The credential/challenge/user/backup-code stores are pk-auth's in-memory SPI implementations
 * (sanctioned on the main classpath for exactly this kind of single-node, educational use). They are
 * the documented swap point: drop in pk-auth's JDBI or DynamoDB persistence SPIs to make passkeys
 * survive a restart. The relying-party id + origins come from {@code ServerConfig} and are what
 * pk-auth validates every ceremony against.
 */
public final class PasskeyStack {

  private final UserLookup users;
  private final HumanAuthenticator humanAuthenticator;
  private final RecoveryAuthenticator recoveryAuthenticator;

  private PasskeyStack(final UserLookup users, final HumanAuthenticator humanAuthenticator,
                       final RecoveryAuthenticator recoveryAuthenticator) {
    this.users = users;
    this.humanAuthenticator = humanAuthenticator;
    this.recoveryAuthenticator = recoveryAuthenticator;
  }

  /**
   * Build an in-memory pk-auth stack for the given relying party.
   *
   * @param relyingParty  the WebAuthn relying-party identity (id + name + acceptable origins).
   * @param clockProvider the clock (system in production; a fixed clock in tests).
   * @return the assembled stack.
   */
  public static PasskeyStack inMemory(final RelyingPartyConfig relyingParty,
                                      final ClockProvider clockProvider) {
    final InMemoryUserLookup users = new InMemoryUserLookup();
    final PasskeyAuthenticationService service = PasskeyAuthenticationServices.builder()
        .userLookup(users)
        .credentialRepository(new InMemoryCredentialRepository())
        .challengeStore(new InMemoryChallengeStore())
        .relyingPartyConfig(relyingParty)
        .clockProvider(clockProvider)
        .build();
    final BackupCodeService backupCodes = BackupCodeService.create(
        BackupCodeService.Dependencies.of(new InMemoryBackupCodeRepository(), clockProvider));
    return new PasskeyStack(users,
        new PkAuthHumanAuthenticator(service, users),
        new RecoveryAuthenticator(backupCodes, users));
  }

  /** @return the shared user lookup (username ↔ pk-auth UserHandle). */
  public UserLookup users() {
    return users;
  }

  /** @return the passkey-backed human authenticator (registration + assertion). */
  public HumanAuthenticator humanAuthenticator() {
    return humanAuthenticator;
  }

  /** @return the backup-code recovery authenticator. */
  public RecoveryAuthenticator recoveryAuthenticator() {
    return recoveryAuthenticator;
  }
}
