package com.codeheadsystems.minioidc.auth;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.backupcodes.BackupCodeService;
import com.codeheadsystems.pkauth.spi.UserLookup;
import java.util.List;
import java.util.Optional;

/**
 * Account recovery / fallback login, backed by pk-auth's alt-flow services. The shipped path is
 * <b>backup codes</b> (view-once, Argon2id-hashed, single-use) — the documented way back in when a
 * passkey device is lost, before "contact support".
 *
 * <p>pk-auth's magic-link and OTP services have the same shape (a {@code start}/issue + a
 * {@code verify}/consume that yields a {@code UserHandle}); they plug in here behind the same seam
 * once their senders (email/SMS) and stores are configured. This class maps mini-oidc's usernames to
 * pk-auth {@link UserHandle}s via the shared {@link UserLookup}, so recovery resolves to the same
 * identity the passkey ceremony would.
 */
public final class RecoveryAuthenticator {

  private final BackupCodeService backupCodes;
  private final UserLookup users;

  public RecoveryAuthenticator(final BackupCodeService backupCodes, final UserLookup users) {
    this.backupCodes = backupCodes;
    this.users = users;
  }

  /**
   * Generate a fresh set of view-once backup codes for a user (replacing any prior set).
   *
   * @return the plaintext codes, shown exactly once; only their hashes are stored.
   * @throws IllegalArgumentException if the user is unknown.
   */
  public List<String> generateBackupCodes(final String username) {
    final UserHandle handle = users.findHandleByUsername(username)
        .orElseThrow(() -> new IllegalArgumentException("unknown user"));
    return backupCodes.generate(handle);
  }

  /**
   * Attempt a fallback login by redeeming a backup code, with no oracle.
   *
   * @param username the user logging in.
   * @param code     the presented backup code.
   * @return the authenticated username on a successful single-use redemption, else empty.
   */
  public Optional<String> recoverWithBackupCode(final String username, final String code) {
    final Optional<UserHandle> handle = username == null ? Optional.empty()
        : users.findHandleByUsername(username);
    if (handle.isEmpty() || code == null || code.isBlank()) {
      return Optional.empty();
    }
    return backupCodes.verify(handle.get(), code) instanceof BackupCodeService.VerifyResult.Success
        ? Optional.of(username)
        : Optional.empty();
  }
}
