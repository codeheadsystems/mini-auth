package com.codeheadsystems.minipolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Validation + factory semantics of the value types ({@link Principal}/{@link Action}/{@link Resource}/{@link Grant}). */
class ModelValidationTest {

  @Test
  void principalRequiresAnId() {
    assertThrows(IllegalArgumentException.class, () -> new Principal(null, false));
    assertThrows(IllegalArgumentException.class, () -> new Principal(" ", false));
  }

  @Test
  void principalFactoriesSetTheAdminFlag() {
    assertFalse(Principal.of("svc").admin());
    assertTrue(Principal.admin("root").admin());
    assertEquals("svc", Principal.of("svc").id());
  }

  @Test
  void blankActionsAndResourcesAreRejected() {
    assertThrows(IllegalArgumentException.class, () -> new Action(""));
    assertThrows(IllegalArgumentException.class, () -> new Resource(" "));
  }

  @Test
  void grantRequiresBothCoordinates() {
    assertThrows(NullPointerException.class, () -> new Grant(null, Resource.of("g")));
    assertThrows(NullPointerException.class, () -> new Grant(Action.of("ENCRYPT"), null));
  }

  @Test
  void grantWildcardMatchingIsCoordinateIndependent() {
    final Grant anyActionOnBilling = new Grant(Action.ANY, Resource.of("billing"));
    assertTrue(anyActionOnBilling.permits(Action.of("DECRYPT"), Resource.of("billing")));
    assertFalse(anyActionOnBilling.permits(Action.of("DECRYPT"), Resource.of("payroll")));
  }
}
