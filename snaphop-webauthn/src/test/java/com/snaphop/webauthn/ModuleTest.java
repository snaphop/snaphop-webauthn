package com.snaphop.webauthn;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.module.ModuleDescriptor;
import java.util.List;
import org.junit.jupiter.api.Test;

/// The module requires only what it says: no `jdk.unsupported` (so no
/// `sun.misc.Unsafe`), and nothing native. If native code is ever needed,
/// it goes through the FFM API (Panama), and this test changes on purpose.
class ModuleTest {

  @Test
  void requiresOnlyThese() {
    ModuleDescriptor d = WebauthnRelyingParty.class.getModule().getDescriptor();
    assertEquals(List.of("com.snaphop.cbor", "java.base", "org.jspecify"), d.requires().stream().map(ModuleDescriptor.Requires::name).sorted().toList());
    assertEquals(false, WebauthnRelyingParty.class.getModule().isNativeAccessEnabled());
  }
}
