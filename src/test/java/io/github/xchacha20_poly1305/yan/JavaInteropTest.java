package io.github.xchacha20_poly1305.yan;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

public class JavaInteropTest {
    @Test
    public void javaCallersCanUseHybridX25519ScryptAndArmor() throws Exception {
        byte[] plaintext = "hello from java".getBytes(StandardCharsets.UTF_8);

        try (HybridIdentity hybrid = HybridIdentity.generate();
             X25519Identity x25519 = X25519Identity.generate()) {

            ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
            try (OutputStream out = Age.encrypt(encrypted, hybrid.getRecipient(), x25519.getRecipient())) {
                out.write(plaintext);
            }

            ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            try (InputStream in = Age.decrypt(new ByteArrayInputStream(encrypted.toByteArray()), hybrid)) {
                byte[] buf = new byte[1024];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    decrypted.write(buf, 0, n);
                }
            }
            assertArrayEquals(plaintext, decrypted.toByteArray());

            String armored = Age.encryptToArmoredString(
                    plaintext,
                    Arrays.asList(hybrid.getRecipient(), x25519.getRecipient()));
            byte[] fromArmor = Age.decryptArmoredString(
                    armored,
                    Collections.singletonList(x25519));
            assertArrayEquals(plaintext, fromArmor);
        }

        try (ScryptRecipient rec = new ScryptRecipient("java-pass", 10);
             ScryptIdentity id = new ScryptIdentity("java-pass")) {
            byte[] encrypted = Age.encryptBytes(plaintext, Collections.singletonList(rec), true);
            byte[] decrypted = Age.decryptBytes(encrypted, Collections.singletonList(id), true);
            assertArrayEquals(plaintext, decrypted);
        }

        assertThrows(KeyFormatException.class, () -> Age.parseRecipient("not-a-key"));
        assertThrows(ArmorFormatException.class, () -> Armor.decode("bad armor"));
    }
}
