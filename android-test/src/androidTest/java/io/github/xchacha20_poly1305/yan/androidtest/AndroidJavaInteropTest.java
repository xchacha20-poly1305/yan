package io.github.xchacha20_poly1305.yan.androidtest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import io.github.xchacha20_poly1305.yan.Age;
import io.github.xchacha20_poly1305.yan.Armor;
import io.github.xchacha20_poly1305.yan.ArmorFormatException;
import io.github.xchacha20_poly1305.yan.HybridIdentity;
import io.github.xchacha20_poly1305.yan.KeyFormatException;
import io.github.xchacha20_poly1305.yan.ScryptIdentity;
import io.github.xchacha20_poly1305.yan.ScryptRecipient;
import io.github.xchacha20_poly1305.yan.X25519Identity;

@RunWith(AndroidJUnit4.class)
public class AndroidJavaInteropTest {
    @Test
    public void javaCallersWorkOnAndroid() throws Exception {
        byte[] plaintext = "hello android java".getBytes(StandardCharsets.UTF_8);

        try (HybridIdentity hybrid = HybridIdentity.generate();
             X25519Identity x25519 = X25519Identity.generate()) {
            String armored = Age.encryptToArmoredString(
                    plaintext,
                    Arrays.asList(hybrid.getRecipient(), x25519.getRecipient()));
            assertArrayEquals(plaintext, Age.decryptArmoredString(armored, Collections.singletonList(hybrid)));
            assertArrayEquals(plaintext, Age.decryptArmoredString(armored, Collections.singletonList(x25519)));
        }

        try (ScryptRecipient rec = new ScryptRecipient("java-android-pass", 10);
             ScryptIdentity id = new ScryptIdentity("java-android-pass")) {
            byte[] ct = Age.encryptBytes(plaintext, Collections.singletonList(rec), true);
            assertArrayEquals(plaintext, Age.decryptBytes(ct, Collections.singletonList(id), true));
        }

        assertThrows(KeyFormatException.class, () -> Age.parseRecipient("invalid"));
        assertThrows(ArmorFormatException.class, () -> Armor.decode("invalid armor"));
    }
}
