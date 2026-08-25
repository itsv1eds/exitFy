package com.extera.plugins.exitfy;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ManifestSignatureTest {

    // Produced by scripts/sign_manifest.py through openssl. The publisher signs
    // with openssl while the client verifies with the JDK/Android provider, so
    // the encodings have to agree in practice, not only on paper.
    private static final String OPENSSL_KEY =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGge9pfbwtLCb9rCO83cC5xyBFNuiIrbJ"
                    + "CSA1AlqO7bEvi+s/SOsQghWpFPyXFOSMflMiUQfLaMZFWzC1KFKDJQ==";
    private static final String OPENSSL_SIGNATURE =
            "MEYCIQC24XLHM6HaZbGV2wclhDklC/xz8b18ocu/l3Rdqq6U+wIhAKi/4hL+q7jsVQF0"
                    + "V5q5VU9gqoLHq8U0W1vO/LoJ5Ybl";
    private static final String OPENSSL_MANIFEST = "{\"family\":\"xray\",\"schema\":3}";

    @Test
    public void acceptsASignatureProducedByThePublisher() throws Exception {
        byte[] manifest = OPENSSL_MANIFEST.getBytes(StandardCharsets.UTF_8);
        byte[] signature = Base64.getDecoder().decode(OPENSSL_SIGNATURE);
        CoreUpdater.verifyManifestSignature(OPENSSL_KEY, manifest, signature);

        byte[] tampered = OPENSSL_MANIFEST.replace("3", "4")
                .getBytes(StandardCharsets.UTF_8);
        assertThrows(Exception.class, () ->
                CoreUpdater.verifyManifestSignature(OPENSSL_KEY, tampered, signature));
    }

    // Signed by the release key itself. If the embedded public key is ever
    // replaced by one the publisher does not hold, every release would be
    // refused on device; this fails the build instead.
    private static final String RELEASE_KEY_PROBE =
            "exitFy manifest signing key check";
    private static final String RELEASE_KEY_PROBE_SIGNATURE =
            "MEQCIAysANAGpYuWmUucxTtIeE0gUbP1XkIdY7Ibcxo+WcCsAiAagsRdSdr1z0cCgtjl"
                    + "MQi9uBnJkHVK7lSRgADDO/KMTg==";

    @Test
    public void theEmbeddedKeyIsTheOneThePublisherSignsWith() throws Exception {
        assertFalse(CoreUpdater.MANIFEST_PUBLIC_KEY.isEmpty());
        byte[] probe = RELEASE_KEY_PROBE.getBytes(StandardCharsets.UTF_8);
        CoreUpdater.verifyManifestSignature(probe,
                Base64.getDecoder().decode(RELEASE_KEY_PROBE_SIGNATURE));

        byte[] tampered = (RELEASE_KEY_PROBE + " ").getBytes(StandardCharsets.UTF_8);
        assertThrows(Exception.class, () -> CoreUpdater.verifyManifestSignature(
                tampered, Base64.getDecoder().decode(RELEASE_KEY_PROBE_SIGNATURE)));
        // An unsigned release must no longer pass now that a key is configured.
        assertThrows(Exception.class,
                () -> CoreUpdater.verifyManifestSignature(probe, null));
    }

    @Test
    public void anUnconfiguredKeyClaimsNothing() throws Exception {
        CoreUpdater.verifyManifestSignature("", null, null);
    }

    @Test
    public void acceptsOnlyASignatureFromTheConfiguredKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        KeyPair other = generator.generateKeyPair();
        byte[] manifest = "{\"family\":\"xray\"}".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(manifest);
        byte[] signature = signer.sign();

        signer.initSign(other.getPrivate());
        signer.update(manifest);
        byte[] foreign = signer.sign();

        String key = Base64.getEncoder()
                .encodeToString(pair.getPublic().getEncoded());
        CoreUpdater.verifyManifestSignature(key, manifest, signature);

        byte[] tampered = manifest.clone();
        tampered[2] ^= 0x20;
        assertThrows(Exception.class,
                () -> CoreUpdater.verifyManifestSignature(key, tampered, signature));
        assertThrows(Exception.class,
                () -> CoreUpdater.verifyManifestSignature(key, manifest, foreign));
        assertThrows(Exception.class,
                () -> CoreUpdater.verifyManifestSignature(key, manifest, null));
        assertThrows(Exception.class,
                () -> CoreUpdater.verifyManifestSignature(key, manifest, new byte[0]));
        assertThrows(Exception.class,
                () -> CoreUpdater.verifyManifestSignature("not-base64!!", manifest, signature));
    }
}
