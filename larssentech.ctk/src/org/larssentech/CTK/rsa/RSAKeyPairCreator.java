// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.rsa;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import org.larssentech.lib.log.Logg3r;

class RSAKeyPairCreator {

	private KeyPair keyPair;

	public PublicKey getPublicey() { return this.keyPair.getPublic(); }

	public PrivateKey getPrivateKey() { return this.keyPair.getPrivate(); }

	KeyPair generateKeys(int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		// Get an instance of the Key Pair Generator and tell it we need RSA
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

		// And initialize it with a ke size and a ***parameter what?***
		keyGen.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
		// Request the key pair and store it
		this.keyPair = keyGen.generateKeyPair();

		Logg3r.log2(new File("ctk.log"), "RSA keys generated successfully (" + keySize + " bits)");
		return this.keyPair;
	}
}
