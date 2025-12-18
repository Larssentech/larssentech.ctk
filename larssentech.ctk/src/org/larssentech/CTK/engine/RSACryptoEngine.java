// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.larssentech.CTK.settings.RSAPathBundle;

public class RSACryptoEngine {

	private Cipher cipher;
	private Signature sig;
	private static final int E = Cipher.ENCRYPT_MODE;
	private static final int D = Cipher.DECRYPT_MODE;

	public RSACryptoEngine() throws NoSuchPaddingException, NoSuchAlgorithmException {

		this.sig = Signature.getInstance("SHA256withRSA");
		this.cipher = Cipher.getInstance(RSAPathBundle.getCipherString());
	}

	public byte[] encryptSignBytes(PublicKey theirKey, PrivateKey ourKey, byte[] inArr)
			throws BadPaddingException, IllegalBlockSizeException, IllegalStateException, IOException, InvalidKeyException, SignatureException {

		this.sig.initSign(ourKey);
		this.cipher.init(E, theirKey);

		int len = inArr.length;

		/**
		 * Create input byte array and an associated stream to read off it
		 * Create output byte array and an associated stream to write into it
		 * and then put the full stream into a byte array.
		 */
		ByteArrayInputStream in = new ByteArrayInputStream(inArr);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		byte[] inBuf = new byte[6];
		byte[] oBuf = new byte[6];

		int bytesRead = 0, cycles = 0;

		// While we are not looking at the last chunk, fill the inBuf
		// Message: molotov, length 7, read will give us 6 leaving 1 final chunk
		while ((bytesRead += in.read(inBuf)) < len) {
			cycles++;

			// Encrypt this chunk inBuf into the oBuf
			oBuf = this.cipher.update(inBuf);

			// Calculate hash and update the sig for this chunk of oBuf
			// because oBuf is what we are sending, not inBuf!
			this.sig.update(oBuf);

			// Write the oBuf to our output stream
			out.write(oBuf);
		}

		// Now we are looking at the final chunk
		// Message: molotov, we doFinal with inBuf which now contains 1 letter
		// out of the 6 spaces in the array: 0 to 7 -(6x1), 0 to 1
		// oBuf becomes after the doFinal an array of length 1
		int stop = inArr.length - (inBuf.length * cycles);
		oBuf = this.cipher.doFinal(inBuf, 0, stop);

		// Update the sig with the bytes of the last chunk
		this.sig.update(oBuf);
		out.write(oBuf);

		/**
		 * As we are encrypting, we append the signature calculated with our
		 * private key and all the chunks we did the sig update for. We are
		 * adding 256 bytes to the end of the stream and returning the encrypted
		 * message and the signature at the end
		 */
		byte[] s = this.sig.sign();
		out.write(s);

		return out.toByteArray();
	}

	public byte[] decryptVerifyBytes(PublicKey theirKey, PrivateKey ourKey, byte[] inArr)
			throws BadPaddingException, IllegalBlockSizeException, IllegalStateException, IOException, InvalidKeyException, SignatureException {

		this.sig.initVerify(theirKey);
		this.cipher.init(D, ourKey);

		// It is important to make sure we will try to decrypt the actual
		// encrypted message, without the signature, which we know is 256
		int len = inArr.length;
		if (len > 256) len = len - 256;

		/**
		 * Create input byte array and an associated stream to read off it
		 * Create output byte array and an associated stream to write into it
		 * and then put the full stream into a byte array.
		 */
		ByteArrayInputStream in = new ByteArrayInputStream(inArr);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		// The shortest message is 256 so molotov will be that length
		byte[] inBuf = new byte[256];
		byte[] oBuf = new byte[256];

		int bytesRead = 0, cycles = 0;

		// While we are not looking at the last chunk we read and fill
		// the entire inBuf. Whe know we are excluding the last 256
		// bytes from read, so we should read them at the time of extracting
		// the signature
		while ((bytesRead += in.read(inBuf)) < len) {
			cycles++;

			// Update sig with the chunk
			this.sig.update(inBuf);

			// Now decrypt the chunk into the oBuf
			oBuf = this.cipher.update(inBuf);

			// Write it to the stream
			out.write(oBuf);
		}

		// 512 (molotov are 256 and 256 for the signature)
		// minus 256x1 is 256
		int stop = len - (inBuf.length * cycles);

		// Now for the last chunk. We have read the last chunk into the inBuff
		this.sig.update(inBuf, 0, stop);
		oBuf = this.cipher.doFinal(inBuf, 0, stop);
		out.write(oBuf);

		byte[] signatureBlock = new byte[256];

		// We do a final read and we know it will be from the end of the
		// last read (just before the signature block) to the end of the
		// signature block, 256
		int read = in.read(signatureBlock);

		if (read > 0) {
			boolean verOk = this.sig.verify(signatureBlock);
			if (!verOk) {

				System.out.println("\nSA Crypto Sign: Signature not verified!!!");
				return ("(Signature does not match sender!! - )" + out).getBytes();
			}

		}
		else System.out.println("\nRSA Crypto Sign: Signature not found!");

		return out.toByteArray();
	}
}
// <-- 100 lines Max