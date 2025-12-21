// (c) 2015-2026 AVANZ.IO
// (c) 2008 Jeffrey J Cerasuolo

package org.larssentech.CTK.engine;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.larssentech.lib.log.Logg3r;

public class BlowfishCryptoEngine {

	private static long LOG_MARK = 256000;
	private SecretKey sK;
	private Cipher cipher;
	private long totalBytes, processedBytes;
	private int mode;
	private File log;

	public File getLog() { return this.log; }

	public void setLog(File log) { this.log = log; }

	public BlowfishCryptoEngine() {

		this.totalBytes = 0;
		this.processedBytes = 0;

		try {
			this.cipher = Cipher.getInstance("Blowfish");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Method to generate the session secret key used to encrypt and to decrypt
	 * 
	 * @throws NoSuchAlgorithmException
	 * @return SecretKey
	 */
	public SecretKey generateSecretKey() throws NoSuchAlgorithmException {

		this.sK = KeyGenerator.getInstance("Blowfish").generateKey();
		return this.sK;
	}

	/**
	 * Getter for the secret key
	 * 
	 * @param s SecretKey
	 */
	public void setSecretKey(SecretKey s) {

		this.sK = s;
	}

	/**
	 * Method to encrypt the data from one stream to another stream. This method
	 * returns the secret key used for the encryption. This method needs whoever
	 * invokes it to convert a file or an array or string or whatever needs
	 * encrypting to a stream. Method can be used both to encrypt and to decrypt,
	 * depending on how the cipher is initialised.
	 * 
	 * @param mode int
	 * @param in   InputStream
	 * @param out  OutputStream
	 * @param size long
	 * @throws IllegalStateException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IllegalStateException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @return SecretKey
	 */
	public SecretKey cryptToStream(int mode, InputStream in, OutputStream out, long size) throws IllegalStateException, IOException, BadPaddingException, IllegalBlockSizeException, IllegalStateException, IOException, InvalidKeyException {

		this.setMode(mode);

		// Reset progress counters
		this.totalBytes = size;
		this.processedBytes = 0;

		// Init the cipher properly
		this.cipher.init(mode, this.sK);

		// The read buffer needs to match the block size of the cipher
		byte[] readBuffer = new byte[this.cipher.getBlockSize()];

		// Set up some counters
		long bytesRead = 0; // For total bytes read
		int cycles = 0; // For iterations -- (iterations x buffer) + final chunk
						// size = total bytes

		// While we are not looking at the last chunk
		while ((bytesRead += in.read(readBuffer)) < size) {

			log(bytesRead);

			this.processedBytes = bytesRead;

			this.totalBytes = size; // Important as a reset can
									// zero it from
			// outside (22-Jul-08)
			cycles++;
			out.write(this.cipher.update(readBuffer));
			out.flush();

		}

		// Last piece: we only need the last bytes to end of text, not all in
		// the buffer
		byte[] lastOut = this.cipher.doFinal(readBuffer, 0, (int) size - readBuffer.length * cycles);
		out.write(lastOut);
		out.close();
		in.close();

		// Set counters to full
		this.processedBytes = size;

		doLog(bytesRead);
		Logg3r.log2(this.log, "CTK: " + this.cipher.getAlgorithm() + " done for: " + bytesRead + " bytes;\n");

		return this.sK;
	}

	private void setMode(int mode2) {

		this.mode = mode2;
	}

	private void log(long bytesRead) {

		boolean b = false;

		if (bytesRead == 0) b = true;
		else if (bytesRead % LOG_MARK == 0) b = true;
		else if (bytesRead == LOG_MARK) b = true;

		if (b) doLog(bytesRead);
	}

	private void doLog(long bytesRead) {

		Logg3r.log2(this.log, this.cipher.getAlgorithm() + ": " + bytesRead);

	}

	private int getMode() {

		return this.mode;
	}

	/**
	 * Returns the bytes the main method in the class has processed so far. Will be
	 * invoked by other classes who might need to know progress for user feedback or
	 * other reasons
	 * 
	 * @return long
	 */
	public long getProcessedBytes() {

		return this.processedBytes;
	}

	/**
	 * Same as getProcessedBytes but will return the total bytes to be processed.
	 * 
	 * @return long
	 */
	public long getTotalBytes() {

		return this.totalBytes;
	}

	/**
	 * Method to reset the counters for the total bytes and the bytes processed.
	 * Useful when the invoking class needs to ensure a long is returned by the
	 * progress methods when requested even if no encryption has happened yet
	 */
	public void resetCounters() {

		this.processedBytes = 0;
		this.totalBytes = 0;
	}
}
