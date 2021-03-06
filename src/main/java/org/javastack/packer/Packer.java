/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.javastack.packer;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple Data Packer
 * 
 * <p>
 * <b>This class is not thread-safe, must be externally sinchronized</b>
 * <p>
 * 
 * Sample usage (output):
 * 
 * <pre>
 * Packer p = new Packer(16);
 * p.useCompress(false);
 * p.setAutoExtendPolicy(AutoExtendPolicy.AUTO);
 * p.useCRC(false);
 * String s1 = "hello", s2 = "world";
 * String hs = "df0c290eae2b";
 * byte b = 42;
 * long l = 0x648C9A7109B4L;
 * int ni = -192813;
 * p.putString(s1).putString(s2);
 * p.putHexString(hs);
 * p.putByte(b);
 * p.putVLong(l);
 * p.putVNegInt(ni);
 * p.flip();
 * String out = p.outputStringBase64URLSafe();
 * System.out.println(out.length() + "\t" + out);
 * </pre>
 * 
 * Sample usage (load):
 * 
 * <pre>
 * p = new Packer(16);
 * p.setAutoExtendPolicy(AutoExtendPolicy.AUTO);
 * p.useCompress(false);
 * p.useCRC(false);
 * p.loadStringBase64URLSafe(input);
 * System.out.println(p.getString());
 * System.out.println(p.getString());
 * System.out.println(p.getHexStringUpper());
 * System.out.println(p.getByte());
 * System.out.println(p.getVLong());
 * System.out.println(p.getVNegInt());
 * </pre>
 * 
 * @see java.nio.ByteBuffer
 * @author Guillermo Grandes / guillermo.grandes[at]gmail.com
 */
public class Packer {
	public static final int DEFAULT_SIZE = 4096;

	public static final int FLAG_COMPRESS = 0x01;
	public static final int FLAG_AES = 0x02;
	public static final int FLAG_CRC = 0x04;
	public static final int FLAG_HASH = 0x08;
	public static final int FLAG_HMAC = 0x10;
	public static final int FLAG_RANDOM_IV = 0x20;
	public static final int FLAG_RSA = 0x40;
	public static final int FLAG_RANDOM_INT_IV = 0x80;

    // AES-GCM parameters
	// Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
	// NIST. 800-38D: https://csrc.nist.gov/publications/detail/sp/800-38d/final
	// For IVs, it is recommended that implementations restrict support to the
	// length of 96 bits, to promote interoperability, efficiency, and simplicity of
	// design.
    static final int GCM_IV_LENGTH = 96 / 8; // in bytes;
    static final int GCM_TAG_LENGTH = 128 / 8; // in bytes
	static final String CIPHER_GCM = "AES/GCM/NoPadding";

	static final String CIPHER_CHAIN_PADDING = "AES/CBC/PKCS5Padding";
	static final String ASYM_CIPHER_CHAIN_PADDING = "RSA/ECB/PKCS1Padding";
	static final String CIPHER = "AES";
	static final Charset charsetUTF8 = Charset.forName("UTF-8");
	static final Charset charsetISOLatin1 = Charset.forName("ISO-8859-1");
	static final Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
	static final Inflater inflater = new Inflater(true);
	static final SecureRandom rnd = new SecureRandom();

	// HASH
	MessageDigest mdHash = null;
	// HMAC
	Mac hMac = null;
	// AES
	byte[] fakeIV = "fKnuy=eimE-Lid2Th$s/3pJS$#vzk4:86UBU:WX$X7GjyB-yrv!+IsJ-nSCGF63SR_9tjt.w9ngxS.WmkVzGY2QycbUWNILc8ZyZguaNE2=D6htKMsmP2EKb9BHsJW4B"
			.getBytes(charsetISOLatin1); // Default shared IV
	AESTYPEIV aesTypeIV = AESTYPEIV.FAKE_IV; // 0=No IV
	int integerIV = Integer.MIN_VALUE;
	byte[] aesIV = null;
	AESTYPE aesType = AESTYPE.NONE;
	Cipher aesCipher = null;
	int aesCipherLen = -1;
	SecretKeySpec aesKey = null;
	// RSA
	Cipher rsaCipher = null;
	Key rsaKeyForEncrypt = null;
	Key rsaKeyForDecrypt = null;

	byte[] buf;
	int bufLimit;
	int bufPosition = 0;
	AutoExtendPolicy autoExtendPolicy = AutoExtendPolicy.NONE;
	boolean useFlagFooter = true;
	boolean useCompress = false;
	boolean useCRC = false;

	/**
	 * Create Packer with default size of {@value #DEFAULT_SIZE}
	 * 
	 * @see java.nio.ByteBuffer
	 */
	public Packer() {
		this(DEFAULT_SIZE);
	}

	/**
	 * Create Packer with specified size
	 * 
	 * @param size for initial buffer
	 * @see java.nio.ByteBuffer
	 */
	public Packer(final int size) {
		buf = new byte[Math.max(1, size)];
		bufLimit = buf.length;
	}

	/**
	 * Set Auto Extend Policy for Buffer
	 * 
	 * @param autoExtendPolicy used to expand
	 * @return this
	 */
	public Packer setAutoExtendPolicy(final AutoExtendPolicy autoExtendPolicy) {
		this.autoExtendPolicy = autoExtendPolicy;
		return this;
	}

	/**
	 * Ensure capacity
	 * 
	 * @param minCapacity you want
	 * @return this
	 */
	public Packer ensureCapacity(int minCapacity) {
		if (minCapacity <= buf.length)
			return this;
		switch (autoExtendPolicy) {
			case NONE:
				return this;
			case MINIMAL:
				break;
			case AUTO:
				minCapacity = roundAuto(minCapacity);
				break;
			case ROUND8:
				minCapacity = round(minCapacity, 8);
				break;
			case ROUND512:
				minCapacity = round(minCapacity, 512);
				break;
			case ROUND4096:
				minCapacity = round(minCapacity, 4096);
				break;
		}
		final byte[] newbuf = new byte[minCapacity];
		System.arraycopy(buf, 0, newbuf, 0, Math.min(buf.length, newbuf.length));
		buf = newbuf;
		bufLimit = buf.length;
		return this;
	}

	/**
	 * Clear Packer Buffer see: {@link java.nio.ByteBuffer#clear()}
	 * 
	 * @return this
	 */
	public Packer clear() {
		this.bufPosition = 0;
		this.bufLimit = buf.length;
		return this;
	}

	/**
	 * Flip Packer Buffer see: {@link java.nio.ByteBuffer#flip()}
	 * 
	 * @return this
	 */
	public Packer flip() {
		bufLimit = bufPosition;
		bufPosition = 0;
		return this;
	}

	/**
	 * Rewind Packer Buffer see: {@link java.nio.ByteBuffer#rewind()}
	 * 
	 * @return this
	 */
	public Packer rewind() {
		bufPosition = 0;
		return this;
	}

	/**
	 * Sets the usage of Footer Flag (default true)
	 * 
	 * @param useFlagFooter for variable features
	 * @return this
	 */
	public Packer useFlagFooter(final boolean useFlagFooter) {
		this.useFlagFooter = useFlagFooter;
		return this;
	}

	/**
	 * Sets the usage of Deflater/Inflater (default false)
	 * 
	 * @param useCompress to reduce size
	 * @return this
	 */
	public Packer useCompress(final boolean useCompress) {
		this.useCompress = useCompress;
		return this;
	}

	/**
	 * Sets the usage of CRC for sanity (default false)
	 * 
	 * @param useCRC to enable CRC
	 * @return this
	 */
	public Packer useCRC(final boolean useCRC) {
		this.useCRC = useCRC;
		return this;
	}

	/**
	 * Sets the usage of HASH for sanity (default no)
	 * 
	 * @param hashAlg
	 *            hash algorithm
	 * @return this
	 * @throws NoSuchAlgorithmException if hash algorithm not found
	 * 
	 * @see java.security.MessageDigest#getInstance(String)
	 */
	public Packer useHASH(final String hashAlg) throws NoSuchAlgorithmException {
		mdHash = MessageDigest.getInstance(hashAlg);
		return this;
	}

	/**
	 * Sets the usage of Hash-MAC for authentication (default no)
	 * 
	 * @param hMacAlg
	 *            HMAC algorithm (HmacSHA1, HmacSHA256,...)
	 * @param passphrase
	 *            shared secret
	 * @return this
	 * 
	 * @throws NoSuchAlgorithmException if hash algorithm not found
	 * @throws InvalidKeyException if invalid key
	 * 
	 * @see javax.crypto.Mac#getInstance(String)
	 * @see <a
	 *      href="http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJCEProvider">JCE
	 *      Provider</a>
	 */
	public Packer useHMAC(final String hMacAlg, final String passphrase) throws NoSuchAlgorithmException,
			InvalidKeyException {
		hMac = Mac.getInstance(hMacAlg); // "HmacSHA256"
		hMac.init(new SecretKeySpec(passphrase.getBytes(charsetUTF8), hMacAlg));
		return this;
	}

	/**
	 * Sets he usage of "AES/GCM/NoPadding" with random-IV for encryption (default no)
	 * 
	 * @param passphrase shared secret
	 * @return this
	 * @throws NoSuchAlgorithmException if algorithm not found
	 * @throws NoSuchPaddingException if padding not found
	 * @throws InvalidKeySpecException if invalid key 
	 */
	public Packer useAESGCM(final String passphrase) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException {
		initCipherGCM();
		initCipherIV(generateRandomIV(GCM_IV_LENGTH), AESTYPEIV.RANDOM_IV);
		initCipherKey(passphrase);
		return this;
	}

	private final void initCipherGCM() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.aesType = AESTYPE.GCM;
		this.aesCipher = Cipher.getInstance(CIPHER_GCM);
		this.aesCipherLen = aesCipher.getBlockSize();
	}

	/**
	 * Sets he usage of "AES/CBC/PKCS5Padding" (with default IV) for encryption (default no)
	 * 
	 * @param passphrase shared secret
	 * @return this
	 * @throws NoSuchAlgorithmException if algorithm not found
	 * @throws NoSuchPaddingException if padding not found
	 */
	public Packer useAES(final String passphrase) throws NoSuchAlgorithmException, NoSuchPaddingException {
		return useAES(passphrase, false);
	}

	/**
	 * Sets he usage of "AES/CBC/PKCS5Padding" with pre-shared IV for encryption (default no)
	 * 
	 * @param passphrase shared secret
	 * @param sharedIV shared Initialization Vector
	 * 
	 * @return this
	 * @throws NoSuchAlgorithmException if algorithm not found
	 * @throws NoSuchPaddingException if padding not found
	 */
	public Packer useAES(final String passphrase, final String sharedIV) throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		initCipherCBC();
		initCipherIV(generateMdfromString(sharedIV, aesCipherLen), AESTYPEIV.SHARED_IV);
		initCipherKey(passphrase);
		return this;
	}

	/**
	 * Sets he usage of "AES/CBC/PKCS5Padding" with a Random Integer IV for encryption (default no). Instead
	 * of use full-random-IV, use a integer seed (this allow compact output)
	 * 
	 * @param passphrase shared secret
	 * 
	 * @return this
	 * @throws NoSuchAlgorithmException if algorithm not found
	 * @throws NoSuchPaddingException if padding not found
	 */
	public Packer useAESwithRandomIntIV(final String passphrase) throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		initCipherCBC();
		integerIV = (rnd.nextInt() & 0x7FFFFFFF);
		initCipherIV(generateMdfromInteger(this.integerIV, aesCipherLen), AESTYPEIV.RANDOM_INT_IV);
		initCipherKey(passphrase);
		return this;
	}

	/**
	 * Sets he usage of "AES/CBC/PKCS5Padding" for encryption (default no)
	 * 
	 * @param passphrase shared secret
	 * @param useRandomIV true for use randomIV (more secure, more size) or false for default IV (less secure,
	 *            less size)
	 * @return this
	 * @throws NoSuchAlgorithmException if algorithm not found
	 * @throws NoSuchPaddingException if padding not found
	 */
	public Packer useAES(final String passphrase, final boolean useRandomIV) throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		initCipherCBC();
		initCipherIV((useRandomIV ? generateRandomIV(aesCipherLen) : getDefaultIV(aesCipherLen)),
				(useRandomIV ? AESTYPEIV.RANDOM_IV : AESTYPEIV.FAKE_IV));
		initCipherKey(passphrase);
		return this;
	}

	private final void initCipherCBC() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.aesType = AESTYPE.CBC;
		this.aesCipher = Cipher.getInstance(CIPHER_CHAIN_PADDING);
		this.aesCipherLen = aesCipher.getBlockSize();
	}

	private final void initCipherIV(final byte[] iv, final AESTYPEIV aesTypeIV) {
		this.aesTypeIV = aesTypeIV;
		final int ivLen = ((aesType == AESTYPE.GCM) //
				? GCM_IV_LENGTH //
				: aesCipherLen);
		this.aesIV = resizeBuffer(iv, ivLen);
	}

	private final void initCipherKey(final String passphrase) throws NoSuchAlgorithmException {
		aesKey = new SecretKeySpec(generateMdfromString(passphrase, aesCipherLen), CIPHER);
	}

	private final byte[] getDefaultIV(final int outlen) {
		return resizeBuffer(fakeIV, outlen);
	}

	private final byte[] generateRandomIV(final int outlen) {
		final byte[] buf = new byte[outlen];
		rnd.nextBytes(buf);
		return buf;
	}

	private final byte[] generateMdfromString(final String input, final int outlen)
			throws NoSuchAlgorithmException {
		final MessageDigest md = getMessageDigestForLength(outlen);
		final byte[] buf = input.getBytes(charsetUTF8);
		md.update(buf, 0, buf.length);
		return resizeBuffer(md.digest(), outlen);
	}

	private final byte[] generateMdfromBuffer(final byte[] buf, final int outlen)
			throws NoSuchAlgorithmException {
		final MessageDigest md = getMessageDigestForLength(outlen);
		md.update(buf, 0, buf.length);
		return resizeBuffer(md.digest(), outlen);
	}

	private final byte[] generateMdfromInteger(final int input, final int outlen)
			throws NoSuchAlgorithmException {
		return generateMdfromBuffer(intToByteArray(input), outlen);
	}

	private static final int round(final int in, final int round) {
		int out = (in & ~(round - 1)); // 7
		if (out != in) {
			out += round; // 8
		}
		return out;
	}

	private static final int roundAuto(final int in) {
		final int r4K = 4096;
		if (in > r4K) {
			return round(in, r4K);
		}
		for (int i = 16; i <= r4K; i <<= 1) {
			if (in < i) {
				return i;
			}
		}
		return round(in, r4K);
	}

	private static final byte[] intToByteArray(final int value) {
		return new byte[] {
				(byte) (value >>> 24), //
				(byte) (value >>> 16), //
				(byte) (value >>> 8),  //
				(byte) value
		};
	}

	private final MessageDigest getMessageDigestForLength(final int outlen) throws NoSuchAlgorithmException {
		String mdAlg = null;
		if (outlen <= (128 >> 3)) {
			mdAlg = "MD5";
		} else if (outlen <= (160 >> 3)) {
			mdAlg = "SHA-1";
		} else if (outlen <= (256 >> 3)) {
			mdAlg = "SHA-256";
		} else if (outlen <= (384 >> 3)) {
			mdAlg = "SHA-384";
		} else if (outlen <= (512 >> 3)) {
			mdAlg = "SHA-512";
		} else {
			throw new NoSuchAlgorithmException();
		}
		return MessageDigest.getInstance(mdAlg);
	}

	/**
	 * Sets he usage of "RSA/ECB/PKCS1Padding" for encryption (default no)
	 * 
	 * @param rsaKeyForEncrypt key for encrypt
	 * @param rsaKeyForDecrypt key for decrypt
	 * @return this
	 * @throws NoSuchPaddingException if padding not found
	 * @throws NoSuchAlgorithmException if algorithm not found
	 */
	public Packer useRSA(final Key rsaKeyForEncrypt, final Key rsaKeyForDecrypt)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.rsaCipher = Cipher.getInstance(ASYM_CIPHER_CHAIN_PADDING);
		this.rsaKeyForEncrypt = rsaKeyForEncrypt;
		this.rsaKeyForDecrypt = rsaKeyForDecrypt;
		return this;
	}

	/**
	 * Generate RSA KeyPair
	 * 
	 * @param keyLen in bits (2048 recomended)
	 * @return keypair
	 * @throws NoSuchAlgorithmException if algorithm not found
	 */
	public static KeyPair generateKeyPair(final int keyLen) throws NoSuchAlgorithmException {
		final String name = ASYM_CIPHER_CHAIN_PADDING;
		final int offset = name.indexOf('/');
		final String alg = ((offset < 0) ? name : name.substring(0, offset));
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(alg);
		generator.initialize(keyLen);
		return generator.genKeyPair();
	}

	/**
	 * Return internal buffer as ByteBuffer
	 * 
	 * @return byte buffer
	 */
	public ByteBuffer getByteBuffer() {
		final ByteBuffer bb = ByteBuffer.wrap(buf);
		bb.limit(bufLimit);
		bb.position(bufPosition);
		return bb;
	}

	// ------------- PUT -------------

	/**
	 * Put native byte (fixed length)
	 * 
	 * @param value byte
	 * @return this
	 * @see #getByte()
	 */
	public Packer putByte(final byte value) {
		ensureCapacity(bufPosition + 1);
		buf[bufPosition++] = value;
		return this;
	}

	/**
	 * Put native char (fixed length)
	 * 
	 * @param value char
	 * @return this
	 * @see #getChar()
	 */
	public Packer putChar(final char value) {
		ensureCapacity(bufPosition + 2);
		buf[bufPosition++] = (byte) (value >> 8);
		buf[bufPosition++] = (byte) (value);
		return this;
	}

	/**
	 * Put native short (fixed length)
	 * 
	 * @param value short
	 * @return this
	 * @see #getShort()
	 */
	public Packer putShort(final short value) {
		ensureCapacity(bufPosition + 2);
		buf[bufPosition++] = (byte) (value >> 8);
		buf[bufPosition++] = (byte) (value);
		return this;
	}

	/**
	 * Put native double (fixed length)
	 * 
	 * @param value double
	 * @return this
	 * @see #getDouble()
	 */
	public Packer putDouble(final double value) {
		putLong(Double.doubleToRawLongBits(value));
		return this;
	}

	/**
	 * Put native float (fixed length)
	 * 
	 * @param value float
	 * @return this
	 * @see #getFloat()
	 */
	public Packer putFloat(final float value) {
		putInt(Float.floatToRawIntBits(value));
		return this;
	}

	/**
	 * Put native int (fixed length)
	 * 
	 * @param value int
	 * @return this
	 * @see #getInt()
	 */
	public Packer putInt(final int value) {
		ensureCapacity(bufPosition + 4);
		buf[bufPosition++] = (byte) (value >> 24);
		buf[bufPosition++] = (byte) (value >> 16);
		buf[bufPosition++] = (byte) (value >> 8);
		buf[bufPosition++] = (byte) (value);
		return this;
	}

	/**
	 * Put native long (fixed length)
	 * 
	 * @param value long
	 * @return this
	 * @see #getLong()
	 */
	public Packer putLong(final long value) {
		ensureCapacity(bufPosition + 8);
		buf[bufPosition++] = (byte) (value >> 56);
		buf[bufPosition++] = (byte) (value >> 48);
		buf[bufPosition++] = (byte) (value >> 40);
		buf[bufPosition++] = (byte) (value >> 32);
		buf[bufPosition++] = (byte) (value >> 24);
		buf[bufPosition++] = (byte) (value >> 16);
		buf[bufPosition++] = (byte) (value >> 8);
		buf[bufPosition++] = (byte) (value);
		return this;
	}

	/**
	 * Put native int in variable length format (support negative value, but size is longer)
	 * 
	 * @param value int
	 * @return this
	 * @see #getVInt()
	 */
	public Packer putVInt(int value) {
		ensureCapacity(bufPosition + 4 + 1);
		int i = 0;
		while (((value & ~0x7FL) != 0L) && ((i += 7) < 32)) {
			buf[bufPosition++] = ((byte) ((value & 0x7FL) | 0x80L));
			value >>>= 7;
		}
		buf[bufPosition++] = ((byte) value);
		return this;
	}

	/**
	 * Put native negative int in variable length format (support positive value, but size is longer)
	 * 
	 * @param value int
	 * @return this
	 * @see #getVNegInt()
	 */
	public Packer putVNegInt(final int value) {
		putVInt(-value);
		return this;
	}

	/**
	 * Put native long in variable length format (support negative value, but size is longer)
	 * 
	 * @param value long
	 * @return this
	 * @see #getVLong()
	 */
	public Packer putVLong(long value) {
		ensureCapacity(bufPosition + 8 + 2);
		// org.apache.lucene.util.packed.AbstractBlockPackedWriter
		int i = 0;
		while (((value & ~0x7FL) != 0L) && ((i += 7) < 64)) {
			buf[bufPosition++] = ((byte) ((value & 0x7FL) | 0x80L));
			value >>>= 7;
		}
		buf[bufPosition++] = ((byte) value);
		return this;
	}

	/**
	 * Put native negative long in variable length format (support positive value, but size is longer)
	 * 
	 * @param value long
	 * @return this
	 * @see #getVNegLong()
	 */
	public Packer putVNegLong(final long value) {
		putVLong(-value);
		return this;
	}

	/**
	 * Put Byte array (encoded as: VInt-Length + bytes)
	 * 
	 * @param value byte array
	 * @return this
	 * @see #getBytes()
	 */
	public Packer putBytes(final byte[] value) {
		putVInt(value.length);
		ensureCapacity(bufPosition + value.length);
		System.arraycopy(value, 0, buf, bufPosition, value.length);
		bufPosition += value.length;
		return this;
	}

	/**
	 * Put Byte array (encoded as: Int32-Length + bytes)
	 * 
	 * @param value byte array
	 * @return this
	 * @see #getBytes()
	 */
	public Packer putBytesF(final byte[] value) {
		putInt(value.length);
		ensureCapacity(bufPosition + value.length);
		System.arraycopy(value, 0, buf, bufPosition, value.length);
		bufPosition += value.length;
		return this;
	}

	/**
	 * Put String in UTF-8 format (encoded as: VInt-Length + bytes)
	 * 
	 * @param value string
	 * @return this
	 * @see #getString()
	 */
	public Packer putString(final String value) {
		putBytes(value.getBytes(charsetUTF8));
		return this;
	}

	/**
	 * Put String in UTF-8 format (encoded as: Int32-Length + bytes)
	 * 
	 * @param value string
	 * @return this
	 * @see #getString()
	 */
	public Packer putStringF(final String value) {
		putBytesF(value.getBytes(charsetUTF8));
		return this;
	}

	/**
	 * Put Hex String ("0123456789ABCDEF")
	 * 
	 * @param value hex string
	 * @return this
	 * @throws IllegalArgumentException if value is invalid
	 * @see #getHexStringLower()
	 * @see #getHexStringUpper()
	 */
	public Packer putHexString(final String value) throws IllegalArgumentException {
		try {
			final byte[] hex = fromHex(value);
			putVInt(hex.length);
			ensureCapacity(bufPosition + hex.length);
			System.arraycopy(hex, 0, buf, bufPosition, hex.length);
			bufPosition += hex.length;
		} catch (ParseException e) {
			throw new IllegalArgumentException("Invalid input string", e);
		}
		return this;
	}

	/**
	 * Put a Collection&lt;String&gt; in UTF-8 format
	 * 
	 * @param collection of values
	 * @return this
	 * @see #getStringCollection(Collection)
	 */
	public Packer putStringCollection(final Collection<String> collection) {
		putVInt(collection.size());
		for (final String value : collection) {
			putString(value);
		}
		return this;
	}

	/**
	 * Put a Map&lt;String, String&gt; in UTF-8 format
	 * 
	 * @param map values
	 * @return this
	 * @see #getStringMap(Map)
	 */
	public Packer putStringMap(final Map<String, String> map) {
		putVInt(map.size());
		for (final Entry<String, String> e : map.entrySet()) {
			final String key = e.getKey();
			final String value = e.getValue();
			putString(key);
			putString(value);
		}
		return this;
	}

	// ------------- OUTPUT -------------

	/**
	 * Output Base64 string
	 * <p>
	 * Base64 info: <a href="http://en.wikipedia.org/wiki/Base64">Base64</a>
	 * 
	 * @return base64 string
	 * @see #loadStringBase64(String)
	 */
	public String outputStringBase64() {
		return new String(Base64.encode(outputBytes(), false), charsetISOLatin1);
	}

	/**
	 * Output Base64 string replacing "+/" to "-_" that is URL safe and removing base64 padding "="
	 * <p>
	 * RFC-4648 info, The "URL and Filename safe" Base 64 Alphabet: <a
	 * href="http://tools.ietf.org/html/rfc4648#page-7">RFC-4648</a>
	 * 
	 * @return base64 string URLSafe
	 * @see #loadStringBase64URLSafe(String)
	 */
	public String outputStringBase64URLSafe() {
		return new String(Base64.encode(outputBytes(), true), charsetISOLatin1);
	}

	/**
	 * Output string in hex format
	 * 
	 * @return hex string
	 * @see #loadStringHex(String)
	 */
	public String outputStringHex() {
		return toHex(outputBytes(), true);
	}

	/**
	 * Output string in raw format (ISO-8859-1)
	 * 
	 * @return raw string
	 * @see #loadStringRAW(String)
	 */
	public String outputStringRAW() {
		return new String(outputBytes(), charsetISOLatin1);
	}

	/**
	 * Output bytes in raw format
	 * 
	 * @return byte array
	 * 
	 * @see #loadBytes(byte[])
	 * @see #useCompress(boolean)
	 * @see #useCRC(boolean)
	 * @see #useHASH(String)
	 */
	public byte[] outputBytes() {
		byte[] tmpBuf = buf;
		int len = bufLimit;
		int flags = 0;
		if (useCompress) {
			flags |= FLAG_COMPRESS;
			tmpBuf = deflate(tmpBuf, len);
			len = tmpBuf.length;
		}
		if (aesKey != null) {
			flags |= FLAG_AES;
			try {
				tmpBuf = crypto(tmpBuf, 0, len, false);
			} catch (Exception e) {
				throw new IllegalArgumentException("AES Encryption failed", e);
			}
			len = tmpBuf.length;
			//
			if (aesIV != null) {
				switch (aesTypeIV) {
					case RANDOM_IV: { // useAES + randomIV
						flags |= FLAG_RANDOM_IV;
						final byte[] ivBuf = aesIV;
						tmpBuf = resizeBuffer(tmpBuf, len + ivBuf.length);
						System.arraycopy(ivBuf, 0, tmpBuf, len, ivBuf.length);
						len = tmpBuf.length;
						break;
					}
					case RANDOM_INT_IV: { // useAES + integerIV
						flags |= FLAG_RANDOM_INT_IV;
						final byte[] ivBuf = intToByteArray(integerIV);
						tmpBuf = resizeBuffer(tmpBuf, len + ivBuf.length);
						System.arraycopy(ivBuf, 0, tmpBuf, len, ivBuf.length);
						len = tmpBuf.length;
						break;
					}
				}
			}
		}
		if (rsaKeyForEncrypt != null) {
			flags |= FLAG_RSA;
			try {
				tmpBuf = cryptoAsym(tmpBuf, 0, len, false);
			} catch (Exception e) {
				throw new IllegalArgumentException("RSA Encryption failed", e);
			}
			len = tmpBuf.length;
		}
		if (useCRC) {
			flags |= FLAG_CRC;
			tmpBuf = resizeBuffer(tmpBuf, len + 1);
			tmpBuf[len] = (byte) crc8(tmpBuf, 0, len);
			len = tmpBuf.length;
		}
		if (mdHash != null) { // useHASH
			flags |= FLAG_HASH;
			final byte[] mdBuf = hash(tmpBuf, 0, len);
			tmpBuf = resizeBuffer(tmpBuf, len + mdBuf.length);
			System.arraycopy(mdBuf, 0, tmpBuf, len, mdBuf.length);
			len = tmpBuf.length;
		}
		if (hMac != null) { // useHMAC
			flags |= FLAG_HMAC;
			final byte[] hmacBuf = hmac(tmpBuf, 0, len);
			tmpBuf = resizeBuffer(tmpBuf, len + hmacBuf.length);
			System.arraycopy(hmacBuf, 0, tmpBuf, len, hmacBuf.length);
			len = tmpBuf.length;
		}
		if (useFlagFooter) {
			tmpBuf = resizeBuffer(tmpBuf, ++len);
			tmpBuf[len - 1] = (byte) (flags & 0xFF);
		} else {
			tmpBuf = resizeBuffer(tmpBuf, len);
		}
		return tmpBuf;
	}

	// ------------- GET -------------

	/**
	 * Get native byte (fixed length)
	 * 
	 * @return byte
	 * @see #putByte(byte)
	 */
	public byte getByte() {
		return buf[bufPosition++];
	}

	/**
	 * Get native char (fixed length)
	 * 
	 * @return char
	 * @see #putChar(char)
	 */
	public char getChar() {
		return (char) (((getByte() & 0xFF) << 8) | (getByte() & 0xFF));
	}

	/**
	 * Get native short (fixed length)
	 * 
	 * @return short
	 * @see #putShort(short)
	 */
	public short getShort() {
		return (short) (((getByte() & 0xFF) << 8) | (getByte() & 0xFF));
	}

	/**
	 * Get native double (fixed length)
	 * 
	 * @return doble
	 * @see #putDouble(double)
	 */
	public double getDouble() {
		return Double.longBitsToDouble(getLong());
	}

	/**
	 * Get native float (fixed length)
	 * 
	 * @return float
	 * @see #putFloat(float)
	 */
	public float getFloat() {
		return Float.intBitsToFloat(getInt());
	}

	/**
	 * Get native int (fixed length)
	 * 
	 * @return int
	 * @see #putInt(int)
	 */
	public int getInt() {
		int v = 0;
		v |= ((getByte() & 0xFF) << 24);
		v |= ((getByte() & 0xFF) << 16);
		v |= ((getByte() & 0xFF) << 8);
		v |= (getByte() & 0xFF);
		return v;
	}

	/**
	 * Get native long (fixed length)
	 * 
	 * @return long
	 * @see #putLong(long)
	 */
	public long getLong() {
		long v = 0;
		v |= ((getByte() & 0xFFL) << 56);
		v |= ((getByte() & 0xFFL) << 48);
		v |= ((getByte() & 0xFFL) << 40);
		v |= ((getByte() & 0xFFL) << 32);
		v |= ((getByte() & 0xFFL) << 24);
		v |= ((getByte() & 0xFFL) << 16);
		v |= ((getByte() & 0xFFL) << 8);
		v |= (getByte() & 0xFFL);
		return v;
	}

	/**
	 * Get native int stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return int
	 * @see #getVNegInt()
	 */
	public int getVInt() {
		int value = 0;
		for (int i = 0; i <= 32; i += 7) {
			final byte b = getByte();
			value |= ((b & 0x7FL) << i);
			if (b >= 0)
				return value;
		}
		return value;
	}

	/**
	 * Get native negative int stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return int
	 * @see #getVInt()
	 */
	public int getVNegInt() {
		return -getVInt();
	}

	/**
	 * Get native long stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return long
	 * @see #getVNegLong()
	 */
	public long getVLong() {
		// org.apache.lucene.util.packed.BlockPackedReaderIterator
		long value = 0;
		for (int i = 0; i <= 64; i += 7) {
			final byte b = getByte();
			value |= ((b & 0x7FL) << i);
			if (b >= 0)
				return value;
		}
		return value;
	}

	/**
	 * Get native negative long stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return long
	 * @see #getVLong()
	 */
	public long getVNegLong() {
		return -getVLong();
	}

	/**
	 * Get Byte array (encoded as: VInt-Length + bytes)
	 * 
	 * @return byte array
	 * @see #putBytes(byte[])
	 */
	public byte[] getBytes() {
		final int len = getVInt();
		final byte[] bytes = new byte[len];
		System.arraycopy(buf, bufPosition, bytes, 0, bytes.length);
		bufPosition += bytes.length;
		return bytes;
	}

	/**
	 * Get Byte array (encoded as: Int32-Length + bytes)
	 * 
	 * @return byte array
	 * @see #putBytes(byte[])
	 */
	public byte[] getBytesF() {
		final int len = getInt();
		final byte[] bytes = new byte[len];
		System.arraycopy(buf, bufPosition, bytes, 0, bytes.length);
		bufPosition += bytes.length;
		return bytes;
	}

	/**
	 * Get String stored in UTF-8 format (encoded as: VInt-Length + bytes)
	 * 
	 * @return string
	 * @see #putString(String)
	 */
	public String getString() {
		final int len = getVInt();
		final byte[] utf = new byte[len];
		System.arraycopy(buf, bufPosition, utf, 0, utf.length);
		bufPosition += utf.length;
		return new String(utf, 0, len, charsetUTF8);
	}

	/**
	 * Get String stored in UTF-8 format (encoded as: Int32-Length + bytes)
	 * 
	 * @return string
	 * @see #putString(String)
	 */
	public String getStringF() {
		int len = getInt();
		byte[] utf = new byte[len];
		System.arraycopy(buf, bufPosition, utf, 0, utf.length);
		bufPosition += utf.length;
		return new String(utf, 0, len, charsetUTF8);
	}

	/**
	 * Get Hex String in upper case ("0123456789ABCDEF")
	 * 
	 * @return hex string
	 * @see #putHexString(String)
	 * @see #getHexStringLower()
	 */
	public String getHexStringUpper() {
		int len = getVInt();
		byte[] hex = new byte[len];
		System.arraycopy(buf, bufPosition, hex, 0, hex.length);
		bufPosition += hex.length;
		return toHex(hex, true);
	}

	/**
	 * Get Collection&lt;String&gt; stored in UTF-8 format
	 * 
	 * @param collection
	 *            to put stored elements
	 * @return collection of strings
	 * @see #putStringCollection(Collection)
	 */
	public Collection<String> getStringCollection(final Collection<String> collection) {
		final int len = getVInt();
		for (int i = 0; i < len; i++) {
			collection.add(getString());
		}
		return collection;
	}

	/**
	 * Get Collection&lt;String&gt; stored in UTF-8 format
	 * 
	 * @param clazz
	 *            to instantiate
	 * @return collection of strings
	 * @see #putStringCollection(Collection)
	 */
	@SuppressWarnings({
			"unchecked", "rawtypes"
	})
	public Collection<String> getStringCollection(final Class<? extends Collection> clazz) {
		try {
			final Collection<String> collection = clazz.newInstance();
			final int len = getVInt();
			for (int i = 0; i < len; i++) {
				collection.add(getString());
			}
			return collection;
		} catch (InstantiationException e) {
			throw new IllegalArgumentException("Invalid class", e);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Invalid class", e);
		}
	}

	/**
	 * Get Map&lt;String, String&gt; stored in UTF-8 format
	 * 
	 * @param map
	 *            to put stored elements
	 * @return map of strings
	 * @see #putStringMap(Map)
	 */
	public Map<String, String> getStringMap(final Map<String, String> map) {
		final int len = getVInt();
		for (int i = 0; i < len; i++) {
			map.put(getString(), getString());
		}
		return map;
	}

	/**
	 * Get Map&lt;String, String&gt; stored in UTF-8 format
	 * 
	 * @param clazz
	 *            to instantiate
	 * @return map of strings
	 * @see #putStringMap(Map)
	 */
	@SuppressWarnings({
			"unchecked", "rawtypes"
	})
	public Map<String, String> getStringMap(final Class<? extends Map> clazz) {
		try {
			final Map<String, String> map = clazz.newInstance();
			final int len = getVInt();
			for (int i = 0; i < len; i++) {
				map.put(getString(), getString());
			}
			return map;
		} catch (InstantiationException e) {
			throw new IllegalArgumentException("Invalid class", e);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Invalid class", e);
		}
	}

	/**
	 * Get Hex String in lower case ("0123456789abcdef")
	 * 
	 * @return hex string
	 * @see #putHexString(String)
	 * @see #getHexStringUpper()
	 */
	public String getHexStringLower() {
		int len = getVInt();
		byte[] hex = new byte[len];
		System.arraycopy(buf, bufPosition, hex, 0, hex.length);
		bufPosition += hex.length;
		return toHex(hex, false);
	}

	// ------------- LOAD -------------

	/**
	 * Load Base64 string
	 * <p>
	 * Base64 info: <a href="http://en.wikipedia.org/wiki/Base64">Base64</a>
	 *
	 * @param in input string
	 * @return this
	 * @throws InvalidInputDataException if invalid data
	 * 
	 * @see #outputStringBase64()
	 */
	public Packer loadStringBase64(final String in) throws InvalidInputDataException {
		return loadBytes(Base64.decode(in.getBytes(charsetISOLatin1)));
	}

	/**
	 * Load URL safe Base64 string
	 * <p>
	 * RFC-4648 info, The "URL and Filename safe" Base 64 Alphabet: <a
	 * href="http://tools.ietf.org/html/rfc4648#page-7">RFC-4648</a>
	 * 
	 * @param in input string
	 * @return this
	 * @throws InvalidInputDataException if invalid data
	 * 
	 * @see Packer#outputStringBase64URLSafe()
	 */
	public Packer loadStringBase64URLSafe(final String in) throws InvalidInputDataException {
		return loadBytes(Base64.decode(in.getBytes(charsetISOLatin1)));
	}

	/**
	 * Load string in hex format
	 * 
	 * @param in input string
	 * @return this
	 * @throws InvalidInputDataException if invalid data
	 * @see #outputStringHex()
	 */
	public Packer loadStringHex(final String in) throws InvalidInputDataException {
		try {
			return loadBytes(fromHex(in));
		} catch (ParseException e) {
			throw new IllegalArgumentException("Invalid input string", e);
		}
	}

	/**
	 * Load string in raw format (ISO-8859-1)
	 * 
	 * @param in input string
	 * @return this
	 * @throws InvalidInputDataException if invalid data
	 * @see #outputStringRAW()
	 */
	public Packer loadStringRAW(final String in) throws InvalidInputDataException {
		return loadBytes(in.getBytes(charsetISOLatin1));
	}

	/**
	 * Load bytes[] in raw format (ISO-8859-1)
	 * 
	 * @param in input buffer
	 * @return this
	 * @throws InvalidInputDataException if invalid data
	 * @see #outputBytes()
	 */
	public Packer loadBytes(byte[] in) throws InvalidInputDataException {
		// TODO: Improve input data parsing exceptions
		int inlen = in.length;
		int flags = 0;
		if (useFlagFooter) {
			flags = (int) in[--inlen];
		} else {
			if (useCompress)
				flags |= FLAG_COMPRESS;
			if (aesKey != null) {
				flags |= FLAG_AES;
				switch (aesTypeIV) { // useAES + randomIV
					case RANDOM_IV:
						flags |= FLAG_RANDOM_IV;
						break;
					case RANDOM_INT_IV:
						flags |= FLAG_RANDOM_INT_IV;
						break;
				}
			}
			if (useCRC)
				flags |= FLAG_CRC;
			if (mdHash != null)
				flags |= FLAG_HASH;
			if (hMac != null)
				flags |= FLAG_HMAC;
		}
		if (checkFlag(flags, FLAG_HMAC)) {
			if (hMac == null)
				throw new InvalidInputDataException("Invalid Flags (HMAC) or hmac not initialized");
			final int hmacLen = hMac.getMacLength();
			byte[] mdBuf = hmac(in, 0, inlen - hmacLen);
			boolean hmacOK = compareBuffer(in, inlen - hmacLen, mdBuf, 0, hmacLen);
			if (!hmacOK)
				throw new InvalidInputDataException("Invalid HMAC");
			inlen -= hmacLen;
		}
		if (checkFlag(flags, FLAG_HASH)) {
			if (mdHash == null)
				throw new InvalidInputDataException("Invalid Flags (HASH) or hash not initialized");
			final int mdLen = mdHash.getDigestLength();
			byte[] mdBuf = hash(in, 0, inlen - mdLen);
			boolean hashOK = compareBuffer(in, inlen - mdLen, mdBuf, 0, mdLen);
			if (!hashOK)
				throw new InvalidInputDataException("Invalid HASH");
			inlen -= mdLen;
		}
		if (checkFlag(flags, FLAG_CRC)) {
			if (!useCRC)
				throw new InvalidInputDataException("Invalid Flags (CRC)");
			final byte crc = (byte) crc8(in, 0, inlen - 1);
			final byte crc2 = in[inlen - 1];
			boolean crcOK = (crc == crc2);
			if (!crcOK)
				throw new InvalidInputDataException("Invalid CRC");
			inlen -= 1;
		}
		if (checkFlag(flags, FLAG_RSA)) {
			if (rsaKeyForDecrypt == null)
				throw new InvalidInputDataException("Invalid Flags (Crypto) or RSA crypto not initialized");
			try {
				in = cryptoAsym(in, 0, inlen, true);
			} catch (Exception e) {
				throw new InvalidInputDataException("Invalid RSA Crypto data", e);
			}
			inlen = in.length;
		}
		if (checkFlag(flags, FLAG_AES)) {
			if (aesKey == null)
				throw new InvalidInputDataException("Invalid Flags (Crypto) or AES crypto not initialized");
			if (checkFlag(flags, FLAG_RANDOM_IV)) {
				final int ivLen = ((aesType == AESTYPE.GCM) //
						? GCM_IV_LENGTH //
						: aesCipherLen);
				final byte[] ivBuf = new byte[ivLen];
				System.arraycopy(in, inlen - ivLen, ivBuf, 0, ivLen);
				initCipherIV(ivBuf, AESTYPEIV.RANDOM_IV);
				inlen -= ivLen;
			} else if (checkFlag(flags, FLAG_RANDOM_INT_IV)) {
				final int ivLen = 4; // Integer length
				final byte[] ivBuf = new byte[ivLen];
				System.arraycopy(in, inlen - ivLen, ivBuf, 0, ivLen);
				try {
					initCipherIV(generateMdfromBuffer(ivBuf, aesCipherLen), AESTYPEIV.RANDOM_INT_IV);
				} catch (Exception e) {
					throw new InvalidInputDataException("Invalid AES Crypto data (RANDOM_INT_IV)", e);
				}
				inlen -= ivLen;
			}
			try {
				in = crypto(in, 0, inlen, true);
			} catch (Exception e) {
				throw new InvalidInputDataException("Invalid AES Crypto data", e);
			}
			inlen = in.length;
		}
		if (checkFlag(flags, FLAG_COMPRESS)) {
			if (!useCompress)
				throw new InvalidInputDataException("Invalid Flags (Compressed)");
			try {
				in = inflate(in, 0, inlen);
			} catch (DataFormatException e) {
				throw new InvalidInputDataException("Invalid Compressed data", e);
			}
			inlen = in.length;
		}
		ensureCapacity(inlen);
		System.arraycopy(in, 0, buf, 0, inlen);
		bufPosition = inlen;
		flip();
		return this;
	}

	// ------------- INTERNAL -------------

	/**
	 * Calculate CRC-8 of input
	 * <p>
	 * <a href="http://en.wikipedia.org/wiki/Cyclic_redundancy_check">CRC-8</a>
	 * 
	 * @param input
	 * @param offset
	 * @param len
	 * @return crc
	 */
	static final int crc8(final byte[] input, final int offset, final int len) {
		final int poly = 0x0D5;
		int crc = 0;
		for (int i = 0; i < len; i++) {
			final byte c = input[offset + i];
			crc ^= c;
			for (int j = 0; j < 8; j++) {
				if ((crc & 0x80) != 0) {
					crc = ((crc << 1) ^ poly);
				} else {
					crc <<= 1;
				}
			}
			crc &= 0xFF;
		}
		return crc;
	}

	/**
	 * Calculate HASH of input
	 * <p>
	 * <a href="http://en.wikipedia.org/wiki/SHA-1">SHA-1</a>
	 * 
	 * @param input
	 * @param offset
	 * @param len
	 * @return hash
	 */
	final byte[] hash(final byte[] input, final int offset, final int len) {
		mdHash.update(input, offset, len);
		return mdHash.digest();
	}

	/**
	 * Calculate HMAC of input
	 * <p>
	 * <a href="http://en.wikipedia.org/wiki/HMAC">HMAC</a>
	 * 
	 * @param input
	 * @param offset
	 * @param len
	 * @return hmac
	 */
	final byte[] hmac(final byte[] input, final int offset, final int len) {
		hMac.update(input, offset, len);
		return hMac.doFinal();
	}

	/**
	 * Encrypt or Decrypt with AES
	 * 
	 * @param input
	 * @param offset
	 * @param len
	 * @param decrypt
	 * @return byte array
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	final byte[] crypto(final byte[] input, final int offset, final int len, final boolean decrypt)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		final AlgorithmParameterSpec spec = ((aesType == AESTYPE.GCM) //
				? new GCMParameterSpec(GCM_TAG_LENGTH * 8, aesIV) //
				: new IvParameterSpec(aesIV));
		aesCipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, aesKey, spec);
		return aesCipher.doFinal(input, offset, len);
	}

	/**
	 * Encrypt or Decrypt with RSA
	 * 
	 * @param input
	 * @param offset
	 * @param len
	 * @param decrypt
	 * @return
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	final byte[] cryptoAsym(final byte[] input, final int offset, final int len, final boolean decrypt)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		rsaCipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, decrypt ? rsaKeyForDecrypt
				: rsaKeyForEncrypt);
		return rsaCipher.doFinal(input, offset, len);
	}

	/**
	 * Resize input buffer to newsize
	 * 
	 * @param buf
	 * @param newsize
	 * @return buf
	 */
	static final byte[] resizeBuffer(final byte[] buf, final int newsize) {
		if (buf.length == newsize)
			return buf;
		final byte[] newbuf = new byte[newsize];
		System.arraycopy(buf, 0, newbuf, 0, Math.min(buf.length, newbuf.length));
		return newbuf;
	}

	/**
	 * Compare buffer1 and buffer2
	 * 
	 * @param buf1
	 * @param offset1
	 * @param buf2
	 * @param offset2
	 * @param len
	 * @return true if all bytes are equal
	 */
	static final boolean compareBuffer(final byte[] buf1, final int offset1, final byte[] buf2,
			final int offset2, final int len) {
		for (int i = 0; i < len; i++) {
			final byte b1 = buf1[offset1 + i];
			final byte b2 = buf2[offset2 + i];
			if (b1 != b2) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Check for a flag
	 * 
	 * @param flags
	 * @param flag
	 * @return boolean
	 */
	static final boolean checkFlag(final int flags, final int flag) {
		return ((flags & flag) != 0);
	}

	/**
	 * Transform byte array to Hex String
	 * 
	 * @param input
	 * @return hex string
	 */
	static final String toHex(final byte[] input, final int len, final boolean upper) {
		final char[] hex = new char[len << 1];
		for (int i = 0, j = 0; i < len; i++) {
			final int bx = input[i];
			final int bh = ((bx >> 4) & 0xF);
			final int bl = (bx & 0xF);
			if ((bh >= 0) && (bh <= 9)) {
				hex[j++] |= (bh + '0');
			} else if ((bh >= 0xA) && (bh <= 0xF)) {
				hex[j++] |= (bh - 0xA + (upper ? 'A' : 'a'));
			}
			if ((bl >= 0x0) && (bl <= 0x9)) {
				hex[j++] |= (bl + '0');
			} else if ((bl >= 0xA) && (bl <= 0xF)) {
				hex[j++] |= (bl - 0xA + (upper ? 'A' : 'a'));
			}
		}
		return new String(hex);
	}

	/**
	 * Transform byte array to Hex String
	 * 
	 * @param input
	 * @param upper
	 * @return hex string
	 */
	static final String toHex(final byte[] input, final boolean upper) {
		return toHex(input, input.length, upper);
	}

	/**
	 * Transform Hex String to byte array
	 * 
	 * @param hex
	 * @return byte array
	 * @throws ParseException
	 */
	static final byte[] fromHex(final String hex) throws ParseException {
		final int len = hex.length();
		final byte[] out = new byte[len / 2];
		for (int i = 0, j = 0; i < len; i++) {
			char c = hex.charAt(i);
			int v = 0;
			if ((c >= '0') && (c <= '9')) {
				v = (c - '0');
			} else if ((c >= 'A') && (c <= 'F')) {
				v = (c - 'A') + 0xA;
			} else if ((c >= 'a') && (c <= 'f')) {
				v = (c - 'a') + 0xA;
			} else {
				throw new ParseException("Invalid char", j);
			}
			if ((i & 1) == 0) {
				out[j] |= (v << 4);
			} else {
				out[j++] |= v;
			}
		}
		return out;
	}

	/**
	 * Deflate input buffer
	 * 
	 * @param in
	 * @param len
	 * @return byte array
	 */
	static final byte[] deflate(final byte[] in, final int len) {
		byte[] defBuf = new byte[len << 1];
		int payloadLength;
		synchronized (deflater) {
			deflater.reset();
			deflater.setInput(in, 0, len);
			deflater.finish();
			payloadLength = deflater.deflate(defBuf);
		}
		return resizeBuffer(defBuf, payloadLength);
	}

	/**
	 * Inflate input buffer
	 * 
	 * @param in
	 * @return byte array
	 * @throws DataFormatException
	 */
	static final byte[] inflate(final byte[] in, final int offset, final int length)
			throws DataFormatException {
		byte[] infBuf = new byte[length << 1];
		int payloadLength;
		synchronized (inflater) {
			inflater.reset();
			inflater.setInput(in, offset, length);
			payloadLength = inflater.inflate(infBuf);
		}
		return resizeBuffer(infBuf, payloadLength);
	}

	/**
	 * Input data is invalid
	 */
	public static class InvalidInputDataException extends Exception {
		private static final long serialVersionUID = 42L;

		public InvalidInputDataException(final String text) {
			super(text);
		}

		public InvalidInputDataException(final Exception e) {
			super(e);
		}

		public InvalidInputDataException(final String text, final Exception e) {
			super(text, e);
		}
	}

	static enum AESTYPEIV {
		FAKE_IV, SHARED_IV, RANDOM_IV, RANDOM_INT_IV
	}

	static enum AESTYPE {
		NONE, CBC, GCM
	}

	public static enum AutoExtendPolicy {
		/**
		 * No auto extend (default)
		 */
		NONE,
		/**
		 * Resize minimal
		 */
		MINIMAL,
		/**
		 * Resize with heuristic mode / automatic rounding
		 */
		AUTO,
		/**
		 * Resize is rounded to 8 bytes boundary
		 */
		ROUND8,
		/**
		 * Resize is rounded to 512 bytes boundary
		 */
		ROUND512,
		/**
		 * Resize is rounded to 4096 bytes boundary
		 */
		ROUND4096
	}
}
