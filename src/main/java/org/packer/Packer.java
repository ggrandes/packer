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
package org.packer;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple Data Packer
 * 
 * Sample usage (output):
 * 
 * <code><blockquote><pre>
 * Packer p = new Packer();
 * p.useCompress(false);
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
 * </pre></blockquote></code>
 * 
 * Sample usage (load):
 * 
 * <code><blockquote><pre>
 * p = new Packer();
 * p.useCompress(false);
 * p.useCRC(false);
 * p.loadStringBase64URLSafe(input);
 * System.out.println(p.getString());
 * System.out.println(p.getString());
 * System.out.println(p.getHexStringUpper());
 * System.out.println(p.getByte());
 * System.out.println(p.getVLong());
 * System.out.println(p.getVNegInt());
 * </pre></blockquote></code>
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

	static final String CIPHER_CHAIN_PADDING = "AES/CBC/PKCS5Padding";
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
	boolean randomIV = false;
	IvParameterSpec aesIV = null;
	Cipher aesCipher = null;
	int aesCipherLen = -1;
	SecretKeySpec aesKey = null;

	final ByteBuffer buf;
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
	 * @param size
	 * @see java.nio.ByteBuffer
	 */
	public Packer(final int size) {
		this.buf = ByteBuffer.allocate(size);
	}

	/**
	 * Clear Packer Buffer see: {@link java.nio.ByteBuffer#clear()}
	 * 
	 * @return
	 */
	public Packer clear() {
		buf.clear();
		return this;
	}

	/**
	 * Flip Packer Buffer see: {@link java.nio.ByteBuffer#flip()}
	 * 
	 * @return
	 */
	public Packer flip() {
		buf.flip();
		return this;
	}

	/**
	 * Rewind Packer Buffer see: {@link java.nio.ByteBuffer#rewind()}
	 * 
	 * @return
	 */
	public Packer rewind() {
		buf.rewind();
		return this;
	}

	/**
	 * Sets the usage of Footer Flag (default true)
	 * 
	 * @param useFlagFooter
	 * @return
	 */
	public Packer useFlagFooter(final boolean useFlagFooter) {
		this.useFlagFooter = useFlagFooter;
		return this;
	}

	/**
	 * Sets the usage of Deflater/Inflater (default false)
	 * 
	 * @param useCompress
	 * @return
	 */
	public Packer useCompress(final boolean useCompress) {
		this.useCompress = useCompress;
		return this;
	}

	/**
	 * Sets the usage of CRC for sanity (default false)
	 * 
	 * @param useCRC
	 * @return
	 */
	public Packer useCRC(final boolean useCRC) {
		this.useCRC = useCRC;
		return this;
	}

	/**
	 * Sets the usage of HASH for sanity (default no)
	 * 
	 * @param hashAlg
	 *            hash algogithm
	 * @return
	 * @throws NoSuchAlgorithmException
	 * 
	 * @see {@link java.security.MessageDigest#getInstance(String)}
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
	 * @return
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * 
	 * @see {@link javax.crypto.Mac#getInstance(String)}
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
	 * Sets he usage of "AES/CBC/PKCS5Padding" (with default IV) for encryption (default no)
	 * 
	 * @param passphrase shared secret
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
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
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public Packer useAES(final String passphrase, final String sharedIV) throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		initCipher();
		initCipherIV(generateMdfromString(sharedIV, aesCipherLen), false);
		initCipherKey(passphrase);
		return this;
	}

	/**
	 * Sets he usage of "AES/CBC/PKCS5Padding" for encryption (default no)
	 * 
	 * @param passphrase shared secret
	 * @param useRandomIV true for use randomIV (more secure, more size) or false for default IV (less secure,
	 *            less size)
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public Packer useAES(final String passphrase, final boolean useRandomIV) throws NoSuchAlgorithmException,
			NoSuchPaddingException {
		initCipher();
		initCipherIV((useRandomIV ? generateRandomIV(aesCipherLen) : getDefaultIV(aesCipherLen)), useRandomIV);
		initCipherKey(passphrase);
		return this;
	}

	private final void initCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
		aesCipher = Cipher.getInstance(CIPHER_CHAIN_PADDING);
		aesCipherLen = aesCipher.getBlockSize();
	}

	private final void initCipherIV(final byte[] iv, final boolean isRandomIV) {
		randomIV = isRandomIV;
		aesIV = new IvParameterSpec(resizeBuffer(iv, aesCipherLen));
	}

	private final void initCipherKey(final String passphrase) throws NoSuchAlgorithmException {
		aesKey = new SecretKeySpec(generateMdfromString(passphrase, aesCipherLen), CIPHER);
	}

	private final byte[] getDefaultIV(final int outlen) {
		return resizeBuffer(fakeIV, outlen);
	}

	private final byte[] generateRandomIV(final int outlen) {
		return rnd.generateSeed(outlen);
	}

	private final byte[] generateMdfromString(final String shared, final int outlen)
			throws NoSuchAlgorithmException {
		final MessageDigest md = getMessageDigestForLength(outlen);
		final byte[] buf = shared.getBytes(charsetUTF8);
		md.update(buf, 0, buf.length);
		return resizeBuffer(md.digest(), outlen);
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
	 * Return the underling ByteBuffer
	 * 
	 * @return
	 */
	public ByteBuffer getByteBuffer() {
		return buf;
	}

	// ------------- PUT -------------

	/**
	 * Put native byte (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getByte()
	 */
	public Packer putByte(final byte value) {
		buf.put(value);
		return this;
	}

	/**
	 * Put native char (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getChar()
	 */
	public Packer putChar(final char value) {
		buf.putChar(value);
		return this;
	}

	/**
	 * Put native short (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getShort()
	 */
	public Packer putShort(final short value) {
		buf.putShort(value);
		return this;
	}

	/**
	 * Put native double (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getDouble()
	 */
	public Packer putDouble(final double value) {
		buf.putDouble(value);
		return this;
	}

	/**
	 * Put native float (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getFloat()
	 */
	public Packer putFloat(final float value) {
		buf.putFloat(value);
		return this;
	}

	/**
	 * Put native int (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getInt()
	 */
	public Packer putInt(final int value) {
		buf.putInt(value);
		return this;
	}

	/**
	 * Put native long (fixed length)
	 * 
	 * @param value
	 * @return
	 * @see #getLong()
	 */
	public Packer putLong(final long value) {
		buf.putLong(value);
		return this;
	}

	/**
	 * Put native int in variable length format (support negative value, but size is longer)
	 * 
	 * @param value
	 * @return
	 * @see #getVInt()
	 */
	public Packer putVInt(final int value) {
		encodeVInt(buf, value);
		return this;
	}

	/**
	 * Put native negative int in variable length format (support positive value, but size is longer)
	 * 
	 * @param value
	 * @return
	 * @see #getVNegInt()
	 */
	public Packer putVNegInt(final int value) {
		encodeVInt(buf, -value);
		return this;
	}

	/**
	 * Put native long in variable length format (support negative value, but size is longer)
	 * 
	 * @param value
	 * @return
	 * @see #getVLong()
	 */
	public Packer putVLong(final long value) {
		encodeVLong(buf, value);
		return this;
	}

	/**
	 * Put native negative long in variable length format (support positive value, but size is longer)
	 * 
	 * @param value
	 * @return
	 * @see #getVNegLong()
	 */
	public Packer putVNegLong(final long value) {
		encodeVLong(buf, -value);
		return this;
	}

	/**
	 * Put Byte array (encoded as: VInt-Length + bytes)
	 * 
	 * @param value
	 * @return
	 * @see #getBytes()
	 */
	public Packer putBytes(final byte[] value) {
		encodeVInt(buf, value.length);
		buf.put(value);
		return this;
	}

	/**
	 * Put Byte array (encoded as: Int32-Length + bytes)
	 * 
	 * @param value
	 * @return
	 * @see #getBytes()
	 */
	public Packer putBytesF(final byte[] value) {
		buf.putInt(value.length);
		buf.put(value);
		return this;
	}

	/**
	 * Put String in UTF-8 format (encoded as: VInt-Length + bytes)
	 * 
	 * @param value
	 * @return
	 * @see #getString()
	 */
	public Packer putString(final String value) {
		encodeString(buf, value);
		return this;
	}

	/**
	 * Put String in UTF-8 format (encoded as: Int32-Length + bytes)
	 * 
	 * @param value
	 * @return
	 * @see #getString()
	 */
	public Packer putStringF(final String value) {
		encodeStringF(buf, value);
		return this;
	}

	/**
	 * Put Hex String ("0123456789ABCDEF")
	 * 
	 * @param value
	 * @return
	 * @throws IllegalArgumentException
	 * @see #getHexStringLower()
	 * @see #getHexStringUpper()
	 */
	public Packer putHexString(final String value) throws IllegalArgumentException {
		try {
			byte[] hex = fromHex(value);
			encodeVInt(buf, hex.length);
			buf.put(hex);
		} catch (ParseException e) {
			throw new IllegalArgumentException("Invalid input string", e);
		}
		return this;
	}

	/**
	 * Put a Collection<String> in UTF-8 format
	 * 
	 * @param collection
	 * @return
	 * @see #getStringCollection(Collection)
	 */
	public Packer putStringCollection(final Collection<String> collection) {
		encodeVInt(buf, collection.size());
		for (final String value : collection) {
			encodeString(buf, value);
		}
		return this;
	}

	/**
	 * Put a Map<String, String> in UTF-8 format
	 * 
	 * @param value
	 * @return
	 * @see #getStringMap(Map)
	 */
	public Packer putStringMap(final Map<String, String> map) {
		encodeVInt(buf, map.size());
		for (final Entry<String, String> e : map.entrySet()) {
			final String key = e.getKey();
			final String value = e.getValue();
			encodeString(buf, key);
			encodeString(buf, value);
		}
		return this;
	}

	// ------------- OUTPUT -------------

	/**
	 * Output Base64 string
	 * <p>
	 * Base64 info: <a href="http://en.wikipedia.org/wiki/Base64">Base64</a>
	 * 
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
	 * @see #loadStringBase64URLSafe(String)
	 */
	public String outputStringBase64URLSafe() {
		return new String(Base64.encode(outputBytes(), true), charsetISOLatin1);
	}

	/**
	 * Output string in hex format
	 * 
	 * @return
	 * @see #loadStringHex(String)
	 */
	public String outputStringHex() {
		return toHex(outputBytes(), true);
	}

	/**
	 * Output string in raw format (ISO-8859-1)
	 * 
	 * @return
	 * @see #loadStringRAW(String)
	 */
	public String outputStringRAW() {
		return new String(outputBytes(), charsetISOLatin1);
	}

	/**
	 * Output bytes in raw format
	 * 
	 * @return
	 * @throws IllegalArgumentException
	 * 
	 * @see #loadBytes(byte[])
	 * @see #useCompress(boolean)
	 * @see #useCRC(boolean)
	 * @see #useHASH(String)
	 */
	public byte[] outputBytes() {
		byte[] tmpBuf = buf.array();
		int len = buf.limit();
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
				throw new IllegalArgumentException("Encryption failed", e);
			}
			len = tmpBuf.length;
			//
			if ((aesIV != null) && randomIV) { // useAES + randomIV
				flags |= FLAG_RANDOM_IV;
				final byte[] ivBuf = aesIV.getIV();
				tmpBuf = resizeBuffer(tmpBuf, len + ivBuf.length);
				System.arraycopy(ivBuf, 0, tmpBuf, len, ivBuf.length);
				len = tmpBuf.length;
			}
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
		}
		return tmpBuf;
	}

	// ------------- GET -------------

	/**
	 * Get native byte (fixed length)
	 * 
	 * @return
	 * @see #putByte(byte)
	 */
	public byte getByte() {
		return buf.get();
	}

	/**
	 * Get native char (fixed length)
	 * 
	 * @return
	 * @see #putChar(char)
	 */
	public char getChar() {
		return buf.getChar();
	}

	/**
	 * Get native short (fixed length)
	 * 
	 * @return
	 * @see #putShort(short)
	 */
	public short getShort() {
		return buf.getShort();
	}

	/**
	 * Get native double (fixed length)
	 * 
	 * @return
	 * @see #putDouble(double)
	 */
	public double getDouble() {
		return buf.getDouble();
	}

	/**
	 * Get native float (fixed length)
	 * 
	 * @return
	 * @see #putFloat(float)
	 */
	public float getFloat() {
		return buf.getFloat();
	}

	/**
	 * Get native int (fixed length)
	 * 
	 * @return
	 * @see #putInt(int)
	 */
	public int getInt() {
		return buf.getInt();
	}

	/**
	 * Get native long (fixed length)
	 * 
	 * @return
	 * @see #putLong(long)
	 */
	public long getLong() {
		return buf.getLong();
	}

	/**
	 * Get native int stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return
	 * @see #getVNegInt()
	 */
	public int getVInt() {
		return decodeVInt(buf);
	}

	/**
	 * Get native negative int stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return
	 * @see #getVInt()
	 */
	public int getVNegInt() {
		return -decodeVInt(buf);
	}

	/**
	 * Get native long stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return
	 * @see #getVNegLong()
	 */
	public long getVLong() {
		return decodeVLong(buf);
	}

	/**
	 * Get native negative long stored in variable length format (support positive value, but size is longer)
	 * 
	 * @return
	 * @see #getVLong()
	 */
	public long getVNegLong() {
		return -decodeVLong(buf);
	}

	/**
	 * Get Byte array (encoded as: VInt-Length + bytes)
	 * 
	 * @return
	 * @see #putBytes(byte[])
	 */
	public byte[] getBytes() {
		int len = decodeVInt(buf);
		byte[] bytes = new byte[len];
		buf.get(bytes);
		return bytes;
	}

	/**
	 * Get Byte array (encoded as: Int32-Length + bytes)
	 * 
	 * @return
	 * @see #putBytes(byte[])
	 */
	public byte[] getBytesF() {
		int len = buf.getInt();
		byte[] bytes = new byte[len];
		buf.get(bytes);
		return bytes;
	}

	/**
	 * Get String stored in UTF-8 format (encoded as: VInt-Length + bytes)
	 * 
	 * @return
	 * @see #putString(String)
	 */
	public String getString() {
		return decodeString(buf);
	}

	/**
	 * Get String stored in UTF-8 format (encoded as: Int32-Length + bytes)
	 * 
	 * @return
	 * @see #putString(String)
	 */
	public String getStringF() {
		return decodeStringF(buf);
	}

	/**
	 * Get Hex String in upper case ("0123456789ABCDEF")
	 * 
	 * @return
	 * @see #putHexString(String)
	 * @see #getHexStringLower()
	 */
	public String getHexStringUpper() {
		int len = decodeVInt(buf);
		byte[] hex = new byte[len];
		buf.get(hex);
		return toHex(hex, true);
	}

	/**
	 * Get Collection<String> stored in UTF-8 format
	 * 
	 * @param collection
	 *            to put stored elements
	 * @return
	 * @see #putStringCollection(Collection)
	 */
	public Collection<String> getStringCollection(final Collection<String> collection) {
		final int len = decodeVInt(buf);
		for (int i = 0; i < len; i++) {
			collection.add(decodeString(buf));
		}
		return collection;
	}

	/**
	 * Get Collection<String> stored in UTF-8 format
	 * 
	 * @param clazz
	 *            to instantiate
	 * @return
	 * @see #putStringCollection(Collection)
	 */
	@SuppressWarnings({
			"unchecked", "rawtypes"
	})
	public Collection<String> getStringCollection(final Class<? extends Collection> clazz) {
		try {
			final Collection<String> collection = clazz.newInstance();
			final int len = decodeVInt(buf);
			for (int i = 0; i < len; i++) {
				collection.add(decodeString(buf));
			}
			return collection;
		} catch (InstantiationException e) {
			throw new IllegalArgumentException("Invalid class", e);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Invalid class", e);
		}
	}

	/**
	 * Get Map<String, String> stored in UTF-8 format
	 * 
	 * @param map
	 *            to put stored elements
	 * @return
	 * @see #putStringMap(Map)
	 */
	public Map<String, String> getStringMap(final Map<String, String> map) {
		final int len = decodeVInt(buf);
		for (int i = 0; i < len; i++) {
			map.put(decodeString(buf), decodeString(buf));
		}
		return map;
	}

	/**
	 * Get Map<String, String> stored in UTF-8 format
	 * 
	 * @param clazz
	 *            to instantiate
	 * @return
	 * @see #putStringMap(Map)
	 */
	@SuppressWarnings({
			"unchecked", "rawtypes"
	})
	public Map<String, String> getStringMap(final Class<? extends Map> clazz) {
		try {
			final Map<String, String> map = clazz.newInstance();
			final int len = decodeVInt(buf);
			for (int i = 0; i < len; i++) {
				map.put(decodeString(buf), decodeString(buf));
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
	 * @return
	 * @see #putHexString(String)
	 * @see #getHexStringUpper()
	 */
	public String getHexStringLower() {
		int len = decodeVInt(buf);
		byte[] hex = new byte[len];
		buf.get(hex);
		return toHex(hex, false);
	}

	// ------------- LOAD -------------

	/**
	 * Load Base64 string
	 * <p>
	 * Base64 info: <a href="http://en.wikipedia.org/wiki/Base64">Base64</a>
	 * 
	 * @throws InvalidInputDataException
	 * 
	 * @see #outputStringBase64()
	 */
	public Packer loadStringBase64(final String in) throws InvalidInputDataException {
		final byte[] tmpBuf = Base64.decode(in.getBytes(charsetISOLatin1));
		return loadBytes(tmpBuf);
	}

	/**
	 * Load URL safe Base64 string
	 * <p>
	 * RFC-4648 info, The "URL and Filename safe" Base 64 Alphabet: <a
	 * href="http://tools.ietf.org/html/rfc4648#page-7">RFC-4648</a>
	 * 
	 * @throws InvalidInputDataException
	 * 
	 * @see Packer#outputStringBase64URLSafe()
	 */
	public Packer loadStringBase64URLSafe(final String in) throws InvalidInputDataException {
		final byte[] tmpBuf = Base64.decode(in.getBytes(charsetISOLatin1));
		return loadBytes(tmpBuf);
	}

	/**
	 * Load string in hex format
	 * 
	 * @return
	 * @throws InvalidInputDataException
	 * @throws ParseException
	 * @see #outputStringHex()
	 */
	public Packer loadStringHex(final String in) throws InvalidInputDataException {
		try {
			byte[] tmpBuf = fromHex(in);
			return loadBytes(tmpBuf);
		} catch (ParseException e) {
			throw new IllegalArgumentException("Invalid input string", e);
		}
	}

	/**
	 * Load string in raw format (ISO-8859-1)
	 * 
	 * @return
	 * @throws InvalidInputDataException
	 * @see #outputStringRAW()
	 */
	public Packer loadStringRAW(final String in) throws InvalidInputDataException {
		final byte[] tmpBuf = in.getBytes(charsetISOLatin1);
		return loadBytes(tmpBuf);
	}

	/**
	 * Load bytes[] in raw format (ISO-8859-1)
	 * 
	 * @return
	 * @throws InvalidInputDataException
	 * @see #outputBytes()
	 */
	public Packer loadBytes(byte[] in) throws InvalidInputDataException {
		int inlen = in.length;
		int flags = 0;
		if (useFlagFooter) {
			flags = (int) in[--inlen];
		} else {
			if (useCompress)
				flags |= FLAG_COMPRESS;
			if (aesKey != null) {
				flags |= FLAG_AES;
				if (randomIV) // useAES + randomIV
					flags |= FLAG_RANDOM_IV;
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
		if (checkFlag(flags, FLAG_AES)) {
			if (aesKey == null)
				throw new InvalidInputDataException("Invalid Flags (Crypto) or crypto not initialized");
			if (checkFlag(flags, FLAG_RANDOM_IV)) {
				final int ivLen = aesCipherLen;
				final byte[] ivBuf = new byte[ivLen];
				System.arraycopy(in, inlen - ivLen, ivBuf, 0, ivLen);
				initCipherIV(ivBuf, true);
				inlen -= ivLen;
			}
			try {
				in = crypto(in, 0, inlen, true);
			} catch (Exception e) {
				throw new InvalidInputDataException("Invalid Crypto data", e);
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
		buf.clear();
		buf.put(in, 0, inlen);
		buf.flip();
		buf.rewind();
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
	 * @return
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
	 * @return
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
	 * @return
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
	 * @return
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	final byte[] crypto(final byte[] input, final int offset, final int len, final boolean decrypt)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		aesCipher.init(decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, aesKey, aesIV);
		return aesCipher.doFinal(input, offset, len);
	}

	/**
	 * Resize input buffer to newsize
	 * 
	 * @param buf
	 * @param newsize
	 * @return
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
	 * @return
	 */
	static final boolean checkFlag(final int flags, final int flag) {
		return ((flags & flag) != 0);
	}

	/**
	 * Transform byte array to Hex String
	 * 
	 * @param input
	 * @return
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
	 * @return
	 */
	static final String toHex(final byte[] input, final boolean upper) {
		return toHex(input, input.length, upper);
	}

	/**
	 * Transform Hex String to byte array
	 * 
	 * @param hex
	 * @return
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
	 * Write String into buffer in UTF-8 format (encoded as: VInt-Length + bytes)
	 * 
	 * @param buf
	 * @param value
	 */
	static final void encodeString(final ByteBuffer out, final String value) {
		final byte[] utf = value.getBytes(charsetUTF8);
		encodeVInt(out, utf.length);
		out.put(utf);
	}

	/**
	 * Write String into buffer in UTF-8 format (encoded as: Int32-Length + bytes)
	 * 
	 * @param buf
	 * @param value
	 */
	static final void encodeStringF(final ByteBuffer out, final String value) {
		final byte[] utf = value.getBytes(charsetUTF8);
		out.putInt(utf.length);
		out.put(utf);
	}

	/**
	 * Read String from buffer stored in UTF-8 format (encoded as: VInt-Length + bytes)
	 * 
	 * @param buf
	 * @return
	 */
	static final String decodeString(final ByteBuffer in) {
		int len = decodeVInt(in);
		byte[] utf = new byte[len];
		in.get(utf);
		return new String(utf, 0, len, charsetUTF8);
	}

	/**
	 * Read String from buffer stored in UTF-8 format (encoded as: Int32-Length + bytes)
	 * 
	 * @param buf
	 * @return
	 */
	static final String decodeStringF(final ByteBuffer in) {
		int len = in.getInt();
		byte[] utf = new byte[len];
		in.get(utf);
		return new String(utf, 0, len, charsetUTF8);
	}

	/**
	 * Write native int into buffer in variable length format
	 * 
	 * @param out
	 * @param value
	 */
	static final void encodeVInt(final ByteBuffer out, int value) {
		int i = 0;
		while (((value & ~0x7FL) != 0L) && ((i += 7) < 32)) {
			out.put((byte) ((value & 0x7FL) | 0x80L));
			value >>>= 7;
		}
		out.put((byte) value);
	}

	/**
	 * Write native long into buffer in variable length format
	 * 
	 * @param out
	 * @param value
	 */
	static final void encodeVLong(final ByteBuffer out, long value) {
		// org.apache.lucene.util.packed.AbstractBlockPackedWriter
		int i = 0;
		while (((value & ~0x7FL) != 0L) && ((i += 7) < 64)) {
			out.put((byte) ((value & 0x7FL) | 0x80L));
			value >>>= 7;
		}
		out.put((byte) value);
	}

	/**
	 * Read native int from buffer in variable length format
	 * 
	 * @param in
	 */
	static final int decodeVInt(final ByteBuffer in) {
		int value = 0;
		for (int i = 0; i <= 32; i += 7) {
			final byte b = in.get();
			value |= ((b & 0x7FL) << i);
			if (b >= 0)
				return value;
		}
		return value;
	}

	/**
	 * Read native long from buffer in variable length format
	 * 
	 * @param in
	 */
	static final long decodeVLong(final ByteBuffer in) {
		// org.apache.lucene.util.packed.BlockPackedReaderIterator
		long value = 0;
		for (int i = 0; i <= 64; i += 7) {
			final byte b = in.get();
			value |= ((b & 0x7FL) << i);
			if (b >= 0)
				return value;
		}
		return value;
	}

	/**
	 * Deflate input buffer
	 * 
	 * @param in
	 * @param len
	 * @return
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
	 * @return
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
}
