package org.javastack.packer.example;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.javastack.packer.Packer;
import org.javastack.packer.Packer.AutoExtendPolicy;

public class Example {

	public static void main(final String[] args) throws Exception {
		KeyPair kp = Packer.generateKeyPair(2048);		// Generate KeyPair (RSA)
		System.out.println("--- Sample 1");
		// Sample usage (output):
		Packer p = new Packer(8);
		p.setAutoExtendPolicy(AutoExtendPolicy.AUTO);	// Enable AutoExtend
		p.useCompress(true);                       		// Enable Compression
		p.useAES("secret", true);                  		// Enable Encryption (AES)
		p.useRSA(kp.getPublic(), kp.getPrivate()); 		// Enable Encryption (RSA)
		p.useCRC(true);                            		// Enable CRC
		p.useHASH("SHA-256");                      		// Enable HASH (SHA-256)
		p.useHMAC("HmacSHA256", "secret");         		// Enable Hash-MAC (SHA-256)
		String s1 = "hello", s2 = "world";
		String hs = "df0c290eae2b";
		byte b = 42;
		long l = 0x648C9A7109B4L;
		int ni = -192813;
		short shr = -27;
		float flt = 1.586f;
		double dbl = 12345678.87654321;
		Collection<String> sc1 = new ArrayList<String>();
		sc1.add("ola");
		sc1.add("k");
		sc1.add("ase");
		Map<String, String> sm1 = new LinkedHashMap<String, String>();
		sm1.put("alice", "wonderland");
		sm1.put("wizzard", "oz");
		p.putString(s1).putString(s2);
		p.putHexString(hs);
		p.putByte(b);
		p.putVLong(l);
		p.putVNegInt(ni);
		p.putShort(shr);
		p.putFloat(flt);
		p.putDouble(dbl);
		p.putStringCollection(sc1);
		p.putStringMap(sm1);
		p.flip();
		String out = p.outputStringBase64URLSafe();
		System.out.println("output:\t" + out + "\t" + "len:" + out.length());

		System.out.println("--- Sample 2");
		// Sample usage (load):
		p = new Packer(8);
		p.setAutoExtendPolicy(AutoExtendPolicy.AUTO);	// Enable AutoExtend
		p.useCompress(true);                       		// Enable Compression
		p.useAES("secret", true);                  		// Enable Encryption (AES)
		p.useRSA(kp.getPublic(), kp.getPrivate());		// Enable Encryption (RSA)
		p.useCRC(true);                            		// Enable CRC
		p.useHASH("SHA-256");                      		// Enable HASH (SHA-256)
		p.useHMAC("HmacSHA256", "secret");         		// Enable Hash-MAC (SHA-256)
		p.loadStringBase64URLSafe(out);
		Collection<String> sc2 = new ArrayList<String>();
		System.out.println(s1 + "\t" + p.getString());
		System.out.println(s2 + "\t" + p.getString());
		System.out.println(hs + "\t" + p.getHexStringLower());
		System.out.println(b + "\t" + p.getByte());
		System.out.println(l + "\t" + p.getVLong());
		System.out.println(ni + "\t" + p.getVNegInt());
		System.out.println(shr + "\t" + p.getShort());
		System.out.println(flt + "\t" + p.getFloat());
		System.out.println(dbl + "\t" + p.getDouble());
		System.out.println(sc1 + "\t" + p.getStringCollection(sc2));
		System.out.println(sm1 + "\t" + p.getStringMap(LinkedHashMap.class));

		System.out.println("--- Sample 3");
		// Sample usage (Output AESGCM):
		p = new Packer(8);
		p.setAutoExtendPolicy(AutoExtendPolicy.AUTO);	// Enable AutoExtend
		p.useAESGCM("secret");                  		// Enable Encryption (AES-GCM)
		//
		p.putString(s1).putString(s2);
		p.flip();
		out = p.outputStringBase64URLSafe();
		System.out.println("output:\t" + out + "\t" + "len:" + out.length());
		// Sample usage (load AESGCM):
		p = new Packer(8);
		p.setAutoExtendPolicy(AutoExtendPolicy.AUTO);	// Enable AutoExtend
		p.useAESGCM("secret");                  		// Enable Encryption (AES-GCM)
		p.loadStringBase64URLSafe(out);
		System.out.println(s1 + "\t" + p.getString());
		System.out.println(s2 + "\t" + p.getString());
	}
}
