package org.packer.example;

import org.packer.Packer;

public class Example {

	public static void main(final String[] args) {
		// Sample usage (output):
		Packer p = new Packer();
		p.useCompress(false);
		p.useCRC(false);
		String s = "hello world";
		String hs = "df0c290eae2b";
		byte b = 42;
		long l = 0x648C9A7109B4L;
		int ni = -192813;
		p.putString(s);
		p.putHexString(hs);
		p.putByte(b);
		p.putVLong(l);
		p.putVNegInt(ni);
		p.flip();
		String out = p.outputStringBase64URLSafe();
		System.out.println(out.length() + "\t" + out);

		// Sample usage (load):
		p = new Packer();
		p.useCompress(false);
		p.useCRC(false);
		p.loadStringBase64URLSafe(out);
		System.out.println(p.getString());
		System.out.println(p.getHexStringUpper());
		System.out.println(p.getByte());
		System.out.println(p.getVLong());
		System.out.println(p.getVNegInt());
	}

}
