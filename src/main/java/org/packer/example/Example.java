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
		short shr = -27;
		p.putString(s);
		p.putHexString(hs);
		p.putByte(b);
		p.putVLong(l);
		p.putVNegInt(ni);
		p.putShort(shr);
		p.flip();
		String out = p.outputStringBase64URLSafe();
		System.out.println("output:\t" + out + "\t" + "len:" + out.length());

		// Sample usage (load):
		p = new Packer();
		p.useCompress(false);
		p.useCRC(false);
		p.loadStringBase64URLSafe(out);
		System.out.println(s + "\t" + p.getString());
		System.out.println(hs + "\t" + p.getHexStringLower());
		System.out.println(b + "\t" + p.getByte());
		System.out.println(l + "\t" + p.getVLong());
		System.out.println(ni + "\t" + p.getVNegInt());
		System.out.println(shr + "\t" + p.getShort());
	}

}
