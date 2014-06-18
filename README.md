# packer

Simple Data Packer for Java (like Kryo,... but very simplified). Open Source Java project under Apache License v2.0

### Current Development Version is [0.0.12](https://maven-release.s3.amazonaws.com/release/org/javastack/packer/0.0.12/packer-0.0.12.jar)

---

## DOC

#### Supported data types

- Fixed length types:
  - byte, char, short, int, long, double, float
- Variable length types (optimized space):
  - int, long, negative int, negative long
- Complex types:
  - String and byte[] (using Variable Length Int or Fixed Int32 for sizes)
  - HexString
  - String Collection
  - String Map

#### Features

- Compression (Deflate)
- Encryption (AES/CBC/PKCS5Padding)
  - Default IV
  - Shared IV
  - Random IV
  - Random Integer IV (compact IV)
- Encryption (RSA/ECB/PKCS1Padding)
- CRC-8 ([CRC-8 poly 0xD5](https://en.wikipedia.org/wiki/Cyclic_redundancy_check))
- Hash ([MessageDigest](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest)) 
- HMAC ([Mac](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac))

#### Usage Example

```java
import org.javastack.packer.Packer;

public class Example {
	public static void main(final String[] args) {
		// Sample usage (output):
		Packer p = new Packer();
		p.useCompress(true);               // Enable Compression
		p.useCRC(true);                    // Enable CRC
		String s1 = "hello", s2 = "world";
		String hs = "df0c290eae2b";
		byte b = 42;
		long l = 0x648C9A7109B4L;
		int ni = -192813;
		p.putString(s1).putString(s2);
		p.putHexString(hs);
		p.putByte(b);
		p.putVLong(l);
		p.putVNegInt(ni);
		p.flip();
		String out = p.outputStringBase64URLSafe();
		System.out.println(out.length() + "\t" + out);

		// Sample usage (load):
		p = new Packer();
		p.useCompress(true);               // Enable Compression
		p.useCRC(true);                    // Enable CRC
		p.loadStringBase64URLSafe(out);
		System.out.println(p.getString());
		System.out.println(p.getString());
		System.out.println(p.getHexStringUpper());
		System.out.println(p.getByte());
		System.out.println(p.getVLong());
		System.out.println(p.getVNegInt());
	}
}
```

* Full examples in [Example package](https://github.com/ggrandes/packer/tree/master/src/main/java/org/javastack/packer/example/)

---

## MAVEN

Add the maven repository location to your pom.xml: 

    <repositories>
        <repository>
            <id>ggrandes-maven-s3-repo</id>
            <url>https://maven-release.s3.amazonaws.com/release/</url>
        </repository>
    </repositories>

Add the dependency to your pom.xml:

    <dependency>
        <groupId>org.javastack</groupId>
        <artifactId>packer</artifactId>
        <version>0.0.12</version>
    </dependency>

---


## Benchmarks

###### TODO


## TODOs

- Buffer Auto-Expansion


---
Inspired in [Kryo](http://code.google.com/p/kryo/) and [Perl-Pack](http://perldoc.perl.org/functions/pack.html), this code is Java-minimalistic version.
