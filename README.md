# packer

Simple Data Packer for Java (like Kryo,... but very simplified). Open Source Java project under Apache License v2.0

### Current Development Version is [0.0.1](https://maven-release.s3.amazonaws.com/release/org/packer/packer/0.0.1/figaro-0.0.1.jar)

---

## DOC

#### Usage Example

```java
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
```

* More examples in [Example package](https://github.com/ggrandes/packer/tree/master/src/main/java/org/packer/example/)

---

## MAVEN

Add the Packer maven repository location to your pom.xml: 

    <repositories>
        <repository>
            <id>packer-maven-s3-repo</id>
            <url>https://maven-release.s3.amazonaws.com/release/</url>
        </repository>
    </repositories>

Add the Packer dependency to your pom.xml:

    <dependency>
        <groupId>org.packer</groupId>
        <artifactId>packer</artifactId>
        <version>0.0.1</version>
    </dependency>

---

## Benchmarks

###### TODO


---
Inspired in [Kryo](http://code.google.com/p/kryo/) and [Perl-Pack](http://perldoc.perl.org/functions/pack.html), this code is Java-minimalistic version.
