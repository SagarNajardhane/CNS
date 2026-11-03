import java.math.BigInteger;

public class DH_MITM {
    public static void main(String[] args) {

        // Public parameters: beta = base (g), p = prime modulus
        BigInteger beta = BigInteger.valueOf(5);
        BigInteger p = BigInteger.valueOf(23);

        // Private keys (X)
        BigInteger XA  = BigInteger.valueOf(6);   // Alice
        BigInteger XB  = BigInteger.valueOf(15);  // Bob
        BigInteger XE1 = BigInteger.valueOf(7);   // Eve (toward Alice)
        BigInteger XE2 = BigInteger.valueOf(11);  // Eve (toward Bob)

        // Public keys: Y = beta^X mod p
        BigInteger YA  = beta.modPow(XA, p);
        BigInteger YB  = beta.modPow(XB, p);
        BigInteger YE1 = beta.modPow(XE1, p);
        BigInteger YE2 = beta.modPow(XE2, p);

        // Shared keys: Z = (other party's Y)^(own X) mod p
        BigInteger ZA  = YE1.modPow(XA, p);   // Alice uses Eve's fake key
        BigInteger ZB  = YE2.modPow(XB, p);   // Bob uses Eve's fake key
        BigInteger ZE1 = YA.modPow(XE1, p);   // Eve with Alice
        BigInteger ZE2 = YB.modPow(XE2, p);   // Eve with Bob

        System.out.println("Beta = " + beta + ", p = " + p);

        System.out.println("\n--- Alice ---");
        System.out.println("XA (private) = " + XA);
        System.out.println("YA (public)  = " + YA);
        System.out.println("ZA (shared)  = " + ZA);

        System.out.println("\n--- Bob ---");
        System.out.println("XB (private) = " + XB);
        System.out.println("YB (public)  = " + YB);
        System.out.println("ZB (shared)  = " + ZB);

        System.out.println("\n--- Eve ---");
        System.out.println("XE1 (private) = " + XE1 + ", XE2 (private) = " + XE2);
        System.out.println("YE1 (public)  = " + YE1 + ", YE2 (public)  = " + YE2);
        System.out.println("ZE1 (shared)  = " + ZE1 + ", ZE2 (shared)  = " + ZE2);

        System.out.println("\n--- Verification ---");
        System.out.println("ZA == ZE1 : " + ZA.equals(ZE1));
        System.out.println("ZB == ZE2 : " + ZB.equals(ZE2));

        if (ZA.equals(ZE1) && ZB.equals(ZE2)) {
            System.out.println("\nMITM Attack Successful!");
            System.out.println("Eve can intercept communication.");
        }
    }
}