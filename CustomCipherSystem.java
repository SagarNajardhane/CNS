public class CustomCipherSystem {

    private String secretKey;

    // Constructor to set the secret key
    public CustomCipherSystem(String secretKey) {
        this.secretKey = secretKey;
    }

    // 1. Encryption Method 
    public String encrypt(String plaintext) {
        StringBuilder ciphertext = new StringBuilder();
        
        for (int i = 0; i < plaintext.length(); i++) {
            char plainChar = plaintext.charAt(i);
            char keyChar = secretKey.charAt(i % secretKey.length());
            
            // Custom Logic: ASCII value XOR with key character, then shift by +5
            char encryptedChar = (char) ((plainChar ^ keyChar) + 5);
            ciphertext.append(encryptedChar);
        }
        
        return ciphertext.toString();
    }

    // 2. Decryption Method 
    public String decrypt(String ciphertext) {
        StringBuilder plaintext = new StringBuilder();
        
        for (int i = 0; i < ciphertext.length(); i++) {
            char cipherChar = ciphertext.charAt(i);
            char keyChar = secretKey.charAt(i % secretKey.length());
            
            // Reverse Logic: Subtract 5 first, then XOR with key character
            char decryptedChar = (char) ((cipherChar - 5) ^ keyChar);
            plaintext.append(decryptedChar);
        }
        
        return plaintext.toString();
    }

    // --- Main Method (Execution) ---
    public static void main(String[] args) {
        // Startup company's secret key
        String myKey = "StartupSecret2026";
        
        // Sensitive document or message
        String originalMessage = "CONFIDENTIAL: Project X Source Code and Contracts.";
        
        // Create object of our custom cipher system
        CustomCipherSystem cipherSystem = new CustomCipherSystem(myKey);
        
        // Encrypt and Decrypt
        String encryptedMsg = cipherSystem.encrypt(originalMessage);
        String decryptedMsg = cipherSystem.decrypt(encryptedMsg);
        
        // Print the results
        System.out.println("--- Custom Encryption System Demo (Java) ---");
        System.out.println("1. Original Message   : " + originalMessage);
        System.out.println("2. Encrypted Ciphertext : " + encryptedMsg);
        System.out.println("3. Decrypted Message  : " + decryptedMsg);
    }
}