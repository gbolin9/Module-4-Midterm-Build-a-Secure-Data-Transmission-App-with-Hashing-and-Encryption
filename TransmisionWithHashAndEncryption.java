import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class TransmisionWithHashAndEncryption {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Scanner scanner = new Scanner(System.in);
        String input;
        int option;                                                           //This is the option for the while loop for choice between file and input
        boolean validInput = false;                                           //Set for while loop
        String filePath; 
        SecretKey secretKey = generateSecretKey(); //Key generated for symetric encryption
        String encryptedMessage; //String used to display the ciphertext
        String decryptedMessage; //String used to display the decrypted plaintext
        String hashString;


        
        while (!validInput) {

            System.out.println("Press 1 to convert a file to hash or two to convert an input to hash then press enter: ");  //Prompts user to choose option
            input = scanner.nextLine();

            try{
            option = Integer.parseInt(input);
            if (option == 1) {                      //Choice for file. Will generate hash value for file and then give the user the hash value
                System.out.println("Please enter the filename you would wish to hash. Then press enter to finish: ");  //Prompts user for a filename to be hashed.
                filePath = scanner.nextLine();
                try {
                    Path path = Paths.get(filePath);
                    String content = Files.readString(path);
                    byte[] hashedBytes = generateHash(content);
                    hashString = hashToString(hashedBytes);
                    System.out.println("The pre-hashed text is: " + content);
                    System.out.println("The hash is: " + hashString);
                    validInput = true;
                    encryptedMessage = symmetricEncryption(content, secretKey);
                    decryptedMessage = symmetricDecryption(encryptedMessage, secretKey);
                    System.out.println("The encrypted message is: " + encryptedMessage);
                    System.out.println("The decrypted message is: " + decryptedMessage);
                    
                    if (hashCheck(hashString, decryptedMessage) == false) {                 //Checks hash value to see if message is unchanged
                        System.out.println("The message is confirmed to be unchanged.");
                    }
                    else{
                        System.out.println("The message has been changed.");
                    }
                    

        }       catch (IOException e) {
                    System.err.println("Error:  " + e.getMessage());       //error message for when not provided viable file link.
        }       catch (Exception ex) {
                }
;
                
                break;
            }
            if (option == 2) {
                System.out.println("Please enter the text you would wish to hash. Then press enter to finish: ");  //Prompts user for input to be hashed.
                String test = scanner.nextLine();
                byte[] hashedBytes = generateHash(test);                                                             //Generates hash value for manual input and then presents it to user.
                hashString = hashToString(hashedBytes);
                System.out.println("The pre-hashed text is: " + test);
                System.out.println("The hash is: " + hashString);
                validInput = true;
                encryptedMessage = symmetricEncryption(test, secretKey);
                decryptedMessage = symmetricDecryption(encryptedMessage, secretKey);
                System.out.println("The encrypted message is: " + encryptedMessage);
                System.out.println("The decrypted message is: " + decryptedMessage);

                if (hashCheck(hashString, decryptedMessage) == false) {                //Checks hash value to see if message is unchanged
                    System.out.println("The message is confirmed to be unchanged.");
                    }
                else{
                    System.out.println("The message has been changed.");
                    }
                    
                break;
            }
            else {
                System.out.println("Error: " + option + " is not an option. Please enter 1 or 2 and press enter");  //Presents error if user selects a number not 1 or 2 and then prompts them to enter again.
                input = scanner.nextLine();
            }
        }
        catch (NumberFormatException e) {
            System.out.println("Error: Please enter a valid option."); //Error if user enters character/s that are not a integer.
        }   catch (Exception ex) {
            }
        }
    

        
        scanner.close() ;
    }

    public static byte[] generateHash(String stringToHash) throws NoSuchAlgorithmException {  //Generates a hash value for file text or user input text.

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(stringToHash.getBytes());
        return hashBytes;
    }
    public static String hashToString(byte[] hashedBytes) {  //Converts the hash value into a string that the user can read.
        StringBuilder builtString = new StringBuilder();
        String stringToReturn = "";
        for (byte b : hashedBytes) {
            String a = Integer.toHexString(0xff & b);
            if (a.length() == 1) {
                builtString.append('0');
        }
        builtString.append(a);
        stringToReturn =  builtString.toString();

    }
    return stringToReturn;
    
}

public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;

    }

public static String symmetricEncryption(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        return encryptedMessage;

    }

public static String symmetricDecryption(String encryptedMessage, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        String decryptedMessage = new String(decryptedBytes);

        return decryptedMessage;
    }
public static boolean hashCheck(String originalHash, String decryptedMessage) throws NoSuchAlgorithmException{

    boolean isChanged = false;
    byte[] newHashBytes = generateHash(decryptedMessage); //Generates hash value to compare to original generated hash
    String newHashString = hashToString(newHashBytes);
    if (newHashString.equals(originalHash))  //Compares new hash value to original hash value to check if unchanged.
    {
        isChanged = false;

    }
        
    else
    {
    
        isChanged = true;
    }

    return isChanged;
        
    }

    


    
}
