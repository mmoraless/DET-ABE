/*
 * TestAESCipher.java         

 * This module is part of the --DET-ABE API--, a Java library  
 * of the SCABE project (Secure Storage and Sharing of data in 
 * the Cloud by using  Attribute based encryption).
 * The DET-ABE library is free software. This library is distributed 
 * on an "AS IS" basis,WITHOUT WARRANTY OF ANY KIND, either expressed 
 * or implied.
 
 * Copyright (c) Miguel Morales-Sandoval (morales.sandoval.miguel@gmail.com)
 * Created:    02 de octubre de 2014
 * Last modification: 05 junio de 2015 (CBC mode)
 */

package test.bswabe;

import src.utilABE.Files;

public class TestAESCipher{
  

   
   public static void test() throws Exception{
   
      final int SEC_LEVEL = 128;
      final int MAX_ITERS = 32;
      
      double keyGen[] = new double[MAX_ITERS];
      double encrypt[] = new double[MAX_ITERS];
      double decrypt[] = new double[MAX_ITERS];
      
      String file = "test/results/file.pdf";
      
      for (int i = 0; i < MAX_ITERS; i++){
      
         try{
            //Open source data
            byte plaitext[] = Files.readBytesFromFile(file);   
            
            //generate key
            src.symmetric.AESCipher.genSymmetricKey(SEC_LEVEL);
            
            //encryp data with key
            byte[] cipherText = src.symmetric.AESCipher.encrypt(plaitext);
         
            //Store results as byte[]
            Files.storeBytesInFile(cipherText, file + "" + i + ".enc");
            Files.storeBytesInFile(src.symmetric.AESCipher.iv, file + "" + i + ".iv");
           
           
           //decrypt the file
            byte[] cipherText2 = Files.readBytesFromFile(file + "" + i + ".enc");
             
            byte iv2[] = Files.readBytesFromFile(file + "" + i + ".iv");
            byte[] plaintext2 = src.symmetric.AESCipher.decrypt(cipherText2, iv2, src.symmetric.AESCipher.key);
             
             //store decrypted data
            Files.storeBytesInFile(plaintext2, file + "" + i + ".dec");
             
             //compares file with its decrypted version
              
            keyGen[i] = src.symmetric.AESCipher.timing[0];
            encrypt[i] = src.symmetric.AESCipher.timing[1];
            decrypt[i] = src.symmetric.AESCipher.timing[2];
         
            
         }
         catch(Exception e){
            System.out.println("AES MODULE: EXCEPTION");
            e.printStackTrace();
            System.out.println("---------------------------");
         }
      
      
         
      }
      
      System.out.println("\nTime (seconds)");
      System.out.println("\n\t AES-key gen, AES-encryption time, AES-dcryption time");
         
      for (int i = 0; i < MAX_ITERS; i++)
         System.out.println(keyGen[i] + "," + encrypt[i] +  "," + decrypt[i]);
      
            
   }
   
   public static void main(String []args) throws Exception{
      test();   
   }

}