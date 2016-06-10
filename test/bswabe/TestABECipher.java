/*
 * TestABECipher.java         

 * This module is part of the --DET-ABE API--, a Java library  
 * of the SCABE project (Secure Storage and Sharing of data in 
 * the Cloud by using  Attribute based encryption).
 * The DET-ABE library is free software. This library is distributed 
 * on an "AS IS" basis,WITHOUT WARRANTY OF ANY KIND, either expressed 
 * or implied.
 
 * Copyright (c) Miguel Morales-Sandoval (morales.sandoval.miguel@gmail.com)
 * Created:      Nov 10, 2014
 * Last modification:  May 10, 2016
 */
 
package test.bswabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedList;
import src.utilABE.*;

import src.cpabe.bsw.accessStructure.*;
import src.cpabe.bsw.ct.*;
import src.cpabe.bsw.common.*;
import src.cpabe.bsw.*;


/**
 * In all test, what is encrypted and decrypted by CP-ABE is an AES-key.
 */
public class TestABECipher{

   public static void doTestEncrypt(){
   
      int secLevel = 128;
      String type = "F";
      final int MAX_ITERs = 1;
      
      PublicKey PK = new PublicKey(secLevel,type);  // 
      src.trustedAuth.bsw.MasterKey MK = new src.trustedAuth.bsw.MasterKey(secLevel,type);  // 
      
      System.out.println("ABE-PK: \n" + PK);
      System.out.println("ABE-MK: \n" + MK);
               
      Pairing pairing = PK.e;
            
      double[][] timing = new double[MAX_ITERs][8];
   
          
      String policy1 = "A";
      String policy2 = "A B 2of2";
      String policy4 = "A B 1of2 C D 1of2 1of2";
      String policy6 = "A B 1of2 C D 1of2 E F 1of2 1of2 1of2";
      String policy8 = "A B 1of2 C D 1of2 1of2 E F 1of2 G H 1of2 1of2 1of2";
      String policy10 = "A B 1of2 C D 1of2 1of2 E F 1of2 G H 1of2 1of2 I J 1of2 1of2 1of2";
      
      //String[] policies = {policy1,policy2,policy4,policy6,policy8,policy10};
      String[] policies = {policy10};
      
      
      List<String> attributes = new LinkedList<String>();
      attributes.add("A");
      attributes.add("B");
            
      List keyList = null;
      List decryptedList = null;
      
      for(String policy:policies){
               
         AccessTree tree = new AccessTree(policy);  
      
         if(!tree.isValid()){
            System.out.println("DET-ABE ENCRYPTION LOCAL MODULE: Given policy is not valid (bad boolean equation). Program ends." );
            System.exit(0);
         }
         
         if(!tree.checkSatisfy(attributes)){
            System.out.println("DET-ABE ENCRYPTION LOCAL MODULE: Given attribute set does not satisfy the encryption." );
            System.exit(0);
         }
         
         System.out.println("List " + attributes + " satisfy the tree"); 
      
      
      
         System.out.println("Tree: \n" + tree);   
      
         decryptedList = new ArrayList();
         keyList = new ArrayList();
      
         for (int i = 0; i < MAX_ITERs; i++){
            
         //1. Creates the AES private key 
            src.symmetric.AESCipher.genSymmetricKey(secLevel);
         
         //2. Encrypts the AES key with ABE. The secLevel and type 
            ABECipher cipher = new ABECipher();
            ABECiphertext ct = cipher.encrypt(PK, src.symmetric.AESCipher.key, tree);
         
         //3. Asks the private key for a user with the given attribs
            ABEPrivateKey prv = src.trustedAuth.bsw.ABETrustedAuthority.keyGen(PK,MK,attributes);
         
         
            prv.show();
            ct.show();
         
         //CP-ABE decryption   
            Element m = cipher.decrypt(ct, prv, pairing);
            
            java.math.BigInteger bi = m.toBigInteger();
            byte[] llave = llave = bi.toByteArray();
         
            if(secLevel/8 != llave.length){
            //System.out.println("\t****************DET-ABE DECRYPTION MODULE: decrypted AES-key is greater: " + llave.length + "-bytes");
            //System.out.println("\t****************key = " + bi);
               byte[] tmp = new byte[llave.length - 1];
               System.arraycopy(llave, 1, tmp, 0, tmp.length);
               llave = tmp;   
            }
         
            keyList.add(src.symmetric.AESCipher.key);
            decryptedList.add(llave);
         
            timing[i][0] = src.symmetric.AESCipher.timing[0];   //time for AES key gen
            timing[i][1] = ABECipher.timing[3];   //time for ABE map2point, maps the AES-key to GT element
            timing[i][2] = ABECipher.timing[4];   //time for ABE encryption - c and c' generation time
            timing[i][3] = ABECipher.timing[5];   //time for secret distribution in the access tree, compute [cy, cy']
            timing[i][4] = ABECipher.timing[0];   //time for ABE decription - time for reduced tree generation
            timing[i][5] = ABECipher.timing[1];   //time for recovering the secret from the access structure using the Shamir algorithm
            timing[i][6] = ABECipher.timing[2];   //time for ABE decryption - with the recovered secret, the final arithmetic operations are computed to decrypt the AES key
            timing[i][7] = src.trustedAuth.bsw.ABETrustedAuthority.timing;   //time for generating an ABE decryption key
         
         }
      
      
         System.out.println("\n\n----- Policy = " + policy);
      
         for (int i = 0; i < MAX_ITERs; i++){
         
            if(!(new java.math.BigInteger(1,(byte[])keyList.get(i)).equals(new java.math.BigInteger(1,(byte[])decryptedList.get(i)))))
               System.out.println("*** HIT -->> NOT EQUAL at " + i);
            else
               System.out.println("*** test " + i + ": success!    AES-key encrypted and recovered correctly.");
         
         }
      
      //muestra los resultados,
         System.out.println("\n Timing (in seconds)");
         System.out.println("AES kgen\t m2point\t c&c'\t\t shamir \t redTree\t shamir inv\t decrypt\t prv k gen");
         for (int i = 0; i < MAX_ITERs; i++){
            for(int j = 0; j < 8; j++)
               System.out.print(timing[i][j] + ",\t");
            System.out.println();
         }
      }
   }  


   public static void main(String args[]){
      doTestEncrypt();
   
   }  
}
