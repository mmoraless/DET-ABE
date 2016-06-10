/*
 * TestDETABE.java         

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
import src.detabe.*;

/**
 * For encryption, a security level, curve type and policy must be selected.
 * The content is encryted with AES and the AES-key is encrypted with CP-ABE.
 * When decrypting, the AES-key is first decrypted using the ABE decryption key 
 * that matches the encryption policy. Then the content is decrypted using that
 * AES-key.
 */
public class TestDETABE{

    
   public static void main(String args[]){
   
      String policy1 = "A B 1of2";
      
      AccessTree tree = new AccessTree(policy1);       
      System.out.println("Tree: \n" + tree);   
      
      //check for satisfisibility
      List<String> attributes = new LinkedList<String>();
      attributes.add("manager");
      attributes.add("professor");
      attributes.add("A");
   
      System.out.println("List " + attributes + " satisfy tree? " + tree.checkSatisfy(attributes));   
      String filepln = "test/results/file.pdf";
      String fileenc = "test/results/file.pdf.encABE";
      String filedec = "test/results/file.pdf.encABE.dec.pdf";         
      
      byte datapln[] = Files.readBytesFromFile(filepln);
   
      String type = "A";
      int secLevel = 128;
   
   
      List list = encrypt(policy1,secLevel,type,datapln,1);
      
      Files.storeObject(list,fileenc, "Encryped DET-ABE data");
      
             //recover from file the CT and the encrypted data
      list = (LinkedList)Files.readObject(fileenc, "DET-ABE DECRYPTION MODULE: Reading encryped DET-ABE data");
   
      byte datadec[] = decrypt(list, attributes,1);    
      
      Files.storeBytesInFile(datadec, filedec);     
      
      //muestra los resultados,
      System.out.println("\nTime in seconds:\n sym-key-gen \t sym-enc \t abe-enc \t pack-det \t prv-dec-key \t abe-dec \t aes-dec");
      for(int j = 0; j < 7; j++)
         System.out.print(DETABECipher.timing[j] + ",\t");
      System.out.println();            
   
   }
  
   public static byte[] decrypt(List list, List attributes, int ITERS){
      double results[] = new double[ITERS];
      DETABECipher cipher = new DETABECipher();
      long startTime, endTime;
      byte[] result = null;
      
      for (int i = 0; i < ITERS; i++){
         startTime = System.nanoTime();  
         result = cipher.decrypt(list,attributes);   
         endTime = System.nanoTime();
         results[i] = (double)(endTime - startTime)/1000000000.0;   
      }
      System.out.println("Decrypt time: ");
      for(double d:results)
         System.out.println(d);
   
      return result;
   }
   
   
   public static List encrypt(String policy, int secLevel, String type, byte[] data, int ITERS){
      double results[] = new double[ITERS];
      DETABECipher cipher = new DETABECipher();
      long startTime, endTime;
      List list = null;
     
      for (int i = 0; i < ITERS; i++){
         startTime = System.nanoTime();
         list = cipher.encrypt(data, secLevel,type, policy);
         endTime = System.nanoTime();
         results[i] = (double)(endTime - startTime)/1000000000.0;
      }
   
      System.out.println("Encrypt time: ");
      for(double d:results)
         System.out.println(d);
   
      return list;
   }

    
}
