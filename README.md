# DET-ABE-API

 This software is part of the --DET-ABE API--, a Java library developed as part of the SCABE project (Secure Storage and Sharing 
 of data in the Cloud by using  Attribute based encryption).
 The DET-ABE library is free software. This library is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either expressed or implied.
 
 Copyright (c) Miguel Morales-Sandoval 
 morales.sandoval.miguel@gmail.com


Before using this software:

1. You must have installed jPBC: http://gas.dia.unisa.it/projects/jpbc/#.Ved6Qfl_NBc
There is an inconsistency when creating the pairing using curve parameters stored in a file. The current version of jPBC produce this error so you can use the version of jPBC .jar files used to write and test the DET-ABE.  You can find these files in this repository.
2. You must update your Java distribution with the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html. This is in order to use encryption security levels of 128, 192, and 256 bits. 
3. This is a standalone implementation of DET-ABE, all code run on the same machine
4. Parameter and keys are available for use in the "params" and "bsw" folders. 
5. In this vesion, attributes as text string are supported (not duplicated)
6. Source code for testing AES, CP-ABE, and DET-ABE are available in folder "test/bswabe/"
7. More info about DET-ABE is found here:
http://link.springer.com/chapter/10.1007%2F978-3-319-24018-3_7


If you find useful this code, please cite our article:

@INPROCEEDINGS{Morales-Sandoval2015,
author="Morales-Sandoval, Miguel
and Diaz-Perez, Arturo",
editor="Akram, Naeem Raja
and Jajodia, Sushil",
title="DET-ABE: A Java API for Data Confidentiality and Fine-Grained Access Control from Attribute Based Encryption",
bookTitle="Information Security Theory and Practice: 9th IFIP WG 11.2 International Conference, WISTP 2015",
year="2015",
publisher="Springer International Publishing",
address=" Heraklion, Crete, Greece",
pages="104--119",
isbn="978-3-319-24018-3",
doi="10.1007/978-3-319-24018-3_7",
url="http://dx.doi.org/10.1007/978-3-319-24018-3_7"
}



