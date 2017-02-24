# ExpirationDate
This will implement an expiration date for your software. 
All the code is in Trial.c.

If compiled as a standalone application, this will produce an executable with 0 entry in the import table, that you can use to test the library.

To integrate the check in an existing project, just add Trial.c to your project and see the function mainCRTStartup to see how to use it.

* It uses a known trick to load libraried starting from PEB, so it won't add any dependencies.
* All used structures are re-defined inside Trial.c, so it completely self-contained and won't require any additional file during compilation.
* It's based on using some registry key to store the information and it include some checks to prevent basic tampering.
* **Please note that a skilled reverser will defeat this protection in around 10 minutes**. Don't use this for anything serious.
* Tested only on x86. Will require some (I guess minor) changes in order to work on x64.
