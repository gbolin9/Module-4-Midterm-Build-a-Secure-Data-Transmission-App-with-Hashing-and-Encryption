This program uphold confidentiality of the cia triad by utilizing a randomly generated private key to encrypt and decrypt text files or user inputs. It upholds integrity by generating a hash value for the message before it is encrypted
and one for the decrypted message and then compares the two. If the hash values are the same, it informs the user that it remains unchanged, but if it is not, it informs the user that the text has been changed.

The role of entropy and key generating is important to this program as it makes it virtually impossible for outside sources to crack the private key to prevent them from reading or changing messages sent to someone else. The randomness of 
the private key ensures that an individual cannot brute force the key as there are too many combinations for machines to try, granted the key is long enough to generate that many possible combinations. 
