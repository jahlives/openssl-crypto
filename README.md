# openssl-crypto

Wrapper script for encryption/decryption of files via openssl command

**** WARNING: the enc parameter encrypts FILE and overwrites the unencrypted file with the crypted content ****  
**** Test it first with some testfiles!! ****

Usage       : /path/to/crypto.sh  
              dec-write|dec-disp|enc  
              -f|--file /path/to/FILE  
              [-d|--digest digest_to_use]  
              [-c|--cipher cipher_to_use]  
              [-p|--pass password]
              
Order of arguments is not important!
enc         : encrypts a file
dec-disp    : decrypts a file to a temp file, display its unencrypted content and deletes the temp file
              do NOT use this action on binary files! Makes only sense with text files
dec-write   : decrypts a file and copy the unencrypted file back to its origin in the filesystem
              use ONLY this decryption action when handling binary files
-f|--file   : file to perform ACTION on
-c|--cipher : cipher to use for ACTION.
              See <openssl ciphers> command for ciphers supported on your system
              blowfish is default if not specified as CIPHER argument
-d|--digest : digest to use for hashing the password
              and creating/verifying a checksum of the of the unencrypted content
              currently md md5 sha1 sha256 sha224 sha512 md4 are supported
              sha1 is default if not specified as DIGEST argument
-p|--pass   : password to use for en/de-cryption. If not specified it will be asked by openssl
-s|--show   : lists supported encryption types
--force     : upon decryption the filecontent is verified with a hash
              if there are discrepancies between the saved and the actual hash crypto.sh exits with exit code 1
              and the temporary files will be deleted.
              use this parameter to enforce decryption even if hashes are NOT matching
-v|--version: shows version information
-h|--help   : shows this help
