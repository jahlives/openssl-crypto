#!/bin/bash
 
######################################################################################################
#                                                                                                    #
# crypto.sh                                                                                          #
# @version                 0.2 (RC2)                                                                 #
# @date                    20.02.2013                                                                #
# @author                  Tobi <tobster@brain-force.ch>                                             #
# @license                 Open Source (GPLv3)                                                       #
# @depends                 Bash                                                                      #
#                          OpenSSL                                                                   #
# @abstract                bash wrapper script for en/de-cryption with openssl                       #
#                          it takes at least an action argument and a path to file                   #
#                          then action will be performed on file.                                    #
# @example                 crypto.sh enc -f /path/to/file                                            #
# @arguments               see crypto.sh -h|--help for more information on available parameters      #
# @latest changes          * use cat and redirection instead of mv to preserve the original ACL      #
#                          * added static config variables for openssl binary and temp dir           #
#                                                                                                    #
######################################################################################################
 
#Define static vars
VERSION='0.2-rc2'
TMP_DIR=/tmp
OPENSSL=/usr/bin/openssl
 
 
#Define vars for commandline args
#only change from here on if you know what you do :-)
ACTION=''
FILE=''
CIPHER=''
KEY=''
FORCE=0
 
[ "x$*" = 'x' ] && $0 --help
# Generate file with cipher types supported by openssl
echo "$(openssl enc -h 2>&1 | grep 'Cipher Types' -A 100 | grep '-')" >$TMP_DIR/ciphers.txt
#cat /tmp/ciphers.txt && exit 0
 
#Read args from cli
while (( $# )) ; do
 case "$1" in
  'dec-write' | 'enc' | 'dec-disp' | 'dec' )
   ACTION="$1"
   shift
  ;;
  '-f' | '--file')
   shift
   FILE="$1"
   shift
  ;;
  '-d' | '--digest')
   shift
   DIGEST="$1"
   shift
  ;;
  '-c' | '--cipher')
   shift
   CIPHER="$1"
   shift
  ;;
  '-p' | '--pass')
   shift
   KEY="$1"
   shift
  ;;
  '-s' | '--show')
   echo ""
   echo "Supported cipher types:"
   cat $TMP_DIR/ciphers.txt
   echo "Cipher types above can be specified as -c or --cipher to $(basename $0)"
   echo "Leave out leading - when using as argument"
   exit 0
  ;;
  '--force')
   FORCE=1
   shift
  ;;
  '-h' | '--help')
   echo ""
   echo "**** WARNING: the enc parameter encrypts FILE and overwrites the unencrypted file with the crypted content ****"
   echo "Usage       : /path/to/$(basename $0)"
   echo "              dec-write|dec-disp|enc"
   echo "              -f|--file /path/to/FILE"
   echo "              [-d|--digest digest_to_use]"
   echo "              [-c|--cipher cipher_to_use]"
   echo "              [-p|--pass password]"
   echo "Order of arguments is not important!"
   echo "enc         : encrypts a file"
   echo "dec-disp    : decrypts a file to a temp file, display its unencrypted content and deletes the temp file"
   echo "              do NOT use this action on binary files! Makes only sense with text files"
   echo "dec-write   : decrypts a file and copy the unencrypted file back to its origin in the filesystem"
   echo "              use only this decryption action when handling binary files"
   echo "-f|--file   : file to perform ACTION on"
   echo "-c|--cipher : cipher to use for ACTION."
   echo "              See <openssl ciphers> command for ciphers supported on your system"
   echo "              blowfish is default if not specified as CIPHER argument"
   echo "-d|--digest : digest to use for hashing the password"
   echo "              and creating/verifying a checksum of the of the unencrypted content"
   echo "              currently md md5 sha1 sha256 sha224 sha512 md4 are supported"
   echo "              sha1 is default if not specified as DIGEST argument"
   echo "-p|--pass   : password to use for en/de-cryption. If not specified it will be asked by openssl"
   echo "-s|--show   : lists supported encryption types"
   echo "--force     : upon decryption the filecontent is verified with a hash"
   echo "              if there are discrepancies between the saved and the actual hash $(basename $0) exits with exit code 1"
   echo "              and the temporary files will be deleted."
   echo "              use this parameter to enforce decryption even if hashes are NOT matching"
   echo "-v|--version: shows version information"
   echo "-h|--help   : shows this help" 
   echo ""
   exit
  ;;
  '-v' | '--version')
   echo "$(basename $0) version $VERSION by <tobster@brain-force.ch"
   exit 0
  ;;
  *)
   echo "FATAL_ERROR: Unknown option $1"
   echo "             check $0 -h|--help"
   exit 1
  ;; 
 esac
done
 
#Checks for args given by user
[ -z "$FILE" ] && echo 'FATAL_ERROR: No FILE given' && exit 1
[[ "x$FILE" != x  && ! -f "$FILE" ]] && echo "FATAL_ERROR: Given FILE not found. Check $FILE" && exit 1
[ -z "$ACTION" ] && echo 'FATAL_ERROR: No ACTION given' && exit 1
[ -z "$CIPHER" ] && echo 'INFO: No CIPHER given <blowfish> will be used' && CIPHER='blowfish'
[[ "$CIPHER" != 'blowfish' && -z "$(cat $TMP_DIR/ciphers.txt | grep -i '\-'${CIPHER}' ')" ]] && echo "INFO: $CIPHER not found. <blowfish> will be used" && CIPHER='blowfish'
[ -z "$DIGEST" ] && echo 'INFO: No digest given. <sha256> will be used instead' && DIGEST='sha256'
if [ -n "$DIGEST" ] ; then
 case $DIGEST in
  md|md5|sha1|sha256|sha224|sha512|md4)
 ;;
 *)
  echo 'INFO: No or a non-valid DIGEST given <sha256> will be used' && DIGEST='sha256'
 ;;
 esac
fi
#Generate "random" string for temp FILENAME
FILENAME=$(basename "$FILE")
FILENAME=$(echo "$FILENAME" | md5sum | awk '{print $1}')
FILENAME=".${FILENAME:4:16}"
case $ACTION in
 'enc')
  $OPENSSL dgst -${DIGEST} -out "${FILE}.hash" "$FILE" > /dev/null 2>&1
  if [ "x$KEY" != 'x' ] ; then
   $OPENSSL enc -in "$FILE" -out "$TMP_DIR/$FILENAME" -e -md "${DIGEST}" -"${CIPHER}" -k "$KEY" > /dev/null 2>&1
  else
   $OPENSSL enc -in "$FILE" -out "$TMP_DIR/$FILENAME" -e -md "${DIGEST}" -"${CIPHER}" > /dev/null 2>&1
  fi
  if [ $? -eq 0 ] ; then
   cat "$TMP_DIR/$FILENAME" > "$FILE"
   rm $TMP_DIR/$FILENAME >/dev/null 2>&1
   echo "INFO: $FILE encrypted successfully"
   exit 0
  fi
  echo 'FATAL_ERROR: File could not be encrypted. Check your parameters!' && rm "$TMP_DIR/$FILENAME" > /dev/null 2>&1 && exit 1
  ;;
 'dec-disp' | 'dec')
  if [ "x$KEY" != 'x' ] ; then
   $OPENSSL enc -in "$FILE" -out "$TMP_DIR/$FILENAME" -d -md "${DIGEST}" -"${CIPHER}" -k "$KEY" > /dev/null 2>&1
  else
   $OPENSSL enc -in "$FILE" -out "$TMP_DIR/$FILENAME" -d -md "${DIGEST}" -"${CIPHER}" > /dev/null 2>&1
  fi
  [ $? -ne 0 ] && echo "FATAL_ERROR: Wrong password and/or wrong algorithm provided and/or $FILE is not encrypted at all!" && exit 1
  [ "$($OPENSSL dgst -$DIGEST $TMP_DIR/$FILENAME 2>/dev/null | awk -F'= ' '{print $2}')" = "$(cat ${FILE}.hash 2>/dev/null | awk -F'= ' '{print $2}')" ]
  if [ $? -ne 0 ] ; then
   echo "WARNING: File decrypted but hashes do NOT match. File is possibly compromised!!"
   if [ $FORCE -eq 0 ] ; then 
    rm $TMP_DIR/$FILENAME 2>/dev/null
    exit 1
   fi
  else
   echo "INFO: File decrypted and hashes DO match"
  fi
  [ -f "$TMP_DIR/$FILENAME" ] && cat "$TMP_DIR/$FILENAME" && rm "$TMP_DIR/$FILENAME" > /dev/null 2>&1 && exit 0
 ;;
 'dec-write')
  if [ "x$KEY" != 'x' ] ; then
   $OPENSSL enc -in "$FILE" -out "$TMP_DIR/$FILENAME" -d -md "${DIGEST}" -"${CIPHER}" -k "$KEY" 2>/dev/null
  else
   $OPENSSL enc -in "$FILE" -out "$TMP_DIR/$FILENAME" -d -md "${DIGEST}" -"${CIPHER}" 2>/dev/null
  fi
  [ $? -ne 0 ] && echo "FATAL_ERROR: Wrong password and/or wrong algorithm provided and/or $FILE is not encrypted at all!" && exit 1
  [ "$($OPENSSL dgst -$DIGEST /tmp/$FILENAME 2>/dev/null | awk -F'= ' '{print $2}')" = "$(cat ${FILE}.hash 2>/dev/null | awk -F'= ' '{print $2}')" ]
  if [ $? -ne 0 ] ; then
   echo "WARNING: File decrypted but hashes do NOT match. File is possibly compromised!!" 
   if [ $FORCE -eq 0 ] ; then
    rm $TMP_DIR/$FILENAME 2>/dev/null
    exit 1
   fi
  else
   echo "INFO: File decrypted and hashes DO match"
  fi
  if [ -f "$TMP_DIR/$FILENAME" ] ; then
   cat "$TMP_DIR/$FILENAME" > "$FILE"
   rm $TMP_DIR/$FILENAME >/dev/null 2>&1
   exit 0
  fi
 ;;
esac
