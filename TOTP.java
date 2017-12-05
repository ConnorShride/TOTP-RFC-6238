 /******************************************************************************
  * Modified example implementation for time-based one-time password in RFC 6238
  *
  * Takes a String command line argument as the shared secret, to be encoded in
  * ASCII, and allows for a 10 hex-digit output rather than 8. Outputs TOTP for
  * the current time with hash functions SHA1, SHA256, and SHA512
  *
  * Last Modified By: Connor Shride, 12/4/17
  *
  * COPYRIGHT DISCLAIMER
  *
  * Copyright (c) 2011 IETF Trust and the persons identified as
  * authors of the code. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, is permitted pursuant to, and subject to the license terms
  * contained in, the Simplified BSD License set forth in Section 4.c of the
  * IETF Trust's Legal Provisions Relating to IETF Documents
  * (http://trustee.ietf.org/license-info).
  *****************************************************************************/

 import java.lang.reflect.UndeclaredThrowableException;
 import java.security.GeneralSecurityException;
 import java.text.DateFormat;
 import java.text.SimpleDateFormat;
 import java.util.Date;
 import javax.crypto.Mac;
 import javax.crypto.spec.SecretKeySpec;
 import java.math.BigInteger;
 import java.util.TimeZone;
 import java.nio.charset.StandardCharsets;

 /******************************************************************************
  * This is an example implementation of the OATH TOTP algorithm.
  * Visit www.openauthentication.org for more information.
  *
  * @author Johan Rydell, PortWise, Inc.
  *****************************************************************************/
 public class TOTP {

     private static final long[] DIGITS_POWER
             // 0 1  2   3    4     5      6       7        8...
             = {1,10,100,1000,10000,100000,1000000,10000000,100000000,
             1000000000,
             10000000000L };

     private TOTP() {}

     /**************************************************************************
      * This method uses the JCE to provide the crypto algorithm. HMAC computes
      * a Hashed Message Authentication Code with the crypto hash algorithm as a
      * parameter.
      *
      * @param crypto the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
      * @param keyBytes: the bytes to use for the HMAC key
      * @param text the message or text to be authenticated
      **************************************************************************/
     private static byte[] hmac_sha(String crypto, byte[] keyBytes,
                                    byte[] text) {
         try {

             Mac hmac = Mac.getInstance(crypto);
             SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
             hmac.init(macKey);
             return hmac.doFinal(text);

         } catch (GeneralSecurityException gse) {

             throw new UndeclaredThrowableException(gse);
         }
     }

     /**************************************************************************
      * This method converts a HEX string to Byte[]
      *
      * @param hex the HEX string
      * @return a byte array
      *************************************************************************/
     private static byte[] hexStr2Bytes(String hex) {

         // Adding one byte to get the right conversion
         // Values starting with "0" can be converted
         byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

         // Copy all the REAL bytes, not the "first"
         byte[] ret = new byte[bArray.length - 1];

         for (int i = 0; i < ret.length; i++) {
             ret[i] = bArray[i + 1];
         }

         return ret;
     }

     /**************************************************************************
      * This method generates a TOTP
      *
      * @param key the shared secret
      * @param time a value that reflects a time (T steps)
      * @param returnDigits number of digits to return
      * @param crypto the crypto function to use
      * @return a numeric String in base 10 that includes the specified number
      * of digits
      *************************************************************************/
     public static String generateTOTP(String key, String time,
                                       String returnDigits, String crypto) {

         int codeDigits = Integer.decode(returnDigits);

         // Pad the time with zeroes
         // First 8 bytes are for the movingFactor
         // Compliant with base RFC 4226 (HOTP)
         while (time.length() < 16 ) {
             time = "0" + time;
         }

         byte[] msgBytes = hexStr2Bytes(time);
         byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
         byte[] hashBytes = hmac_sha(crypto, keyBytes, msgBytes);

         // put selected bytes into result int
         int offset = hashBytes[hashBytes.length - 1] & 0xf;

         int binary =
             ((hashBytes[offset] & 0x7f) << 24) |
             ((hashBytes[offset + 1] & 0xff) << 16) |
             ((hashBytes[offset + 2] & 0xff) << 8) |
             (hashBytes[offset + 3] & 0xff);

         long otp = (long)binary % DIGITS_POWER[codeDigits];

         String result = Long.toString(otp);

         // pad result prepending zeros
         while (result.length() < codeDigits) {
             result = "0" + result;
         }

         return result;
     }

     /**************************************************************************
      * Displays TOTPs for the current time and given shared secret string using
      * SHA1, SHA256, and SHA512
      *
      * @param args shared secret and number of output digits
      *************************************************************************/
     public static void main(String[] args) {

         // get string shared secret and number of output digits
         String key = args[0];
         String digits = args[1];

         // default start time of zero and steps of 30 seconds
         long T0 = 0;
         long X = 30;

         DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
         df.setTimeZone(TimeZone.getTimeZone("UTC"));
         long time = System.currentTimeMillis() / 1000;

         // print table header (timestamp, timestamp UTC, T, TOTP, hash function
         System.out.println("+---------------+--------------------+----------" +
                 "----------+---------------+----------+");
         System.out.printf("|%-15s|%-20s|%-20s|%-15s|%-10s|\n", "Time(sec)",
                 "Time (UTC format)", "Value of T(Hex)", "TOTP", "Mode");
         System.out.println("+---------------+--------------------+----------" +
                 "----------+---------------+----------+");

         long T = (time - T0)/X;
         String steps = Long.toHexString(T).toUpperCase();
         String fmtTime = String.format("%1$-11s", time);
         String utcTime = df.format(new Date(time*1000));

         // SHA1 row
         System.out.printf("|%-15s|%-20s|%-20s", fmtTime, utcTime, steps);
         System.out.printf("|%-15s|%-10s|\n", generateTOTP(key, steps, digits,
                 "HmacSHA1"), "SHA1");

         // SHA256 row
         System.out.printf("|%-15s|%-20s|%-20s", fmtTime, utcTime, steps);
         System.out.printf("|%-15s|%-10s|\n", generateTOTP(key, steps, digits,
                 "HmacSHA256"), "SHA256");

         // SHA512 row
         System.out.printf("|%-15s|%-20s|%-20s", fmtTime, utcTime, steps);
         System.out.printf("|%-15s|%-10s|\n", generateTOTP(key, steps, digits,
                 "HmacSHA512"), "SHA512");

         System.out.println("+---------------+--------------------+---------" +
                 "-----------+---------------+----------+");
     }
 }
