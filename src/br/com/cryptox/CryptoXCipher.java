package br.com.cryptox;


import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.AlgorithmParameterGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Blowfish
 * DES
 * DESede
 * PBEWithMD5AndDES
 * PBEWithMD5AndTripleDES
 * TripleDES
 * @author renan.campos
 *
 */
public class CryptoXCipher {

    private int     cifraCesar = 16;
    private Charset charset;
    private Cipher  encrypt;
    private Cipher  decrypt;
    private AlgorithmParameterSpec paramSpec;
    
    private static enum Mode {
        ENCRYPT, DECRYPT;
    }
    
    private static Logger log = LoggerFactory.getLogger(CryptoXCipher.class);

    /**
     * Gera chave
     * @param algoritmo
     * @param sal
     * @return
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeySpecException 
     * @throws InvalidParameterSpecException 
     */
    private SecretKey getKey(String algoritmo, String sal) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException
    {
        KeySpec keySpec;
        if(algoritmo.indexOf("RC") != -1)
        {
            if(sal.length() < 5 || sal.length() > 16)
            {
                log.info("RC Key size should be between 5 AND 16");
            }
        }
        else if(algoritmo.indexOf("PBE") != -1)
        {
            byte[] salt = { (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x34, (byte) 0xE3,
                    (byte) 0x03 };
            int iteracoes = 16;
            keySpec = new PBEKeySpec(sal.toCharArray(), salt, iteracoes);
            paramSpec = new PBEParameterSpec(salt, iteracoes);
            return SecretKeyFactory.getInstance(algoritmo).generateSecret(keySpec);
        }
        keySpec = new SecretKeySpec(sal.getBytes(charset), algoritmo);
        return (SecretKey) keySpec;
    }
    
    private CryptoXCipher (String sal, String algoritmo, int cifraCesar, Charset charset) throws IllegalArgumentException {
        try {
            this.charset = charset;
            SecretKey chave = getKey(algoritmo, sal);
            this.encrypt = Cipher.getInstance(algoritmo);
            this.decrypt = Cipher.getInstance(algoritmo);
            this.encrypt.init(Cipher.ENCRYPT_MODE, chave, paramSpec);
            this.decrypt.init(Cipher.DECRYPT_MODE, chave, paramSpec);
            this.cifraCesar = cifraCesar;
        }
        catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * @param sal
     *            - chave para criar salt (sal)
     * @param algoritmo
     *            algoritmo para criptografia
     * @param val
     * @return
     */
    public static CryptoXCipher getInstance(String sal, String algoritmo, int val) {
        return new CryptoXCipher(sal, algoritmo, val, Charset.forName("UTF-8"));
    }

    public static CryptoXCipher getInstance(String sal, String algoritmo, int val, Charset cs) {
        return new CryptoXCipher(sal, algoritmo, val, cs);
    }

    /**
     * Criptografa uma String
     * @param str - String a ser criptografada
     * @return
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String crypt(String str) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        str = this.cifraCesar(str, Mode.ENCRYPT);
        byte[] cc = str.getBytes(this.charset);
        byte[] enc = this.encrypt.doFinal(cc);
        return new String(Base64.encodeBase64(enc));
    }

    /**
     * Aplica o conceito Cifra de cesar para a String, dependendo de seu modo
     * 
     * @param str
     *            - String a ser aplicada
     * @param status
     *            {@link Mode}
     * @return
     *         String alterada
     */
    private String cifraCesar(String str, Mode status) {
        char[] newStr = new char[str.length()];
        int i = 0;
        if (status.equals(Mode.ENCRYPT)) {
            for (char c : str.toCharArray()) {
                newStr[i] = (char) (c + this.cifraCesar);
                i++;
            }
        } else {
            for (char c : str.toCharArray()) {
                newStr[i] = (char) (c - this.cifraCesar);
                i++;
            }
        }

        return String.copyValueOf(newStr);
    }

    /**
     * 
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decrypt(String str) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] dec = Base64.decodeBase64(str.getBytes(this.charset));
        byte[] cc = this.decrypt.doFinal(dec);
        return this.cifraCesar(new String(cc, this.charset), Mode.DECRYPT);
    }
    
    public static void main(String[] args) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        String key = "java";
        CryptoXCipher j = CryptoXCipher.getInstance(key, "ARCFOUR", 10);
        String x = j.crypt("teste");
        System.out.println(x);
        System.out.println(j.decrypt(x));
    }
}
