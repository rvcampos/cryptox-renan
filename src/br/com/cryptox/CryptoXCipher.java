package br.com.cryptox;

/*
 * =============================================================================
 * Copyright (c) 2012 Renan Vizza Campos. All rights reserved. Just Kidding.
 * LICENSE: Apache 2.0
 * Use como quiser, se for melhorar me avise!!
 * Feel free to use this class/project, if you enhance it, please, contact me!
 * 
 * contact: renanvcampos@gmail.com
 */
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
 * Classe que criptografa e descriptografa grande maioria dos algoritmos CIPHER: <b><br>
 * Blowfish<br>
 * DES<br>
 * DESede<br>
 * PBEWithMD5AndDES<br>
 * PBEWithMD5AndTripleDES<br>
 * TripleDES<br>
 * RC2<br>
 * RC4</b> <br>
 * Ver mais em: <a
 * href=http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html>
 * Providers</a>
 * 
 * @author renan.campos
 * 
 */
public class CryptoXCipher {

    private int                    cifraCesar = 16;
    private Charset                charset;
    private Cipher                 encrypt;
    private Cipher                 decrypt;
    private AlgorithmParameterSpec paramSpec;

    /**
     * Enumerador contendo dois casos: <br>
     * {@link #ENCRYPT}<br>
     * {@link #DECRYPT}
     * 
     * @author renan.campos
     * 
     */
    private static enum Mode {
        /**
         * Criptografar
         */
        ENCRYPT,
        /**
         * Descriptografar
         */
        DECRYPT;
    }

    private static Logger log = LoggerFactory.getLogger(CryptoXCipher.class);

    /**
     * Gera chave e os parametros para um determinado algoritmo.
     * 
     * @param algoritmo
     * @param sal
     * @return {@link SecretKey}
     * @throws NoSuchAlgorithmException
     *             Algorismo não existente
     * @throws InvalidKeySpecException
     * @throws InvalidParameterSpecException
     */
    private SecretKey getKey(String algoritmo, String sal)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            InvalidParameterSpecException {
        KeySpec keySpec;
        if (algoritmo.indexOf("PBE") != -1) {
            byte[] salt = { (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
                    (byte) 0x56, (byte) 0x34, (byte) 0xE3, (byte) 0x03 };
            int iteracoes = 16;
            keySpec = new PBEKeySpec(sal.toCharArray(), salt, iteracoes);
            paramSpec = new PBEParameterSpec(salt, iteracoes);
            return SecretKeyFactory.getInstance(algoritmo).generateSecret(
                    keySpec);
        }
        keySpec = new SecretKeySpec(sal.getBytes(charset), algoritmo);
        return (SecretKey) keySpec;
    }

    /**
     * Construtor private
     * 
     * @param sal
     *            Palavra chave
     * @param algoritmo
     *            Algoritmo a ser utilizado
     * @param cifraCesar
     *            em quantos numeros os caracteres serão trocados
     * @param charset
     * @throws IllegalArgumentException
     */
    private CryptoXCipher(String sal, String algoritmo, int cifraCesar,
            Charset charset) throws IllegalArgumentException {
        try {
            this.charset = charset;
            SecretKey chave = getKey(algoritmo, sal);
            this.encrypt = Cipher.getInstance(algoritmo);
            this.decrypt = Cipher.getInstance(algoritmo);
            this.encrypt.init(Cipher.ENCRYPT_MODE, chave, paramSpec);
            this.decrypt.init(Cipher.DECRYPT_MODE, chave, paramSpec);
            this.cifraCesar = cifraCesar;
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Método getInstance com charset padrão UTF-8
     * 
     * @param sal
     *            chave para criar salt (sal)
     * @param algoritmo
     *            algoritmo para criptografia
     * @param val
     *            valor para cifra de cesar
     * @return instancia de {@link CryptoXCipher}
     */
    public static CryptoXCipher getInstance(String sal, String algoritmo,
            int val) {
        return new CryptoXCipher(sal, algoritmo, val, Charset.forName("UTF-8"));
    }

    /**
     * Método getInstance com charset definido pelo usuário
     * 
     * @param sal
     *            chave para criar salt (sal)
     * @param algoritmo
     *            algoritmo para criptografia
     * @param val
     *            valor para cifra de cesar
     * @param cs
     *            Charset
     * @return
     */
    public static CryptoXCipher getInstance(String sal, String algoritmo,
            int val, Charset cs) {
        return new CryptoXCipher(sal, algoritmo, val, cs);
    }

    /**
     * Criptografa uma String
     * 
     * @param str
     *            - String a ser criptografada
     * @return String criptografada
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String crypt(String str) throws UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        str = this.cifraCesar(str, Mode.ENCRYPT);
        byte[] cc = str.getBytes(this.charset);
        byte[] enc = this.encrypt.doFinal(cc);
        return new String(Base64.encodeBase64(enc));
    }

    /**
     * Aplica o <a href=http://pt.wikipedia.org/wiki/Cifra_de_César>conceito Cifra de cesar</a> para
     * a String, dependendo de seu modo
     * 
     * @param str
     *            - String a ser aplicada
     * @param modo
     *            {@link Mode}
     * @return String alterada
     */
    private String cifraCesar(String str, Mode modo) {
        char[] newStr = new char[str.length()];
        int i = 0;
        if (modo.equals(Mode.ENCRYPT)) {
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
     * Decriptografa uma string criptografada
     * 
     * @param str
     *            String criptografada
     * @return String descriptografada
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decrypt(String str) throws UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        byte[] dec = Base64.decodeBase64(str.getBytes(this.charset));
        byte[] cc = this.decrypt.doFinal(dec);
        return this.cifraCesar(new String(cc, this.charset), Mode.DECRYPT);
    }
}
