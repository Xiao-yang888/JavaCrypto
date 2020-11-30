package com.raunda.c190604;

import sun.awt.AWTAccessor;
import sun.security.krb5.internal.crypto.Des;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Demo {
    String key = "c1906041";//设定的字符串秘钥
    String data = "小手一撮，又是一个人过冬";

    static String str = "憨憨华";
    /**
     * 程序的主函数
     * @param args
     */
    public static void main(String[] args) {
        System.out.println("憨憨周华华");
        System.out.println(str);
//        System.out.println(data);
        Demo demo = new Demo();
        System.out.println(demo.key);
        System.out.println(demo.data);
        //加密
        byte[] cipherText = demo.encrypt(demo.key.getBytes(), demo.data.getBytes());
        System.out.println(cipherText);//返回地址


    }

    //1，java中，属性和方法被包裹在class中，但是并不能直接调用属性和方法
    //2，通过new关键字实例化一个类的对象,然后通过对象才能调用
    //3，static是java中的一个修饰符，被该修饰符修饰的可以 是方法或属性
    //4，如果一个方法被static修饰，则不需要new对象实例化，可直接调用

    /**
     * DES算法的封装
     * @param key des算法的秘钥
     * @param data 要操作的数据，明文或者密文
     * @param mode des算法的操作模式
     * @return byte数组，加密后的密文或者是解密后的明文
     */
    public byte[] desOperation(byte[] key, byte[] data, int mode) {
        try {
            DESKeySpec spec = new DESKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = factory.generateSecret(spec);
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(mode, secretKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
    //函数一：加密
    public byte[] encrypt(byte[] key, byte[] data) {
        //面向百度编程
        try {
            //生成DES的秘钥
            DESKeySpec desKeySpec = new DESKeySpec(key);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
            //执行cipher加密动作的实例
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            //执行最后的加密
            return cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.out.println("出现异常");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } finally {
            //最终的逻辑处理

        }


        //返回值语句
        return null;//代表空，没有
    }

    //函数二：解密
    public byte[] decrypt(byte[] cipherText, byte[] key) {
        try {
            DESKeySpec spec = new DESKeySpec(key);//des秘钥的初始化
            //标准的加密算法工厂，DES算法
            SecretKeyFactory factory = SecretKeyFactory.getInstance("Des");
            SecretKey secretKey = factory.generateSecret(spec);
            //执行解密 cipher
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(cipherText);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return  null;
    }
}

