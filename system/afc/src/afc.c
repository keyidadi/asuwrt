// PKCS7Sign.cpp : Defines the entry point for the console application.  
//  
  
#include "stdafx.h"  
  
#include <iostream>      
#include <openssl/md5.h>    
  
#include <stdio.h>  
#include <openssl/rsa.h>  
#include <openssl/evp.h>  
#include <openssl/objects.h>  
#include <openssl/x509.h>  
#include <openssl/err.h>  
#include <openssl/pem.h>  
#include <openssl/pkcs12.h>   
#include <openssl/ssl.h>  
  
#pragma comment(lib, "libeay32.lib")     
#pragma comment(lib, "ssleay32.lib")     
  
/* 
PKCS7Sign.cpp 
Auth��Kagula 
���ܣ�����OpenSSLʵ������ǩ���������̣����� 
������VS2008+SP1,OpenSSL1.0.1 
*/  
  
/* 
���ܣ���ʼ��OpenSSL 
*/  
void InitOpenSSL()  
{  
    CRYPTO_malloc_init();  
    /* Just load the crypto library error strings, 
    * SSL_load_error_strings() loads the crypto AND the SSL ones */  
    /* SSL_load_error_strings();*/  
    ERR_load_crypto_strings();  
    OpenSSL_add_all_algorithms();   
    OpenSSL_add_all_ciphers();  
    OpenSSL_add_all_digests();  
}  
  
/* 
���ܣ���length���ȵ�inputָ����ڴ�����BASE64���� 
��ڣ� 
const void *input           ָ���ڴ���ָ�� 
int length                  �ڴ�����Ч���� 
���أ� 
char *                      �����ַ���ָ�룬ʹ����Ϻ󣬱�����free�����ͷš� 
*/  
char *base64(const void *input, int length)  
{  
  BIO *bmem, *b64;  
  BUF_MEM *bptr;  
  
  b64 = BIO_new(BIO_f_base64());  
  bmem = BIO_new(BIO_s_mem());  
  b64 = BIO_push(b64, bmem);  
  BIO_write(b64, input, length);  
  BIO_flush(b64);  
  BIO_get_mem_ptr(b64, &bptr);  
  
  char *buff = (char *)malloc(bptr->length);  
  memcpy(buff, bptr->data, bptr->length-1);  
  buff[bptr->length-1] = 0;  
  
  BIO_free_all(b64);  
  
  return buff;  
}  
  
/* 
���ܣ�base64���� 
��ڣ� 
char *inputBase64  BASE64�����ǩ�� 
void *retBuf       �����С 
���أ� 
void *retBuf       ��������ݴ��������ڴ��� 
int *retBufLen     ��������ݵĳ��� 
*/  
void *decodeBase64(char *inputBase64, void *retBuf,int *retBufLen)  
{  
    BIO *b64, *bmem;  
      
    b64 = BIO_new(BIO_f_base64());  
    bmem = BIO_new_mem_buf(inputBase64, strlen((const char *)inputBase64));  
    bmem = BIO_push(b64, bmem);   
    int err=0;  
    int i=0;  
    do{  
        err = BIO_read(bmem, (void *)( (char *)retBuf+i++), 1);  
    }while( err==1 && i<*retBufLen );  
    BIO_free_all(bmem);  
  
    *retBufLen = --i;  
      
    return retBuf;  
}  
  
  
  
/* 
���ܣ������Ľ���ǩ�� 
��ڣ� 
char*certFile    ֤�飨���磺xxx.pfx�� 
char* pwd        ֤������� 
char* plainText  ��ǩ�����ַ��� 
int flag         ǩ����ʽ 
���ڣ� 
char *           ǩ�����������BASE64��ʽ���� 
                 ʹ����Ϻ󣬱�����free�����ͷš� 
*/  
  
char * PKCS7_GetSign(char*certFile,char* pwd, char* plainText,int flag)  
{  
    //ȡPKCS12����  
    FILE* fp;  
    if (!(fp = fopen(certFile, "rb")))   
    {   
        fprintf(stderr, "Error opening file %s\n", certFile);          
        return NULL;       
    }      
    PKCS12 *p12= d2i_PKCS12_fp(fp, NULL);    
    fclose (fp);      
    if (!p12) {        
        fprintf(stderr, "Error reading PKCS#12 file\n");     
        ERR_print_errors_fp(stderr);    
        return NULL;     
    }   
       
    //ȡpkey����X509�C�����C���  
    EVP_PKEY *pkey=NULL;       
    X509 *x509=NULL;  
    STACK_OF(X509) *ca = NULL;  
    if (!PKCS12_parse(p12, pwd, &pkey, &x509, &ca)) {           
        fprintf(stderr, "Error parsing PKCS#12 file\n");         
        ERR_print_errors_fp(stderr);  
        return NULL;  
    }   
    PKCS12_free(p12);  
  
    //�����D��BIO����  
    //��vc++���簲ȫ��̷�����14��-openssl bio��� ��   http://www.2cto.com/kf/201112/115018.html  
    BIO *bio = BIO_new(BIO_s_mem());    
    BIO_puts(bio,plainText);  
  
    //���ֺ���  
    //PKCS7_NOCHAIN:ǩ���в�����֤����������������ΪNULLֵ�Ļ����ɲ������FLAG���  
    //PKCS7_NOSMIMECAP:ǩ������Ҫ֧��SMIME  
    PKCS7* pkcs7 = PKCS7_sign(x509,pkey, ca,bio, flag);  
    if(pkcs7==NULL)  
    {  
        ERR_print_errors_fp(stderr);  
        return NULL;  
    }  
  
    //�������ֱ��룬һ����ASN1����һ����DER���롣  
    //ȡ��������(DER��ʽ)  
    //opensslѧϰ�ʼ�֮pkcs7-data�������͵ı������  
    //http://ipedo.i.sohu.com/blog/view/114822358.htm  
    //��ڣ�pkcs7����  
    //����:der����  
    unsigned char *der;  
    unsigned char *derTmp;  
    unsigned long derlen;  
    derlen = i2d_PKCS7(pkcs7,NULL);  
    der = (unsigned char *) malloc(derlen);  
    memset(der,0,derlen);  
    derTmp = der;  
    i2d_PKCS7(pkcs7,&derTmp);  
  
    //DERתBASE64  
    return base64(der,derlen);  
}  
  
/* 
���ܣ���֤ǩ�� 
��ڣ� 
char*certFile    ֤�飨���ף� 
char* plainText  ���� 
char* cipherText ǩ�� 
���ڣ� 
bool true  ǩ����֤�ɹ� 
bool false ��֤ʧ�� 
*/  
bool PKCS7_VerifySign(char*certFile,char* plainText,char* cipherText )  
{  
    /* Get X509 */  
    FILE* fp = fopen (certFile, "r");  
    if (fp == NULL)   
        return false;  
    X509* x509 = PEM_read_X509(fp, NULL, NULL, NULL);  
    fclose (fp);  
  
    if (x509 == NULL) {  
        ERR_print_errors_fp (stderr);  
        return false;  
    }  
  
    //BASE64����  
    unsigned char *retBuf[1024*8];  
    int retBufLen = sizeof(retBuf);  
    memset(retBuf,0,sizeof(retBuf));  
    decodeBase64(cipherText,(void *)retBuf,&retBufLen);  
  
    //��ǩ����ȡPKCS7����  
    BIO* vin = BIO_new_mem_buf(retBuf,retBufLen);  
    PKCS7 *p7 = d2i_PKCS7_bio(vin,NULL);  
  
  
    //ȡSTACK_OF(X509)����  
    STACK_OF(X509) *stack=sk_X509_new_null();//X509_STORE_new()  
    sk_X509_push(stack,x509);  
  
  
    //��������תΪBIO  
    BIO *bio = BIO_new(BIO_s_mem());    
    BIO_puts(bio,plainText);  
  
    //��֤ǩ��  
    int err = PKCS7_verify(p7, stack, NULL,bio, NULL, PKCS7_NOVERIFY);  
  
    if (err != 1) {  
        ERR_print_errors_fp (stderr);  
        return false;  
    }  
  
    return true;  
}  
  
int _tmain(int argc, _TCHAR* argv[])  
{  
    char certFile[] = "demo.pfx";  
    char plainText[]= "Hello,World!";  
  
    InitOpenSSL();  
  
    //���ֺ���  
    //PKCS7_NOCHAIN:ǩ���в�����֤����  
    //PKCS7_NOSMIMECAP:ǩ������Ҫ֧��SMIME  
    char * cipherText = PKCS7_GetSign(certFile,"11111111",plainText,PKCS7_DETACHED|PKCS7_NOSMIMECAP);  
  
    //��ӡ��BASE64������ǩ��  
    std::cout<<cipherText<<std::endl;  
  
    //��֤����ǩ��  
    if(PKCS7_VerifySign("BOC-CA.cer",plainText,cipherText))  
        std::cout<<"Verify OK!"<<std::endl;  
    else  
        std::cout<<"Verify Failed!"<<std::endl;  
      
    //�ͷ�ǩ���ַ��������棩  
    free(cipherText);  
  
    //���������ַ�����  
    getchar();  
    return 0;  
}  
  