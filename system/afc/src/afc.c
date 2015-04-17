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
Auth：Kagula 
功能：调用OpenSSL实现数字签名功能例程（二） 
环境：VS2008+SP1,OpenSSL1.0.1 
*/  
  
/* 
功能：初始化OpenSSL 
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
功能：对length长度的input指向的内存块进行BASE64编码 
入口： 
const void *input           指向内存块的指针 
int length                  内存块的有效长度 
返回： 
char *                      返回字符串指针，使用完毕后，必须用free函数释放。 
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
功能：base64解码 
入口： 
char *inputBase64  BASE64编码的签名 
void *retBuf       缓存大小 
返回： 
void *retBuf       解码后数据存放在这块内存中 
int *retBufLen     解码后数据的长度 
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
功能：对明文进行签名 
入口： 
char*certFile    证书（例如：xxx.pfx） 
char* pwd        证书的密码 
char* plainText  待签名的字符串 
int flag         签名方式 
出口： 
char *           签名后的数据以BASE64形式返回 
                 使用完毕后，必须用free函数释放。 
*/  
  
char * PKCS7_GetSign(char*certFile,char* pwd, char* plainText,int flag)  
{  
    //取PKCS12對象  
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
       
    //取pkey對象、X509證書、證書鏈  
    EVP_PKEY *pkey=NULL;       
    X509 *x509=NULL;  
    STACK_OF(X509) *ca = NULL;  
    if (!PKCS12_parse(p12, pwd, &pkey, &x509, &ca)) {           
        fprintf(stderr, "Error parsing PKCS#12 file\n");         
        ERR_print_errors_fp(stderr);  
        return NULL;  
    }   
    PKCS12_free(p12);  
  
    //明文轉為BIO對象  
    //《vc++网络安全编程范例（14）-openssl bio编程 》   http://www.2cto.com/kf/201112/115018.html  
    BIO *bio = BIO_new(BIO_s_mem());    
    BIO_puts(bio,plainText);  
  
    //數字簽名  
    //PKCS7_NOCHAIN:签名中不包含证书链，第三个参数为NULL值的话，可不加这个FLAG标记  
    //PKCS7_NOSMIMECAP:签名不需要支持SMIME  
    PKCS7* pkcs7 = PKCS7_sign(x509,pkey, ca,bio, flag);  
    if(pkcs7==NULL)  
    {  
        ERR_print_errors_fp(stderr);  
        return NULL;  
    }  
  
    //共有两种编码，一种是ASN1，另一种是DER编码。  
    //取數據簽名(DER格式)  
    //openssl学习笔记之pkcs7-data内容类型的编码解码  
    //http://ipedo.i.sohu.com/blog/view/114822358.htm  
    //入口：pkcs7对象  
    //出口:der对象  
    unsigned char *der;  
    unsigned char *derTmp;  
    unsigned long derlen;  
    derlen = i2d_PKCS7(pkcs7,NULL);  
    der = (unsigned char *) malloc(derlen);  
    memset(der,0,derlen);  
    derTmp = der;  
    i2d_PKCS7(pkcs7,&derTmp);  
  
    //DER转BASE64  
    return base64(der,derlen);  
}  
  
/* 
功能：验证签名 
入口： 
char*certFile    证书（含匙） 
char* plainText  明文 
char* cipherText 签名 
出口： 
bool true  签名验证成功 
bool false 验证失败 
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
  
    //BASE64解码  
    unsigned char *retBuf[1024*8];  
    int retBufLen = sizeof(retBuf);  
    memset(retBuf,0,sizeof(retBuf));  
    decodeBase64(cipherText,(void *)retBuf,&retBufLen);  
  
    //从签名中取PKCS7对象  
    BIO* vin = BIO_new_mem_buf(retBuf,retBufLen);  
    PKCS7 *p7 = d2i_PKCS7_bio(vin,NULL);  
  
  
    //取STACK_OF(X509)对象  
    STACK_OF(X509) *stack=sk_X509_new_null();//X509_STORE_new()  
    sk_X509_push(stack,x509);  
  
  
    //明码数据转为BIO  
    BIO *bio = BIO_new(BIO_s_mem());    
    BIO_puts(bio,plainText);  
  
    //验证签名  
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
  
    //數字簽名  
    //PKCS7_NOCHAIN:签名中不包含证书链  
    //PKCS7_NOSMIMECAP:签名不需要支持SMIME  
    char * cipherText = PKCS7_GetSign(certFile,"11111111",plainText,PKCS7_DETACHED|PKCS7_NOSMIMECAP);  
  
    //打印出BASE64编码后的签名  
    std::cout<<cipherText<<std::endl;  
  
    //验证数字签名  
    if(PKCS7_VerifySign("BOC-CA.cer",plainText,cipherText))  
        std::cout<<"Verify OK!"<<std::endl;  
    else  
        std::cout<<"Verify Failed!"<<std::endl;  
      
    //释放签名字符串（缓存）  
    free(cipherText);  
  
    //输入任意字符继续  
    getchar();  
    return 0;  
}  
  