#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "omp.h"

int success = 0;

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv ){

    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintexts;
    int len;
    int plaintext_len;
    
    unsigned char* plaintext = malloc(ciphertext_len);
    bzero(plaintext,ciphertext_len);

    /* Create and initialise the context */
  
    if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleOpenSSLErrors();

  
    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleOpenSSLErrors();
   
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    
    // return 1 if decryption successful, otherwise 0
    if(1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        success = 1;
    plaintext_len += len;

   
    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //delete [] plaintext;
    return plaintext;
}


size_t calcDecodeLength(char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Base64Decode( char* b64message, unsigned char** buffer, size_t* length) {

    
    BIO *bio, *b64;  // A BIO is an I/O strean abstraction

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
    //initialisatio of key and iv with 0
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}


int checkPlaintext(char* plaintext, char* result){

    int length = 10; // we just check the first then characters
    return strncmp(plaintext, result, length);

}

int main (void)
{
    
    // pasword Mar10
    // it took 213 seconds to work out this password
    //char* ciphertext_base64 = (char*) "U2FsdGVkX1/x92BdYvopo2z2ZE5u68vEA+00lPDdMF0rr7SGaWdB3+INMw3TWtKNsEI4SKIA0mf87dj7/Q8KiJ2Wzh6MtdxKAfrjvueXod32tU7F35IdyMWCxJGQZcIey0/DLIW3SHqYhuTSP0GBBQ==\n";
    
    /*  This is the Cipher2. 
        Expected ouput: April29 
        This takes an aproximate average of 9 seconds to run
    */
    char* ciphertext_base64 = (char*) "U2FsdGVkX1/Y+mHv2oZdo5MLKEQWCATfc31jSGWXZ6D3gWuLdZYVUrRnGNecV+EdFsMYSWhEh1nsP9tMwpQaPeWMP3MZ6G0HCLVw+fjRjYY1Fi+lpuGKd/jmZh0Loylw0gVo2SUxNigSvjnn3xAGHg==\n";  

    char* plaintext = "This is the top seret message in parallel computing! Please keep it in a safe place.";

    /*
        Dictionary array. forward vector order = 0-9 -> A-Z -> a-z and reverse vector order = A-Z -> a-z -> 0-9
    */
    char dict[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";    //Forward vector

    /* char dict[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; //Reverse vector */
        
    int decryptedtext_len, ciphertext_len, dict_len;

    // cipher (binary) pointer and length
    size_t cipher_len; // size_t is sizeof(type)
    unsigned char* ciphertext;
  
    unsigned char salt[8];
    
    ERR_load_crypto_strings();
    
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

    unsigned char key[16];
    unsigned char iv[16];

    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    
    // retrive the slater from ciphertext (binary)
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) { // find the keyword "Salted__"
        
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16; 
        cipher_len -= 16;
    
    }

    dict_len = strlen(dict);

    int id;
    int exit=0;
    int i,j,k,l,m;

    time_t begin = time(NULL);
    time_t end;
    
    unsigned char* result;
    omp_set_num_threads(7);
    #pragma omp parallel for collapse(5) firstprivate(begin,plaintext,ciphertext,cipher_len,salt,plainpassword) shared(exit,dict_len,dict) private(key,iv,result,i,j,k,l,m,id,end,password) schedule(static,1)
    for(int i=0; i<dict_len; i++)
        for(int j=0; j<dict_len; j++)
            for(int k=0; k<dict_len; k++)
                for(int l=0; l<dict_len; l++)
                    for(int m=0; m<dict_len; m++){
                        id = omp_get_thread_num();
                        if(exit == 0) {
                        password = &plainpassword[0];
                        password[0] = dict[i];
                        password[1] = dict[j];
                        password[2] = dict[k];
                        password[3] = dict[l];
                        password[4] = dict[m];

                        //prinunsigned char* resulttf(" print ID %d\n",id );
                        

                        initAES(password, salt, key, iv);
                        result = decrypt(ciphertext, cipher_len, key, iv);
                            
                        if(checkPlaintext(plaintext, result)==0){
                                printf("Password is %s\n", password);
                                end = time(NULL);
                                printf("Time elpased is %ld seconds", (end - begin));
                                #pragma omp critical
                                exit = 1;
                               // return 0;
                        }
                        //if (success == 1){
                            

                       // }
                        free(result);  
                    }

                }
                        

            
    // Clean up
    
    EVP_cleanup();
    ERR_free_strings();


    return 0;
}
