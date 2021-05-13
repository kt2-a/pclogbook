
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <sys/time.h>
#include <mpi/mpi.h>

int success = 0;
/*
    Function: checkPlaintext
    Operation: Compares the recently acquired result to the target plaintext.
    Inputs: char* plaintext - pointer to target plaintext
            char* result - pointer to result of decryption attempt.
    Output: return strncmp(plaintext, result, length) - value < 0 : plaintext > result
                                                        value > 0 : plaintext < result
                                                        value = 0 : plaintext = result
    Notes: Complies with the standards of a Known-Plaintext-Attack.
*/
int checkPlaintext(char* plaintext, char* result){
    int length = 10;
    return strncmp(plaintext, result, length);
}

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv)
{
    //initialisatio of key and iv with 0
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *success){

    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintexts;
    int len;
    int plaintext_len;
    
    //unsigned char* plaintext = new unsigned char[ciphertext_len];
    unsigned char* plaintext = malloc(ciphertext_len);
    bzero(plaintext,ciphertext_len);

    /* Create and initialise the context */
  
    if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    
    //printf("%lu\n", strlen(key));
    //printf("%lu\n", strlen(iv));
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
        //handleOpenSSLErrors()
         //printf("Here9!\n");
         *success = 1;
    plaintext_len += len;

   
    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //string ret = (char*)plaintext;
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

    
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

/*
    Function: main
    Operation: primary runtime, initialise variables, generate password, create parallel region, attempt cracking.
*/
int main (int argc, char **argv){
   
    //Initialise OpenMPI specific variables, used in message passing and vector assignment.
    MPI_Status status;
    MPI_Request req;
    int ranking, sizing, error, test, rcvbuf, sendbuf;
    int counter = 1;

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

    //Initialise Key and IV.
    unsigned char key[16];
    unsigned char iv[16];

    //Define password length.
    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    int password_length = 3;

    // retreive the slater from ciphertext (binary)
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16;
        cipher_len -= 16;
    }

    //initialize the dictionary length.
    dict_len = strlen(dict);

    //Initialization of MPI environment 
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &ranking);
    MPI_Comm_size(MPI_COMM_WORLD, &sizing);
    MPI_Irecv(&rcvbuf, counter, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req); 

    //Initialise clock time 
    time_t begin = time(NULL);


    for(int i = ranking; i < dict_len; i = i + sizing)
    {
      for(int j=0; j<dict_len; j++)
      {
        for(int k=0; k<dict_len; k++)
        {
          for(int l=0; l<dict_len; l++)
          {
            for(int m=0; m<dict_len; m++)
            {

                    //check if the posted receive has been completed. 
                    MPI_Test(&req, &test, &status);
                    if(test == 1){
                        MPI_Finalize();
                    }

                    *password = dict[i];
                    *(password+1) = dict[j];
                    *(password+2) = dict[k];
                    *(password+3) = dict[l];
                    *(password+4) = dict[m];

                    initAES(password, salt, key, iv);
                    unsigned char* result = decrypt(ciphertext, cipher_len, key, iv, &success);

                    if (success == 1){
                        if(checkPlaintext(plaintext, result)==0){

                                MPI_Bcast(&sendbuf, counter, MPI_INT, ranking, MPI_COMM_WORLD);

                                printf("Password is %s\n", password);
                                
                                time_t end = time(NULL);
                                printf("Time elpased is %ld seconds", (end - begin));
 
                                return 0;
                        }
                    }

                    free(result);


                }
            }
        }
    }
  }


    // Clean up
    EVP_cleanup();
    ERR_free_strings();
    MPI_Finalize();
}
