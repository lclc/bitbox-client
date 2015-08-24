/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "commander.h"
#include "random.h"
#include "base64.h"
#include "flags.h"
#include "aes.h"


const char *CMD_STR[] = { FOREACH_CMD(GENERATE_STRING) };

static int REPORT_BUF_OVERFLOW = 0;
static char json_report[COMMANDER_REPORT_SIZE] = {0};

// Must free() returned value (allocated inside base64() function)
char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                          PASSWORD_ID id)
{
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen % N_BLOCK;
    unsigned char inpad[inpadlen];
    unsigned char enc[inpadlen];
    unsigned char iv[N_BLOCK];
    unsigned char enc_cat[inpadlen + N_BLOCK]; // concatenating [ iv0  |  enc ]
    aes_context ctx[1];

    // Set cipher key
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_read_aeskey(id), 32, ctx);

    // PKCS7 padding
    memcpy(inpad, in, inlen);
    for (pads = 0; pads < N_BLOCK - inlen % N_BLOCK; pads++ ) {
        inpad[inlen + pads] = (N_BLOCK - inlen % N_BLOCK);
    }

    // Make a random initialization vector
    if (random_bytes((uint8_t *)iv, N_BLOCK, 0) == STATUS_ERROR) {
        commander_fill_report("random", FLAG_ERR_ATAES, STATUS_ERROR);
        memset(inpad, 0, inpadlen);
        return NULL;
    }
    memcpy(enc_cat, iv, N_BLOCK);

    // CBC encrypt multiple blocks
    aes_cbc_encrypt( inpad, enc, inpadlen / N_BLOCK, iv, ctx );
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);

    // base64 encoding
    int b64len;
    char *b64;
    b64 = base64(enc_cat, inpadlen + N_BLOCK, &b64len);
    *out_b64len = b64len;
    memset(inpad, 0, inpadlen);
    return b64;
}


// Must free() returned value
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len,
                          PASSWORD_ID id)
{
    *decrypt_len = 0;

    if (!in || inlen == 0) {
        return NULL;
    }

    // Unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((char *)in, inlen, &ub64len);
    if (!ub64 || (ub64len % N_BLOCK) || ub64len < N_BLOCK) {
        free(ub64);
        return NULL;
    }

    // Set cipher key
    aes_context ctx[1];
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_read_aeskey(id), 32, ctx);

    unsigned char dec_pad[ub64len - N_BLOCK];
    aes_cbc_decrypt(ub64 + N_BLOCK, dec_pad, ub64len / N_BLOCK - 1, ub64, ctx);
    memset(ub64, 0, ub64len);
    free(ub64);

    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len - N_BLOCK - 1];
    if (ub64len - N_BLOCK - padlen <= 0) {
       memset(dec_pad, 0, sizeof(dec_pad));
       return NULL;
    }
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec) {
        memset(dec_pad, 0, sizeof(dec_pad));
        return NULL;
    }
    memcpy(dec, dec_pad, ub64len - N_BLOCK - padlen);
    dec[ub64len - N_BLOCK - padlen] = '\0';
    *decrypt_len = ub64len - N_BLOCK - padlen + 1;
    memset(dec_pad, 0, sizeof(dec_pad));
    return dec;
}



//
//  Reporting results  //
//

static void commander_fill_report_len(const char *attr, const char *val, int err,
                                      size_t vallen)
{
    size_t len = strlen(json_report);
    if (len == 0) {
        strncat(json_report, "{", 1);
    } else {
        json_report[len - 1] = ','; // replace closing '}' with continuing ','
    }

    if (COMMANDER_REPORT_SIZE < (vallen + strlen(attr) + len +
                                 (22 < strlen(FLAG_ERR_REPORT_BUFFER) ? strlen(FLAG_ERR_REPORT_BUFFER) : 22))) {
        if (!REPORT_BUF_OVERFLOW) {
            strcat(json_report, FLAG_ERR_REPORT_BUFFER);
            REPORT_BUF_OVERFLOW = 1;
        }
    } else {
        strcat(json_report, " \"");
        strcat(json_report, attr);
        if (err == STATUS_ERROR) {
            strcat(json_report, "\":{ \"error\": ");
        } else {
            strcat(json_report, "\": ");
        }

        if (val[0] == '{') {
            strncat(json_report, val, vallen);
        } else {
            strcat(json_report, "\"");
            strncat(json_report, val, vallen);
            strcat(json_report, "\"");
        }

        // Add closing '}'
        if (err == STATUS_ERROR) {
            strcat(json_report, " } }");
        } else {
            strcat(json_report, " }");
        }
    }
}


void commander_fill_report(const char *attr, const char *val, int err)
{
    commander_fill_report_len(attr, val, err, strlen(val));
}
