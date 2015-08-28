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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "commander.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"

__extension__ static uint8_t MEM_aeskey_2FA_[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_stand_[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_crypt_[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_verify_[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_memory_[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};


static int memory_eeprom(const uint8_t *write_b, uint8_t *read_b, const int32_t addr,
                         const uint16_t len)
{
    if (write_b) {
        memcpy(read_b, write_b, len);
        (void) addr;
        return STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}


// Encrypted storage
static int memory_eeprom_crypt(const uint8_t *write_b, uint8_t *read_b,
                               const int32_t addr)
{
    int enc_len, dec_len;
    char *enc, *dec, enc_r[MEM_PAGE_LEN * 4 + 1] = {0};
    if (read_b) {
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(read_b, MEM_PAGE_LEN),
                                  MEM_PAGE_LEN * 2, &enc_len, PASSWORD_MEMORY);
        if (!enc) {
            goto err;
        }
        memcpy(enc_r, enc, enc_len);
        free(enc);
    }

    if (write_b) {
        char enc_w[MEM_PAGE_LEN * 4 + 1] = {0};
        enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(write_b, MEM_PAGE_LEN),
                                  MEM_PAGE_LEN * 2, &enc_len, PASSWORD_MEMORY);
        if (!enc) {
            goto err;
        }
        memcpy(enc_w, enc, enc_len);
        free(enc);
        if (memory_eeprom((uint8_t *)enc_w, (uint8_t *)enc_r, addr, MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
        if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN, (uint8_t *)enc_r + MEM_PAGE_LEN,
                          addr + MEM_PAGE_LEN, MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
        if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * 2,
                          (uint8_t *)enc_r + MEM_PAGE_LEN * 2, addr + MEM_PAGE_LEN * 2, MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
        if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * 3,
                          (uint8_t *)enc_r + MEM_PAGE_LEN * 3, addr + MEM_PAGE_LEN * 3, MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
    } else {
        if (memory_eeprom(NULL, (uint8_t *)enc_r, addr, MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
        if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN, addr + MEM_PAGE_LEN,
                          MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
        if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * 2, addr + MEM_PAGE_LEN * 2,
                          MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
        if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * 3, addr + MEM_PAGE_LEN * 3,
                          MEM_PAGE_LEN) == STATUS_ERROR) {
            goto err;
        }
    }

    dec = aes_cbc_b64_decrypt((unsigned char *)enc_r, MEM_PAGE_LEN * 4, &dec_len,
                              PASSWORD_MEMORY);
    if (!dec) {
        goto err;
    }
    memcpy(read_b, utils_hex_to_uint8(dec), MEM_PAGE_LEN);
    memset(dec, 0, dec_len);
    free(dec);
    utils_clear_buffers();
    return STATUS_SUCCESS; // 1 on success
err:
    utils_clear_buffers();
    return STATUS_ERROR;
}


int memory_write_aeskey(const char *password, int len, PASSWORD_ID id)
{
    int ret = 0;
    uint8_t password_b[MEM_PAGE_LEN];
    memset(password_b, 0, MEM_PAGE_LEN);


    if (!password) {
        commander_fill_report("password", FLAG_ERR_PASSWORD_LEN, STATUS_ERROR);
        return STATUS_ERROR;
    }

    if (len < PASSWORD_LEN_MIN) {
        commander_fill_report("password", FLAG_ERR_PASSWORD_LEN, STATUS_ERROR);
        return STATUS_ERROR;
    }

    if (strlen(password) < PASSWORD_LEN_MIN) {
        commander_fill_report("password", FLAG_ERR_PASSWORD_LEN, STATUS_ERROR);
        return STATUS_ERROR;
    }

    sha256_Raw((uint8_t *)password, len, password_b);
    sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch ((int)id) {
        case PASSWORD_MEMORY:
            memcpy(MEM_aeskey_memory_, password_b, MEM_PAGE_LEN);
            ret = STATUS_SUCCESS;
            break;
        case PASSWORD_2FA:
            memcpy(MEM_aeskey_2FA_, password_b, MEM_PAGE_LEN);
            ret = STATUS_SUCCESS;
            break;
        case PASSWORD_STAND:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_stand_, MEM_AESKEY_STAND_ADDR);
            break;
        case PASSWORD_CRYPT:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_crypt_, MEM_AESKEY_CRYPT_ADDR);
            break;
        case PASSWORD_VERIFY:
            ret = memory_eeprom_crypt(password_b, MEM_aeskey_verify_, MEM_AESKEY_VERIFY_ADDR);
            break;
        default:
            memset(password_b, 0, MEM_PAGE_LEN);
            commander_fill_report("password", FLAG_ERR_PASSWORD_ID, STATUS_ERROR);
            return STATUS_ERROR;
    }

    memset(password_b, 0, MEM_PAGE_LEN);
    if (ret == STATUS_SUCCESS) {
        return STATUS_SUCCESS;
    } else {
        commander_fill_report("password", FLAG_ERR_ATAES, STATUS_ERROR);
        return STATUS_ERROR;
    }
}


uint8_t *memory_read_aeskey(PASSWORD_ID id)
{
    switch ((int)id) {
        case PASSWORD_MEMORY:
            return MEM_aeskey_memory_;
        case PASSWORD_2FA:
            return MEM_aeskey_2FA_;
        case PASSWORD_STAND:
            memory_eeprom_crypt(NULL, MEM_aeskey_stand_, MEM_AESKEY_STAND_ADDR);
            return MEM_aeskey_stand_;
        case PASSWORD_CRYPT:
            memory_eeprom_crypt(NULL, MEM_aeskey_crypt_, MEM_AESKEY_CRYPT_ADDR);
            return MEM_aeskey_crypt_;
        case PASSWORD_VERIFY:
            memory_eeprom_crypt(NULL, MEM_aeskey_verify_, MEM_AESKEY_VERIFY_ADDR);
            return MEM_aeskey_verify_;
        default:
            return 0;
    }
    return 0;
}


