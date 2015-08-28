/*

 The MIT License (MIT)

 Copyright (c) 2015 Lucas Betschart
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


#ifndef _BITBOX_CLIENT_H_
#define _BITBOX_CLIENT_H_


/*************** General ***************/
// Initialize USB. Needs to be done before sending any command.
int init(void);

// Need to set the password on client side to encrypt commands
int set_communication_password(const char* password);

// Saves a new device name. The maximum length is 32 characters.
int set_name(const char* name);

// Returns the current device name.
int get_name(char* name_out);

//lclc Sign using a private key

//lclc Get an extended public key at the indicated keypath


/*************** First time use initialization ***************/
// A password is required that has a length of at least 4 characters.
// The password needs to be sent only once and is used to encrypt all communication via the AES-256-CBC algorithm.
int set_password_on_device(const char* password);

//lclc Generate a wallet on your Digital Bitbox

//lclc Backup the existing wallet to a micro SD card

//lclc Set a verification password for two-factor authentication (2FA)


/*************** Other ***************/
// !!!! Dangerous !!!!
// Reset the device and erase all data
// To prevent mistakes, the touch button must be pressed 3 times before a reset occurs.
// After resetting the device, a password must be set before any other command is accepted.
int reset_device(void);

// Get a random number from the device
// true (1) or pseudo mode (2)
// A 16 byte random number is returned as a hexadecimal string.
// The true RNG mode updates a seed value written to the chip's EEPROM,
// which has a specified minimum lifespan of 100,000 write cycles.
// The pseudo RNG mode derives numbers using this seed and does not affect lifespan.
int get_random_number(int mode, char random_out);

// Encrypt or decrypt text (AES 256 CBC)
//Type:  encrypt,decrypt, password, or xpub.
// The latter two options set the AES key that is stored onboard in non-volatile memory,
// which has a specified minimum lifespan of 100,000 write cycles.
//Data:  the data to encrypt / decrypt or the AES key to be set. Encrypted data is base-64 encoded.
// For type equal to xpub, data is the keypath to the extended public key.
// The AES key is the double SHA256 hash of the password or extended public key.
//int encrypt_text(char*  text,);
//int decrypt_text(char* text);

// Toggle the LED
int toggleLED(void);

// Get the device's serial number
//int get_serial_number(char* serial_number_out);

// Get the device's version number
//int get_version_number(char* version_out);

// Send any command that doesn't yet have a own function
int send_any_command(const char *cmd, const char *val);

#endif
