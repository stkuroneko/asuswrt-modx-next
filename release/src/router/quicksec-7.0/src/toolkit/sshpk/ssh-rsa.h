/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RSA key generation, encryption and decryption.
*/

#ifndef SSH_RSA_H
#define SSH_RSA_H

extern const SshPkType ssh_pk_if_modn;
extern const SshPkType ssh_pk_if_modn_generator;

extern const SshPkType ssh_pk_dl_modp;
extern const SshPkType ssh_pk_dl_modp_generator;

#if 0
/* Obselete key types */
extern const SshPkType ssh_pk_dl_modp_old;
extern const SshPkType ssh_pk_dl_modp_generator_old;
#endif

#endif /* SSH_RSA_H */
