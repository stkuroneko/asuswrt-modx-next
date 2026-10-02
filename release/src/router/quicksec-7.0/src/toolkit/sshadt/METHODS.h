/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   private
*/

bool (* container_init)(SshADTContainer, struct ssh_adt_container_pars *);
void (* clear)(SshADTContainer);
void (* destr)(SshADTContainer); /* private */

SshADTHandle (* insert_at)(SshADTContainer, SshADTRelativeLocation,
                           SshADTHandle, void *);

SshADTHandle (* insert_to)(SshADTContainer, SshADTAbsoluteLocation,
                           void *);

SshADTHandle (* alloc_n_at)(SshADTContainer, SshADTRelativeLocation,
                            SshADTHandle, size_t);

SshADTHandle (* alloc_n_to)(SshADTContainer, SshADTAbsoluteLocation,
                            size_t);

SshADTHandle (* put_n_at)(SshADTContainer, SshADTRelativeLocation,
                          SshADTHandle, size_t, void *);

SshADTHandle (* put_n_to)(SshADTContainer, SshADTAbsoluteLocation,
                          size_t, void *);

void *(* get)(SshADTContainer, SshADTHandle);
size_t (* num_objects)(SshADTContainer);
SshADTHandle (* get_handle_to)(SshADTContainer, void *);
SshADTHandle (* get_handle_to_location)(SshADTContainer,
                                        SshADTAbsoluteLocation);
SshADTHandle (* next)(SshADTContainer, SshADTHandle);
SshADTHandle (* previous)(SshADTContainer, SshADTHandle);
SshADTHandle (* enumerate_start)(SshADTContainer);
SshADTHandle (* enumerate_next)(SshADTContainer, SshADTHandle);

SshADTHandle (* get_handle_to_equal)(SshADTContainer, void *);

void *(* reallocate)(SshADTContainer, void *, size_t);
void *(* detach)(SshADTContainer, SshADTHandle);
void (* delet)(SshADTContainer, SshADTHandle);

void *(* map_lookup)(SshADTContainer, SshADTHandle);
void (* map_attach)(SshADTContainer, SshADTHandle, void *);
