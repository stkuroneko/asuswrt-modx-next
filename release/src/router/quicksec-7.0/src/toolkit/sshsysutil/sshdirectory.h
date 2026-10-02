/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Portable directory access interface.
*/

#ifndef SSHDIRECTORY_H
#define SSHDIRECTORY_H

/*
 * Types and definitions.
 */

/* Handle identifying an open directory. */
typedef struct SshDirectoryRec *SshDirectoryHandle;


/*
 * Prototypes for global functions.
 */

/* Opens the directory <directory> and returns a handle that can be
   used to enumerate its contents.  The function returns NULL if the
   directory could not be opened. */
SshDirectoryHandle ssh_directory_open(const char *directory);

/* Reads the next item from the directory <directory>.  The function
   returns true if the directory did have more items, or false
   otherwise. */
bool ssh_directory_read(SshDirectoryHandle directory);

/* Closes the directory handle <directory> and frees all resources
   associated with it.  The directory handle <directory> must not be
   used after this call. */
void ssh_directory_close(SshDirectoryHandle directory);


/* Access function for directory entries.  These functions can be
   called to the directory handle <directory> after the
   ssh_directory_read() function has returned true.  It is an error to
   call these functions without first calling the ssh_directory_read()
   function. */

/* Returns the name of the current file in the directory <directory>.
   The returned file name is valid until the next call of the
   ssh_directory_read() and ssh_directory_close() functions. */
const char *ssh_directory_file_name(SshDirectoryHandle directory);






























#endif /* not SSHDIRECTORY_H */
