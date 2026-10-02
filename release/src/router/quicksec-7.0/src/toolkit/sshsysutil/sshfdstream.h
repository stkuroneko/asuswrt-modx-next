/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Streams interface interfacing to file descriptors on Unix
   and Win32 platforms.
*/

#ifndef SSHFDSTREAM_H
#define SSHFDSTREAM_H

#include "sshstream.h"

/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is true, the
   descriptor will be automatically closed when the stream is destroyed. */
SshStream ssh_stream_fd_wrap(SshIOHandle fd, bool close_on_destroy);

/* Creates a stream around two file descriptors, one for reading and
   one for writing.  `readfd' must be open for reading, and `writefd' for
   writing.  If close_on_destroy is true, both descriptors will be
   automatically closed when the stream is destroyed. */
SshStream ssh_stream_fd_wrap2(SshIOHandle readfd, SshIOHandle writefd,
                              bool close_on_destroy);

/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is true, the
   descriptor will be automatically closed when the stream is destroyed.
   Calls close callback with close param when closed.
*/
SshStream
ssh_stream_fd_wrap_with_close_callback(SshIOHandle fd,
                                       void (*close_callback)(void *),
                                       void *close_param,
                                       bool close_on_destroy);


/* Creates a stream around the standard input/standard output of the
   current process. */
SshStream ssh_stream_fd_stdio(void);

/* Creates a stream for stderr output of the current process.
   This stream is for output only, and has never anything to read.*/
SshStream ssh_stream_fd_stderr(void);

/* Returns the file descriptor being used for reads, or -1 if the stream is
   not an fd stream. */
SshIOHandle ssh_stream_fd_get_readfd(SshStream stream);

/* Returns the file descriptor being used for writes, or -1 if the stream is
   not an fd stream. */
SshIOHandle ssh_stream_fd_get_writefd(SshStream stream);

/* Marks the stream as a forked copy.  The consequence is that when the stream
   is destroyed, the underlying file descriptors are not restored to blocking
   mode.  This should be called for each stream before destroying them
   after a fork (but only on one of parent or child). */
void ssh_stream_fd_mark_forked(SshStream stream);

/* Creates a file descriptor stream around the file `filename'.  If
   the argument `readable' is true, the application will read data
   from the file.  If the argument `writable' is true, the application
   will write data to the file.  The function returns a stream or NULL
   if the operation fails. */
SshStream ssh_stream_fd_file(const char *filename, bool readable,
                             bool writable);







































#endif /* SSHFDSTREAM_H */
