#ifndef LAPY_NATIVE_DIRECTORY_H
#define LAPY_NATIVE_DIRECTORY_H

#include <stdint.h>

/* Transport only, not elevation or authorization. Both endpoints must already
 * be authenticated and bound to the intended live process by the caller.
 * Requires a connected AF_UNIX SOCK_SEQPACKET socket. Operations are nonblocking
 * and return a positive errno (zero on success); never retry an uncertain send.
 * Each packet is bound to the caller's request ID. No kernel addresses cross it.
 */
int lapy_send_directory(int socket_fd, int directory_fd, uint64_t request_id);

/* On success, *directory_fd is one owned, close-on-exec directory descriptor.
 * The caller must close it. On every error it is -1; any received descriptors
 * have been closed. Sending never transfers away the sender's ownership.
 * Runtime support for MSG_CMSG_CLOEXEC is required; no racy fallback is used.
 */
int lapy_receive_directory(int socket_fd, uint64_t request_id, int *directory_fd);

/* Same ownership contract; stage receives a static diagnostic label, never
 * addresses or descriptor values. It may be NULL. */
int lapy_receive_directory_diagnostic(int socket_fd, uint64_t request_id,
                                      int *directory_fd, const char **stage);

/* Explicit alternative for platforms without atomic CLOEXEC reception.
 * PRECONDITION: caller excludes fork/exec and descriptor-table mutation by
 * every other thread/sharer until this call finishes. For remote use this
 * requires verified target quiescence; a request ID or PID is insufficient.
 * Uses recvmsg without MSG_CMSG_CLOEXEC, then F_SETFD and verifies F_GETFD.
 * Same cleanup and output ownership contract. Never an automatic fallback.
 */
int lapy_receive_directory_exclusive(int socket_fd, uint64_t request_id,
                                     int *directory_fd, const char **stage);

#endif
