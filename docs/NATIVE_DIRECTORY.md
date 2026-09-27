# Native directory-reference route (in progress)

The intended result remains a process that is elevated and can use its own
normal file APIs under `/data`. This is not a file-operation broker. The daemon
would transfer a directory descriptor once; the kernel would then manage the
new root's references through native filesystem operations.

## Implemented component

`source/native_directory.c` transfers one owned directory descriptor over an
already authenticated, connected Unix `SOCK_SEQPACKET` socket using SCM_RIGHTS.
It preserves the sender's descriptor and gives the receiver a close-on-exec
descriptor. Both operations are nonblocking. The receiver rejects missing or
extra rights, truncation, wrong request IDs, wrong packet sizes and non-directory
descriptors, closing any rights it received before reporting an error. The
request ID is correlation, not authentication. The caller must authenticate and
bind the channel to the intended live process before transferring a root fd.

`make check` exercises 1000 transfers, Linux descriptor-count stability, hostile
packets, kernel ancillary truncation, nonblocking receive, cross-process
ownership and use after sender close, and a disconnected peer with SIGPIPE
suppressed. ASan/UBSan are enabled. `make native-components` cross-compiles the
transport object with the PS5 SDK. Neither command builds a working elevation
backend or proves PS5 Unix-socket/ancillary support.

## Why this route is worth testing

In [FreeBSD 11 sys_fchdir](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/kern/vfs_syscalls.c#L721),
the kernel acquires a vnode reference for the new working directory, and
`pwd_chdir` releases the old one. In
[pwd_chroot](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/kern/kern_descrip.c#L3019),
the kernel acquires the new root reference and releases the old root. Existing
non-null `fd_jdir` is preserved with its original ownership. This may provide
the required access without ever writing either root/jail pointer directly.
This is a source-grounded candidate, **not evidence of PS5 behavior**.

The proposed flow is: authenticate and stop the target safely; establish private
credentials and filedesc state using native paths; deliver a root directory fd;
invoke fchdir then chroot in the target; restore the working directory if the
contract requires it; close temporary descriptors and restore execution state.
Credential privilege changes, shared state handling and tracing are not yet
implemented. There must be no fallback to raw root/jail pointer writes.

## Discovery in kstuff and libhijacker

Pinned kstuff-lite `33ec81e5e086837f54644d519ed0a90b16d5c1f5` includes:

- `prosper0gdb/r0gdb.c:r0gdb_kfncall`: an existing kernel-call mechanism requiring
  its instrumentation setup; not a directly linkable SDK user-mode API.
- `ps5-kstuff/uelf/kekcall.c`: remote syscall dispatch selects the target's first
  thread and invokes a sysent handler. The inspected dispatch function does not
  itself retain the selected process/thread or stop concurrent target activity.
  It must not be assumed safe for arbitrary exit races or for handlers that use
  curthread/user-memory context rather than only the explicit thread argument.
- `self_elevation.c`: native seteuid dispatch for the caller, followed by raw
  filesystem pointer writes. Reuse requires changing the filesystem half.

Pinned libhijacker's `Tracer` does attach/wait and single-step syscalls, but its
helper ignores some ptrace/wait results and returns RAX without interpreting
the syscall carry flag. It is not sufficient unchanged for transactional
elevation. Peer authentication, bounded waits, all-thread stop/resume behavior,
pending signals, register restoration and process identity must be validated.

## Required PS5 gates

1. A read-only transport probe must establish native AF_UNIX/SOCK_SEQPACKET,
   SCM_RIGHTS and MSG_CMSG_CLOEXEC support. Unsupported cases return errors.
2. Confirm that a descriptor transferred across title sandbox paths refers to
   the intended root, and that the target can invoke fchdir/chroot with the
   intended credentials. Do not assume FreeBSD behavior proves this.
3. Verify `/data` access while retaining the existing jail-directory reference.
   If Sony requires a different jail directory, this route is insufficient; do
   not compensate by raw writes or extra counter increments.
4. Validate credential cloning/identity bookkeeping and filedesc isolation,
   repeated calls, rollback boundaries, exit/exec/rfork and concurrent threads.
5. Record native results through the lab logging server's `ps5log/1` contract,
   with the exact binary identity, from a clean boot and exclusive console lease.

The default build continues to refuse a purported safe elevation payload until
the actual backend is implemented and these gates have evidence.
