#ifndef SPDK_REUSEPORT_LOADER_H
#define SPDK_REUSEPORT_LOADER_H

#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>

/* Define SO_ATTACH_REUSEPORT_EBPF if not available in headers */
#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 51
#endif

static inline int
attach_reuseport_ebpf(int sockfd, const char *bpf_obj_path, const char *prog_name, struct bpf_object **obj_out)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int rc;

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if(!obj) {
        return -errno;
    }

    rc = bpf_object__load(obj);
    if(rc != 0) {
        bpf_object__close(obj);
        return rc;
    }

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if(!prog) {
        bpf_object__close(obj);
        return -ENOENT;
    }

    prog_fd = bpf_program__fd(prog);
    if(prog_fd < 0) {
        bpf_object__close(obj);
        return -EINVAL;
    }

    rc = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));
    if(rc != 0) {
        bpf_object__close(obj);
        return -errno;
    }

    if(obj_out) {
        *obj_out = obj;
    }

    return 0;
}


static inline void
detach_reuseport_ebpf(struct bpf_object *obj)
{
    if(obj) {
        bpf_object__close(obj);
    } 
}


#endif /* SPDK_REUSEPORT_LOADER_H */