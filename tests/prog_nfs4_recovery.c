/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Session recovery against a loopback RPC peer, without a NAS or FUSE mount. */
#define _GNU_SOURCE
#include "config.h"
#if !defined(HAVE_NFS4_2) || defined(WIN32)
int main(void) { return 77; }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_STDATOMIC_H
#include <stdatomic.h>
#endif
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(expr, ...) do { if (!(expr)) { \
        fprintf(stderr, "FAIL: " __VA_ARGS__); fputc('\n', stderr); exit(1); \
} } while (0)
#define MAX_OPS 16

enum reclaim_fault {
        LOSS_NONE, LOSS_RECLAIM, LOSS_REOPEN, LOSS_COMPLETE
};

struct completion {
#ifdef HAVE_STDATOMIC_H
        atomic_uint calls;
#else
        unsigned calls;
#endif
        int status;
        struct nfs_stat_64 attributes;
        struct nfsfh *fh;
};

struct scenario {
        const char *name;
        int session_lost, reboot, reconnect, active;
        int delays, drop_when_delayed, destroy_when_delayed;
        int switch_uid, open_file, lock_file, repeat, concurrent;
        int cancel, destroy, create_delays;
        int lost_mutation_reply;
        int no_grace, reclaim_stale, dirty, fsync_before_reboot;
        int new_open, rejected_mutation;
        int active_write, open_uid, reclaim_delays, post_grace, verifier_change;
        int threaded;
        int new_after_loss, reclaim_destroy, reclaim_close, reclaim_loss, reclaim_reboot;
        int reopen_delays;
        nfsstat4 reclaim_error;
};

struct fixture {
        struct nfs_context *nfs;
        int listener, peer;
        const char *name;
        uint64_t deadline;
        clientid4 clientid;
        sequenceid4 create_sequence;
        sessionid4 session;
        uint32_t sequences[2];
        int valid, delay, drop_when_delayed;
        char delayed_request[16384];
        size_t delayed_length;
        unsigned requests, exchanges, creates, binds, renews, rejections;
        verifier4 verifier;
        char owner[1024];
        size_t owner_length;
        char session_cred[1024];
        size_t session_cred_length;
        stateid4 open_state;
        stateid4 lock_state;
        int file_open;
        int locked;
        unsigned opens, reads, closes;
        int create_delays;
        char create_request[16384];
        size_t create_request_length;
        int drop_mutation_reply;
        unsigned removes;
        int no_grace, reclaim_stale, reclaim_complete;
        unsigned reclaims;
        char open_cred[1024], open_owner[32];
        size_t open_cred_length, open_owner_length;
        uint32_t share_access;
        int reclaim_delays, post_grace, verifier_change;
        int threaded;
        int reuse_stateid, reclaim_loss, reclaim_reboot;
        int reopen_delays;
        nfsstat4 reclaim_error;
        unsigned reclaim_faults;
        int standalone;
        char *contents;
};

struct mutation_completion {
        struct completion mutation, followup;
};

static void
complete(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct completion *cb = opaque;
        (void)data;
        CHECK(!cb->calls, "completion called more than once");
        cb->status = status;
        if (status < 0) {
                const char *error = nfs_get_error(nfs);
                fprintf(stderr, "NFS callback: %d: %s\n", status, error ? error : "no detail");
        }
        cb->calls = 1;
}

static void
stat_complete(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct completion *cb = opaque;
        if (!status)
                cb->attributes = *(struct nfs_stat_64 *)data;
        complete(status, nfs, data, opaque);
}

static void
open_complete(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct completion *cb = opaque;
        if (!status)
                cb->fh = data;
        complete(status, nfs, data, opaque);
}

static void
raw_complete(struct rpc_context *rpc, int status, void *data, void *opaque)
{
        struct completion *cb = opaque;
        (void)rpc;
        (void)data;
        CHECK(++cb->calls == 1, "raw completion called more than once");
        cb->status = status;
}

static void
mutation_complete(int status, struct nfs_context *nfs, void *data, void *opaque)
{
        struct mutation_completion *cb = opaque;
        complete(status, nfs, data, &cb->mutation);
        CHECK(status < 0, "uncertain mutation was reported as successful");
        CHECK(!nfs_stat64_async(nfs, "/", stat_complete, &cb->followup),
              "reentrant submission from failed mutation callback");
}

static void
transfer(int fd, void *buffer, size_t length, int writing)
{
        char *p = buffer;
        while (length) {
                ssize_t count = writing ? write(fd, p, length) : read(fd, p, length);
                if (count < 0 && errno == EINTR)
                        continue;
                CHECK(count > 0, "%s RPC record: %s",
                      writing ? "write" : "read", count ? strerror(errno) : "EOF");
                p += count;
                length -= count;
        }
}

static nfsstat4
session_op(struct fixture *f, const nfs_argop4 *arg, nfs_resop4 *out)
{
        switch (arg->argop) {
        case OP_EXCHANGE_ID: {
                const client_owner4 *owner = &arg->nfs_argop4_u.opexchangeid.eia_clientowner;
                EXCHANGE_ID4resok *res = &out->nfs_resop4_u.opexchangeid.EXCHANGE_ID4res_u.eir_resok4;
                if (f->exchanges++) {
                        CHECK(owner->co_ownerid.co_ownerid_len == f->owner_length &&
                              !memcmp(owner->co_ownerid.co_ownerid_val, f->owner, f->owner_length) &&
                              !memcmp(owner->co_verifier, f->verifier, sizeof(verifier4)),
                              "recovery changed the client owner or verifier");
                } else {
                        f->owner_length = owner->co_ownerid.co_ownerid_len;
                        CHECK(f->owner_length && f->owner_length <= sizeof(f->owner), "client owner length");
                        memcpy(f->owner, owner->co_ownerid.co_ownerid_val, f->owner_length);
                        memcpy(f->verifier, owner->co_verifier, sizeof(verifier4));
                }
                res->eir_clientid = f->clientid;
                res->eir_sequenceid = f->create_sequence;
                res->eir_flags = EXCHGID4_FLAG_USE_NON_PNFS;
                res->eir_state_protect.spr_how = SP4_NONE;
                res->eir_server_owner.so_major_id.so_major_id_val = "loopback";
                res->eir_server_owner.so_major_id.so_major_id_len = 8;
                res->eir_server_scope.eir_server_scope_val = "loopback";
                res->eir_server_scope.eir_server_scope_len = 8;
                return NFS4_OK;
        }
        case OP_CREATE_SESSION: {
                const CREATE_SESSION4args *cs = &arg->nfs_argop4_u.opcreatesession;
                CREATE_SESSION4resok *res = &out->nfs_resop4_u.opcreatesession.CREATE_SESSION4res_u.csr_resok4;
                if (cs->csa_clientid != f->clientid)
                        return NFS4ERR_STALE_CLIENTID;
                CHECK(cs->csa_sequence == f->create_sequence, "CREATE_SESSION sequence");
                if (f->create_delays) {
                        --f->create_delays;
                        return NFS4ERR_DELAY;
                }
                ++f->create_sequence;
                memset(f->session, ++f->creates, sizeof(sessionid4));
                memset(f->sequences, 0, sizeof(f->sequences));
                memcpy(res->csr_sessionid, f->session, sizeof(sessionid4));
                res->csr_sequence = cs->csa_sequence;
                res->csr_fore_chan_attrs = cs->csa_fore_chan_attrs;
                res->csr_fore_chan_attrs.ca_maxrequests = 2;
                res->csr_back_chan_attrs = cs->csa_back_chan_attrs;
                f->valid = 1;
                return NFS4_OK;
        }
        case OP_BIND_CONN_TO_SESSION: {
                const BIND_CONN_TO_SESSION4args *bind = &arg->nfs_argop4_u.opbindconntosession;
                BIND_CONN_TO_SESSION4resok *res = &out->nfs_resop4_u.opbindconntosession.BIND_CONN_TO_SESSION4res_u.bctsr_resok4;
                ++f->binds;
                if (!f->valid || memcmp(bind->bctsa_sessid, f->session, sizeof(sessionid4)))
                        return NFS4ERR_BADSESSION;
                memcpy(res->bctsr_sessid, f->session, sizeof(sessionid4));
                res->bctsr_dir = CDFS4_FORE;
                return NFS4_OK;
        }
        case OP_SEQUENCE: {
                const SEQUENCE4args *seq = &arg->nfs_argop4_u.opsequence;
                SEQUENCE4resok *res = &out->nfs_resop4_u.opsequence.SEQUENCE4res_u.sr_resok4;
                if (!f->valid || memcmp(seq->sa_sessionid, f->session, sizeof(sessionid4)))
                        return NFS4ERR_BADSESSION;
                CHECK(seq->sa_slotid < 2, "slot outside the negotiated table");
                if (f->delay) {
                        --f->delay;
                        return NFS4ERR_DELAY;
                }
                CHECK(seq->sa_sequenceid == ++f->sequences[seq->sa_slotid], "skipped or reused sequence");
                memcpy(res->sr_sessionid, f->session, sizeof(sessionid4));
                res->sr_sequenceid = seq->sa_sequenceid;
                res->sr_slotid = seq->sa_slotid;
                res->sr_highest_slotid = res->sr_target_highest_slotid = 1;
                return NFS4_OK;
        }
        case OP_RECLAIM_COMPLETE:
                f->reclaim_complete = 1;
                return NFS4_OK;
        case OP_DESTROY_SESSION:
                f->valid = 0;
                return NFS4_OK;
        default:
                CHECK(0, "unexpected session operation %u", arg->argop);
                return NFS4ERR_SERVERFAULT;
        }
}

static void
mount_attributes(const bitmap4 *wanted, int file, fattr4 *attr,
                  uint32_t mask[2], char buffer[256])
{
        const uint32_t supported[2] = {
                (1U << FATTR4_TYPE) | (1U << FATTR4_CHANGE) | (1U << FATTR4_SIZE) |
                (1U << FATTR4_FSID) | (1U << FATTR4_FILEID),
                (1U << (FATTR4_MODE - 32)) | (1U << (FATTR4_NUMLINKS - 32)) |
                (1U << (FATTR4_OWNER - 32)) | (1U << (FATTR4_OWNER_GROUP - 32)) |
                (1U << (FATTR4_SPACE_USED - 32)) | (1U << (FATTR4_TIME_ACCESS - 32)) |
                (1U << (FATTR4_TIME_METADATA - 32)) | (1U << (FATTR4_TIME_MODIFY - 32))
        };
        ZDR encoder;
        unsigned bit;

        mask[0] = wanted->bitmap4_len ? wanted->bitmap4_val[0] & supported[0] : 0;
        mask[1] = wanted->bitmap4_len > 1 ? wanted->bitmap4_val[1] & supported[1] : 0;
        zdrmem_create(&encoder, buffer, 256, ZDR_ENCODE);
        for (bit = 0; bit < 64; bit++) {
                uint32_t small = 0;
                uint64_t large = 0;
                char *owner = "1001";
                if (!(mask[bit / 32] & (1U << (bit % 32))))
                        continue;
                switch (bit) {
                case FATTR4_TYPE: small = file ? NF4REG : NF4DIR; break;
                case FATTR4_MODE: small = file ? 0644 : 0755; break;
                case FATTR4_NUMLINKS: small = file ? 1 : 2; break;
                case FATTR4_OWNER: case FATTR4_OWNER_GROUP:
                        CHECK(zdr_string(&encoder, &owner, 16), "encode owner");
                        continue;
                case FATTR4_FSID:
                        large = 1;
                        CHECK(zdr_uint64_t(&encoder, &large) && zdr_uint64_t(&encoder, &large), "encode fsid");
                        continue;
                case FATTR4_TIME_ACCESS: case FATTR4_TIME_METADATA: case FATTR4_TIME_MODIFY:
                        large = 1700000000;
                        CHECK(zdr_uint64_t(&encoder, &large) && zdr_uint32_t(&encoder, &small), "encode time");
                        continue;
                case FATTR4_SIZE: case FATTR4_SPACE_USED:
                        large = file == 1 ? 8U * 1024U * 1024U : file == 2 ? 11 : 4096;
                        CHECK(zdr_uint64_t(&encoder, &large), "encode size");
                        continue;
                default:
                        large = file + 1;
                        CHECK(zdr_uint64_t(&encoder, &large), "encode identity");
                        continue;
                }
                CHECK(zdr_uint32_t(&encoder, &small), "encode attributes");
        }
        attr->attrmask.bitmap4_len = 2;
        attr->attrmask.bitmap4_val = mask;
        attr->attr_vals.attrlist4_val = buffer;
        attr->attr_vals.attrlist4_len = zdr_getpos(&encoder);
        zdr_destroy(&encoder);
}

static void
serve(struct fixture *f)
{
        char request[16384], reply[262144], attributes[MAX_OPS][256];
        uint32_t marker, size, bitmaps[MAX_OPS];
        uint32_t mount_masks[MAX_OPS][2], entry_masks[2][2];
        char entry_attributes[2][256];
        entry4 entries[2] = {0};
        struct rpc_msg call = {0}, response = {0};
        COMPOUND4args args = {0};
        COMPOUND4res result = {0};
        nfs_resop4 ops[MAX_OPS] = {0};
        ZDR decoder, encoder;
        unsigned i;
        int file = 0;

        CHECK(++f->requests <= (f->standalone ? 100000U : 128U), "%s: unbounded requests", f->name);
        transfer(f->peer, &marker, 4, 0);
        marker = ntohl(marker);
        size = marker & 0x7fffffffU;
        CHECK((marker & 0x80000000U) && size <= sizeof(request), "RPC record size");
        transfer(f->peer, request, size, 0);
        zdrmem_create(&decoder, request, size, ZDR_DECODE);
        CHECK(zdr_callmsg(f->nfs->rpc, &decoder, &call), "decode RPC call");
        CHECK(call.body.cbody.prog == NFS4_PROGRAM && call.body.cbody.vers == NFS_V4,
              "unexpected RPC program %u version %u", call.body.cbody.prog, call.body.cbody.vers);
        if (call.body.cbody.proc == NFSPROC4_NULL)
                goto reply;
        CHECK(call.body.cbody.proc == NFSPROC4_COMPOUND, "unexpected RPC procedure %u", call.body.cbody.proc);
        CHECK(zdr_COMPOUND4args(&decoder, &args), "decode COMPOUND");
        CHECK(args.minorversion == 2 && args.argarray.argarray_len &&
              args.argarray.argarray_len <= MAX_OPS, "COMPOUND version or length");
        if (f->standalone) {
                fprintf(stderr, "RPC %u:", f->requests);
                for (i = 0; i < args.argarray.argarray_len; i++)
                        fprintf(stderr, " %u", args.argarray.argarray_val[i].argop);
                fputc('\n', stderr);
        }
        if (args.argarray.argarray_val[0].argop == OP_EXCHANGE_ID ||
            args.argarray.argarray_val[0].argop == OP_CREATE_SESSION) {
                const struct opaque_cred *cred = &call.body.cbody.cred;
                CHECK(cred->oa_flavor == AUTH_SYS && cred->oa_length <= sizeof(f->session_cred),
                      "session credentials");
                if (!f->session_cred_length) {
                        f->session_cred_length = cred->oa_length;
                        memcpy(f->session_cred, cred->oa_base, cred->oa_length);
                } else {
                        CHECK(cred->oa_length == f->session_cred_length &&
                              !memcmp(cred->oa_base, f->session_cred, cred->oa_length),
                              "recovery used another caller's credentials");
                }
        }
        switch (args.argarray.argarray_val[0].argop) {
        case OP_EXCHANGE_ID: case OP_CREATE_SESSION:
        case OP_BIND_CONN_TO_SESSION: case OP_DESTROY_SESSION:
                CHECK(args.argarray.argarray_len == 1, "session management compound length");
                break;
        default:
                CHECK(args.argarray.argarray_val[0].argop == OP_SEQUENCE,
                      "%s: ordinary COMPOUND without SEQUENCE (first op %u)",
                      f->name, args.argarray.argarray_val[0].argop);
        }
        if (args.argarray.argarray_val[0].argop == OP_CREATE_SESSION && f->create_request_length) {
                CHECK(size == f->create_request_length && !memcmp(request, f->create_request, size),
                      "CREATE_SESSION retry changed the original request");
                f->create_request_length = 0;
        }
        if ((f->reclaim_loss == LOSS_COMPLETE && args.argarray.argarray_len == 2 &&
             args.argarray.argarray_val[1].argop == OP_RECLAIM_COMPLETE) ||
            ((f->reclaim_loss == LOSS_RECLAIM || f->reclaim_loss == LOSS_REOPEN) &&
             args.argarray.argarray_len == 3 &&
             args.argarray.argarray_val[2].argop == OP_OPEN &&
             args.argarray.argarray_val[2].nfs_argop4_u.opopen.claim.claim ==
                     (f->reclaim_loss == LOSS_REOPEN ? CLAIM_FH : CLAIM_PREVIOUS))) {
                f->reclaim_loss = f->valid = 0;
                f->reclaim_faults++;
                if (f->reclaim_reboot) {
                        ++f->clientid;
                        f->create_sequence = 1;
                        f->file_open = f->locked = f->reclaim_complete = 0;
                }
        }
        if (args.argarray.argarray_len == 1 && args.argarray.argarray_val[0].argop == OP_SEQUENCE) {
                ++f->renews;
                if (f->delayed_length) {
                        CHECK(size == f->delayed_length && !memcmp(request, f->delayed_request, size),
                              "keepalive retry changed XID, credentials or SEQUENCE");
                        f->delayed_length = 0;
                }
        }

        result.resarray.resarray_val = ops;
        for (i = 0; i < args.argarray.argarray_len; i++) {
                const nfs_argop4 *arg = &args.argarray.argarray_val[i];
                nfs_resop4 *out = &ops[i];
                nfsstat4 status = NFS4_OK;
                out->resop = arg->argop;
                switch (arg->argop) {
                case OP_PUTROOTFH:
                        file = 0;
                        break;
                case OP_PUTFH:
                        file = arg->nfs_argop4_u.opputfh.object.nfs_fh4_len == 4 &&
                                !memcmp(arg->nfs_argop4_u.opputfh.object.nfs_fh4_val, "file", 4);
                        if (f->standalone && arg->nfs_argop4_u.opputfh.object.nfs_fh4_len == 4 &&
                            !memcmp(arg->nfs_argop4_u.opputfh.object.nfs_fh4_val, "newf", 4))
                                file = 2;
                        break;
                case OP_LOOKUP:
                        file = 1;
                        if (f->standalone) {
                                const utf8str_cs *name = &arg->nfs_argop4_u.oplookup.objname;
                                if (name->utf8string_len == 4 && !memcmp(name->utf8string_val, "file", 4))
                                        file = f->clientid > 100 ? 2 : 1;
                                else if (f->clientid <= 100 || name->utf8string_len != 7 ||
                                         memcmp(name->utf8string_val, "renamed", 7))
                                        status = NFS4ERR_NOENT;
                        }
                        break;
                case OP_ACCESS:
                        out->nfs_resop4_u.opaccess.ACCESS4res_u.resok4.supported =
                                arg->nfs_argop4_u.opaccess.access;
                        out->nfs_resop4_u.opaccess.ACCESS4res_u.resok4.access =
                                arg->nfs_argop4_u.opaccess.access;
                        break;
                case OP_REMOVE:
                        CHECK(!file, "REMOVE parent");
                        ++f->removes;
                        break;
                case OP_OPEN: {
                        const OPEN4args *open = &arg->nfs_argop4_u.opopen;
                        OPEN4resok *res = &out->nfs_resop4_u.opopen.OPEN4res_u.resok4;
                        CHECK(open->owner.clientid == f->clientid && !f->file_open &&
                              open->openhow.opentype == OPEN4_NOCREATE, "unexpected OPEN");
                        if (!f->opens && f->post_grace) {
                                f->post_grace--;
                                status = NFS4ERR_GRACE;
                                break;
                        }
                        CHECK(open->claim.claim == CLAIM_PREVIOUS ? !f->reclaim_complete : f->reclaim_complete,
                              "CLAIM_PREVIOUS must precede RECLAIM_COMPLETE; non-reclaim OPEN must follow it");
                        if (open->claim.claim == CLAIM_PREVIOUS || (f->opens && open->claim.claim == CLAIM_FH)) {
                                CHECK(file == 1, "recovery OPEN changed the original filehandle");
                                CHECK(call.body.cbody.cred.oa_length == f->open_cred_length &&
                                      !memcmp(call.body.cbody.cred.oa_base, f->open_cred, f->open_cred_length),
                                      "recovery OPEN used another caller's credentials");
                                CHECK(open->owner.owner.owner_len == f->open_owner_length &&
                                      !memcmp(open->owner.owner.owner_val, f->open_owner, f->open_owner_length) &&
                                      open->share_access == f->share_access && !open->share_deny,
                                      "recovery changed the OPEN owner/access");
                                ++f->reclaims;
                                if (f->reclaim_delays) {
                                        f->reclaim_delays--;
                                        status = NFS4ERR_DELAY;
                                        break;
                                }
                                if (f->no_grace && open->claim.claim == CLAIM_PREVIOUS) {
                                        status = NFS4ERR_NO_GRACE;
                                        break;
                                }
                                if (f->reclaim_error && open->claim.claim == CLAIM_PREVIOUS) {
                                        status = f->reclaim_error;
                                        break;
                                }
                                if (f->reopen_delays && open->claim.claim == CLAIM_FH) {
                                        f->reopen_delays--;
                                        status = NFS4ERR_GRACE;
                                        break;
                                }
                                if (f->reclaim_stale) {
                                        status = NFS4ERR_STALE;
                                        break;
                                }
                        } else {
                                f->open_cred_length = call.body.cbody.cred.oa_length;
                                f->open_owner_length = open->owner.owner.owner_len;
                                CHECK(f->open_cred_length <= sizeof(f->open_cred) &&
                                      f->open_owner_length <= sizeof(f->open_owner), "OPEN identity length");
                                memcpy(f->open_cred, call.body.cbody.cred.oa_base, f->open_cred_length);
                                memcpy(f->open_owner, open->owner.owner.owner_val, f->open_owner_length);
                                f->share_access = open->share_access;
                        }
                        f->open_state.seqid = 1;
                        memset(f->open_state.other, 0x35 + (f->reuse_stateid ? 0 : f->opens), sizeof(f->open_state.other));
                        res->stateid = f->open_state;
                        res->delegation.delegation_type = OPEN_DELEGATE_NONE;
                        f->file_open = file = 1;
                        ++f->opens;
                        break;
                }
                case OP_READ: {
                        const READ4args *read = &arg->nfs_argop4_u.opread;
                        READ4resok *res = &out->nfs_resop4_u.opread.READ4res_u.resok4;
                        CHECK(file && f->file_open &&
                              !memcmp(&read->stateid, &f->open_state, sizeof(stateid4)),
                              "READ did not preserve the open stateid");
                        if (f->standalone) {
                                uint64_t remaining = 8U * 1024U * 1024U;
                                CHECK(read->offset <= remaining, "READ offset past test data");
                                remaining -= read->offset;
                                res->data.data_len = read->count < 65536 ? read->count : 65536;
                                if (res->data.data_len > remaining)
                                        res->data.data_len = remaining;
                                res->eof = res->data.data_len == remaining;
                                res->data.data_val = f->contents + read->offset;
                        } else {
                                CHECK(read->offset == 0 && read->count >= 12, "READ extent");
                                res->eof = 1;
                                res->data.data_val = "file payload";
                                res->data.data_len = 12;
                        }
                        ++f->reads;
                        break;
                }
                case OP_WRITE: {
                        const WRITE4args *write = &arg->nfs_argop4_u.opwrite;
                        WRITE4resok *res = &out->nfs_resop4_u.opwrite.WRITE4res_u.resok4;
                        char *payload = NULL;
                        uint32_t payload_len = 0;
                        CHECK(file && f->file_open &&
                              !memcmp(&write->stateid, &f->open_state, sizeof(stateid4)), "WRITE stateid");
                        CHECK(zdr_bytes(&decoder, &payload, &payload_len, 4096), "WRITE payload");
                        if (f->standalone) {
                                CHECK(write->offset < 8U * 1024U * 1024U &&
                                      payload_len <= 8U * 1024U * 1024U - write->offset, "WRITE extent");
                                memcpy(f->contents + write->offset, payload, payload_len);
                        } else {
                                CHECK(payload_len == 12 && !memcmp(payload, "file payload", 12),
                                      "WRITE payload after stateid translation");
                        }
                        res->count = payload_len;
                        res->committed = UNSTABLE4;
                        memset(res->writeverf, 0x5a, sizeof(verifier4));
                        break;
                }
                case OP_COMMIT:
                        CHECK(file, "COMMIT filehandle");
                        memset(out->nfs_resop4_u.opcommit.COMMIT4res_u.resok4.writeverf,
                               f->verifier_change ? 0x6b : 0x5a, sizeof(verifier4));
                        break;
                case OP_LOCK: {
                        const LOCK4args *lock = &arg->nfs_argop4_u.oplock;
                        CHECK(file && f->file_open && !f->locked && !lock->reclaim &&
                              lock->locker.new_lock_owner && lock->offset == 0 && lock->length == 12 &&
                              !memcmp(&lock->locker.locker4_u.open_owner.open_stateid,
                                      &f->open_state, sizeof(stateid4)), "LOCK owner or extent");
                        f->lock_state.seqid = 1;
                        memset(f->lock_state.other, 0x46, sizeof(f->lock_state.other));
                        out->nfs_resop4_u.oplock.LOCK4res_u.resok4.lock_stateid = f->lock_state;
                        f->locked = 1;
                        break;
                }
                case OP_LOCKU: {
                        const LOCKU4args *unlock = &arg->nfs_argop4_u.oplocku;
                        CHECK(file && f->locked && unlock->offset == 0 && unlock->length == 12 &&
                              !memcmp(&unlock->lock_stateid, &f->lock_state, sizeof(stateid4)),
                              "session replacement lost the byte-range lock");
                        out->nfs_resop4_u.oplocku.LOCKU4res_u.lock_stateid = f->lock_state;
                        f->locked = 0;
                        break;
                }
                case OP_CLOSE:
                        CHECK(file && f->file_open && !f->locked &&
                              !memcmp(&arg->nfs_argop4_u.opclose.open_stateid,
                                      &f->open_state, sizeof(stateid4)), "CLOSE stateid");
                        out->nfs_resop4_u.opclose.CLOSE4res_u.open_stateid = f->open_state;
                        f->file_open = 0;
                        ++f->closes;
                        break;
                case OP_GETFH:
                        out->nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_val = file == 2 ? "newf" : file ? "file" : "root";
                        out->nfs_resop4_u.opgetfh.GETFH4res_u.resok4.object.nfs_fh4_len = 4;
                        break;
                case OP_READDIR: {
                        const READDIR4args *read = &arg->nfs_argop4_u.opreaddir;
                        READDIR4resok *res = &out->nfs_resop4_u.opreaddir.READDIR4res_u.resok4;
                        unsigned count = f->clientid > 100 ? 2 : 1, entry;
                        CHECK(f->standalone && !file && read->cookie <= count, "READDIR cookie");
                        for (entry = 0; entry < count; entry++) {
                                entries[entry].cookie = entry + 1;
                                entries[entry].name.utf8string_val = count == 2 && entry == 0 ? "renamed" : "file";
                                entries[entry].name.utf8string_len = strlen(entries[entry].name.utf8string_val);
                                mount_attributes(&read->attr_request, entry + 1, &entries[entry].attrs,
                                                  entry_masks[entry], entry_attributes[entry]);
                                if (entry + 1 < count)
                                        entries[entry].nextentry = &entries[entry + 1];
                        }
                        res->reply.entries = read->cookie < count ? &entries[read->cookie] : NULL;
                        res->reply.eof = 1;
                        break;
                }
                case OP_GETATTR: {
                        const bitmap4 *wanted = &arg->nfs_argop4_u.opgetattr.attr_request;
                        fattr4 *attr = &out->nfs_resop4_u.opgetattr.GETATTR4res_u.resok4.obj_attributes;
                        uint32_t type = file ? NF4REG : NF4DIR;
                        uint64_t maximum = 4096;
                        ZDR attr_encoder;
                        CHECK(wanted->bitmap4_len, "empty GETATTR bitmap");
                        zdrmem_create(&attr_encoder, attributes[i], sizeof(attributes[i]), ZDR_ENCODE);
                        if (wanted->bitmap4_val[0] & (1U << FATTR4_MAXREAD)) {
                                bitmaps[i] = (1U << FATTR4_MAXREAD) | (1U << FATTR4_MAXWRITE);
                                CHECK(zdr_uint64_t(&attr_encoder, &maximum) && zdr_uint64_t(&attr_encoder, &maximum), "encode rwmax");
                        } else if (f->standalone) {
                                zdr_destroy(&attr_encoder);
                                mount_attributes(wanted, file, attr, mount_masks[i], attributes[i]);
                                break;
                        } else {
                                bitmaps[i] = 1U << FATTR4_TYPE;
                                CHECK(zdr_uint32_t(&attr_encoder, &type), "encode type");
                        }
                        attr->attrmask.bitmap4_len = 1;
                        attr->attrmask.bitmap4_val = &bitmaps[i];
                        attr->attr_vals.attrlist4_val = attributes[i];
                        attr->attr_vals.attrlist4_len = zdr_getpos(&attr_encoder);
                        zdr_destroy(&attr_encoder);
                        break;
                }
                default:
                        status = session_op(f, arg, out);
                }
                /* All operation result unions begin with nfsstat4. */
                memcpy(&out->nfs_resop4_u, &status, sizeof(status));
                ++result.resarray.resarray_len;
                result.status = status;
                if (status != NFS4_OK) {
                        ++f->rejections;
                        break;
                }
        }
        if (result.status == NFS4ERR_DELAY && result.resarray.resarray_len == 1 &&
            ops[0].resop == OP_SEQUENCE) {
                f->delayed_length = size;
                memcpy(f->delayed_request, request, size);
        }
        if (result.status == NFS4ERR_DELAY && result.resarray.resarray_len == 1 &&
            ops[0].resop == OP_CREATE_SESSION) {
                f->create_request_length = size;
                memcpy(f->create_request, request, size);
        }
        if (f->drop_mutation_reply && result.status == NFS4_OK &&
            result.resarray.resarray_len && ops[result.resarray.resarray_len - 1].resop == OP_REMOVE) {
                f->drop_mutation_reply = 0;
                f->valid = 0;
                f->nfs->rpc->nfs4_renew_due = rpc_current_time() - 1;
                zdr_destroy(&decoder);
                return;
        }
reply:
        response.xid = call.xid;
        response.direction = REPLY;
        response.body.rbody.stat = MSG_ACCEPTED;
        response.body.rbody.reply.areply.stat = SUCCESS;
        response.body.rbody.reply.areply.reply_data.results.where = (char *)&result;
        response.body.rbody.reply.areply.reply_data.results.proc =
                call.body.cbody.proc == NFSPROC4_NULL ? (zdrproc_t)zdr_void : (zdrproc_t)zdr_COMPOUND4res;
        zdrmem_create(&encoder, reply, sizeof(reply), ZDR_ENCODE);
        CHECK(zdr_replymsg(f->nfs->rpc, &encoder, &response), "encode RPC reply");
        if (result.status == NFS4_OK && result.resarray.resarray_len &&
            ops[result.resarray.resarray_len - 1].resop == OP_READ) {
                /* libnfs leaves the READ data to the caller's zero-copy path. */
                READ4resok *res = &ops[result.resarray.resarray_len - 1].nfs_resop4_u.opread.READ4res_u.resok4;
                char *payload = res->data.data_val;
                uint32_t count = res->data.data_len;
                CHECK(zdr_bytes(&encoder, &payload, &count, count), "encode READ payload");
        }
        size = zdr_getpos(&encoder);
        marker = htonl(size | 0x80000000U);
        transfer(f->peer, &marker, 4, 1);
        transfer(f->peer, reply, size, 1);
        if (f->standalone)
                fprintf(stderr, "RESULT %u: %u\n", f->requests, result.status);
        zdr_destroy(&encoder);
        zdr_destroy(&decoder);
}

static void
step(struct fixture *f)
{
        struct pollfd fds[3] = {
                {f->threaded ? -1 : nfs_get_fd(f->nfs), f->threaded ? 0 : nfs_which_events(f->nfs), 0},
                {f->listener, POLLIN, 0},
                {f->peer, POLLIN, 0}
        };
        struct timeval timeout = {.tv_sec = 2};
        int ret, one = 1;
        CHECK(rpc_current_time() < f->deadline, "%s: recovery deadline exceeded", f->name);
        ret = poll(fds, 3, 10);
        if (ret < 0 && errno == EINTR)
                return;
        CHECK(ret >= 0, "poll: %s", strerror(errno));
        if (!f->threaded)
                CHECK(nfs_service(f->nfs, fds[0].revents) == 0, "nfs_service: %s", nfs_get_error(f->nfs));
        if (fds[2].revents & (POLLIN | POLLHUP)) {
                char byte;
                ssize_t available = recv(f->peer, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
                if (available == 0 || (available < 0 && errno == ECONNRESET)) {
                        close(f->peer);
                        f->peer = -1;
                } else if (available > 0) {
                        do {
                                serve(f);
                                available = recv(f->peer, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
                        } while (available > 0);
                } else {
                        CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR,
                              "peek peer: %s", strerror(errno));
                }
        }
        if ((fds[1].revents & POLLIN) && f->peer == -1) {
                f->peer = accept(f->listener, NULL, NULL);
                CHECK(f->peer >= 0, "accept: %s", strerror(errno));
                CHECK(!setsockopt(f->peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
                      !setsockopt(f->peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) &&
                      !setsockopt(f->peer, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)), "peer socket options");
        }
        if (f->drop_when_delayed && f->nfs->rpc->nfs4_delay_queue_len) {
                close(f->peer);
                f->peer = -1;
                f->drop_when_delayed = 0;
        }
}

static void
probe(struct fixture *f)
{
        struct completion cb = {0};
        CHECK(!nfs_stat64_async(f->nfs, "/", stat_complete, &cb), "submit post-fault stat");
        while (!cb.calls)
                step(f);
        CHECK(cb.status == 0 && S_ISDIR(cb.attributes.nfs_mode),
              "%s: stat after fault returned %d", f->name, cb.status);
        CHECK(rpc_nfs4_session_is_valid(f->nfs->rpc), "stat completed without a valid session");
}

static void
read_probe(struct fixture *f, struct nfsfh *fh)
{
        struct completion cb = {0};
        char payload[32];
        memset(payload, 0xa5, sizeof(payload));
        CHECK(!nfs_pread_async(f->nfs, fh, payload, sizeof(payload), 0, complete, &cb),
              "submit READ on held handle");
        while (!cb.calls)
                step(f);
        CHECK(cb.status == 12 && !memcmp(payload, "file payload", 12) &&
              (unsigned char)payload[12] == 0xa5, "held handle READ payload");
}

static void
lock_file(struct fixture *f, struct nfsfh *fh, int unlock)
{
        struct completion cb = {0};
        CHECK(!nfs_lockf_async(f->nfs, fh, unlock ? NFS4_F_ULOCK : NFS4_F_TLOCK,
                              12, complete, &cb), "submit lock operation");
        while (!cb.calls)
                step(f);
        CHECK(!cb.status && f->locked == !unlock, "lock completion");
}

static void
concurrent_probe(struct fixture *f)
{
        struct completion pending[24] = {0};
        unsigned i, completed;
        for (i = 0; i < 24; i++)
                CHECK(!nfs_stat64_async(f->nfs, "/", stat_complete, &pending[i]), "queue concurrent stat");
        do {
                step(f);
                for (i = completed = 0; i < 24; i++)
                        completed += pending[i].calls;
        } while (completed < 24);
        for (i = 0; i < 24; i++)
                CHECK(!pending[i].status && S_ISDIR(pending[i].attributes.nfs_mode),
                      "concurrent stat %u failed", i);
}

/* The same strict wire peer can drive a real, separately supervised FUSE
 * mount. Its control channel changes only this peer's client/session state. */
static int
serve_mount(void)
{
        struct fixture f = {.listener = -1, .peer = -1, .clientid = 100,
                            .create_sequence = 1, .standalone = 1, .name = "mount"};
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        struct timeval timeout = {.tv_sec = 2};
        socklen_t length = sizeof(addr);
        int stop = 0, one = 1;

        f.contents = malloc(8U * 1024U * 1024U);
        CHECK(f.contents, "test data allocation");
        memset(f.contents, 'a', 8U * 1024U * 1024U);
        f.nfs = nfs_init_context();
        f.listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(f.nfs && f.listener >= 0 && !bind(f.listener, (struct sockaddr *)&addr, sizeof(addr)) &&
              !listen(f.listener, 4) && !getsockname(f.listener, (struct sockaddr *)&addr, &length), "mount peer listener");
        printf("PORT %u\n", ntohs(addr.sin_port));
        fflush(stdout);
        while (!stop) {
                struct pollfd fds[3] = {{STDIN_FILENO, POLLIN, 0}, {f.listener, POLLIN, 0}, {f.peer, POLLIN, 0}};
                int ret = poll(fds, 3, 1000);
                if (ret < 0 && errno == EINTR)
                        continue;
                CHECK(ret >= 0, "mount peer poll");
                if (fds[0].revents & (POLLIN | POLLHUP)) {
                        char command[32];
                        if (!fgets(command, sizeof(command), stdin) || !strcmp(command, "STOP\n")) {
                                stop = 1;
                        } else if (!strcmp(command, "REBOOT\n") || !strcmp(command, "REBOOT_NOGRACE\n")) {
                                ++f.clientid;
                                f.create_sequence = 1;
                                f.valid = f.file_open = f.locked = f.reclaim_complete = 0;
                                f.no_grace = !strcmp(command, "REBOOT_NOGRACE\n");
                                printf("RESET %llu\n", (unsigned long long)f.clientid);
                        } else {
                                CHECK(!strcmp(command, "STATS\n"), "mount peer control command");
                                printf("STATS %u %u %u %u %u %u\n", f.exchanges, f.creates,
                                       f.reclaims, f.reads, f.closes, f.rejections);
                        }
                        fflush(stdout);
                }
                if (fds[2].revents & (POLLIN | POLLHUP)) {
                        char byte;
                        ssize_t count = recv(f.peer, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
                        if (!count || (count < 0 && errno == ECONNRESET)) {
                                close(f.peer);
                                f.peer = -1;
                        } else if (count > 0) {
                                serve(&f);
                        }
                }
                if ((fds[1].revents & POLLIN) && f.peer == -1) {
                        f.peer = accept(f.listener, NULL, NULL);
                        CHECK(f.peer >= 0 && !setsockopt(f.peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
                              !setsockopt(f.peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) &&
                              !setsockopt(f.peer, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)), "mount peer accept");
                }
        }
        if (f.peer >= 0)
                close(f.peer);
        close(f.listener);
        nfs_destroy_context(f.nfs);
        free(f.contents);
        return 0;
}

int main(int argc, char **argv)
{
        const struct scenario scenarios[] = {
                {.name = "renew-ok"},
                {.name = "renew-delay", .delays = 1},
                {.name = "renew-lost", .session_lost = 1},
                {.name = "reboot-renew", .session_lost = 1, .reboot = 1},
                {.name = "rebind-ok", .reconnect = 1},
                {.name = "reboot-rebind", .session_lost = 1, .reboot = 1, .reconnect = 1},
                {.name = "active-lost", .session_lost = 1, .active = 1},
                {.name = "renew-delay-repeat", .delays = 3},
                {.name = "renew-delay-reconnect", .delays = 1, .drop_when_delayed = 1},
                {.name = "renew-delay-destroy", .delays = 1, .destroy_when_delayed = 1},
                {.name = "renew-lost-credentials", .session_lost = 1, .switch_uid = 1},
                {.name = "active-lost-credentials", .session_lost = 1, .active = 1, .switch_uid = 1},
                {.name = "renew-lost-open", .session_lost = 1, .open_file = 1},
                {.name = "active-lost-read", .session_lost = 1, .active = 1, .open_file = 1},
                {.name = "renew-lost-lock", .session_lost = 1, .open_file = 1, .lock_file = 1},
                {.name = "active-lost-repeat", .session_lost = 1, .active = 1, .repeat = 1},
                {.name = "active-lost-concurrent", .session_lost = 1, .active = 1, .concurrent = 1},
                {.name = "recovery-cancel", .session_lost = 1, .active = 1, .cancel = 1},
                {.name = "recovery-destroy", .session_lost = 1, .active = 1, .destroy = 1},
                {.name = "recovery-create-delay", .session_lost = 1, .create_delays = 3},
                {.name = "recovery-create-delay-reconnect", .session_lost = 1, .create_delays = 1, .drop_when_delayed = 1},
                {.name = "lost-mutation-reply", .session_lost = 1, .active = 1, .lost_mutation_reply = 1},
                {.name = "reboot-open", .session_lost = 1, .reboot = 1, .open_file = 1},
                {.name = "reboot-active-read", .session_lost = 1, .reboot = 1, .open_file = 1, .active = 1},
                {.name = "reboot-open-credentials", .session_lost = 1, .reboot = 1, .open_file = 1, .switch_uid = 1},
                {.name = "reboot-open-no-grace", .session_lost = 1, .reboot = 1, .open_file = 1, .no_grace = 1},
                {.name = "reboot-no-grace-delay", .session_lost = 1, .reboot = 1, .open_file = 1, .no_grace = 1, .reopen_delays = 10},
                {.name = "reboot-no-grace-stale", .session_lost = 1, .reboot = 1, .open_file = 1, .no_grace = 1, .reclaim_stale = 1},
                {.name = "reboot-no-grace-session-loss", .session_lost = 1, .reboot = 1, .open_file = 1, .no_grace = 1, .reclaim_loss = LOSS_REOPEN},
                {.name = "reboot-no-grace-reboot", .session_lost = 1, .reboot = 1, .open_file = 1, .no_grace = 1, .reclaim_loss = LOSS_REOPEN, .reclaim_reboot = 1},
                {.name = "reboot-no-grace-complete-loss", .session_lost = 1, .reboot = 1, .open_file = 1, .no_grace = 1, .reclaim_loss = LOSS_COMPLETE},
                {.name = "reboot-no-grace-close", .session_lost = 1, .reboot = 1, .open_file = 1, .active = 1, .no_grace = 1, .reopen_delays = 1, .reclaim_close = 1},
                {.name = "reboot-no-grace-destroy", .session_lost = 1, .reboot = 1, .open_file = 1, .active = 1, .no_grace = 1, .reopen_delays = 1, .reclaim_destroy = 1},
                {.name = "reboot-no-grace-threaded", .session_lost = 1, .reboot = 1, .open_file = 1, .active = 1, .no_grace = 1, .threaded = 1},
                {.name = "reboot-reclaim-bad", .session_lost = 1, .reboot = 1, .open_file = 1, .reclaim_error = NFS4ERR_RECLAIM_BAD},
                {.name = "reboot-reclaim-conflict", .session_lost = 1, .reboot = 1, .open_file = 1, .reclaim_error = NFS4ERR_RECLAIM_CONFLICT},
                {.name = "reboot-open-stale", .session_lost = 1, .reboot = 1, .open_file = 1, .reclaim_stale = 1},
                {.name = "reboot-dirty-open", .session_lost = 1, .reboot = 1, .open_file = 1, .dirty = 1},
                {.name = "reboot-fsynced-open", .session_lost = 1, .reboot = 1, .open_file = 1, .dirty = 1, .fsync_before_reboot = 1},
                {.name = "reboot-lock-lost", .session_lost = 1, .reboot = 1, .open_file = 1, .lock_file = 1},
                {.name = "reboot-new-open", .session_lost = 1, .reboot = 1, .active = 1, .new_open = 1},
                {.name = "reboot-rejected-mutation", .session_lost = 1, .reboot = 1, .active = 1, .rejected_mutation = 1},
                {.name = "reboot-active-write", .session_lost = 1, .reboot = 1, .active = 1, .open_file = 1, .active_write = 1},
                {.name = "reboot-open-other-uid", .session_lost = 1, .reboot = 1, .open_file = 1, .open_uid = 1},
                {.name = "reboot-reclaim-delay", .session_lost = 1, .reboot = 1, .open_file = 1, .reclaim_delays = 3},
                {.name = "reboot-create-long-delay", .session_lost = 1, .reboot = 1, .create_delays = 10},
                {.name = "reboot-post-grace", .session_lost = 1, .reboot = 1, .active = 1, .new_open = 1, .post_grace = 10},
                {.name = "commit-verifier-change", .open_file = 1, .dirty = 1, .fsync_before_reboot = 1, .verifier_change = 1},
                {.name = "reboot-threaded-read", .session_lost = 1, .reboot = 1, .active = 1, .open_file = 1, .threaded = 1},
                {.name = "reboot-new-open-after-loss", .session_lost = 1, .reboot = 1, .open_file = 1, .dirty = 1, .new_after_loss = 1},
                {.name = "reboot-reclaim-destroy", .session_lost = 1, .reboot = 1, .open_file = 1, .active = 1, .reclaim_delays = 1, .reclaim_destroy = 1},
                {.name = "reboot-reclaim-close", .session_lost = 1, .reboot = 1, .open_file = 1, .active = 1, .reclaim_delays = 1, .reclaim_close = 1},
                {.name = "reboot-reclaim-session-loss", .session_lost = 1, .reboot = 1, .open_file = 1, .reclaim_loss = LOSS_RECLAIM},
                {.name = "reboot-reclaim-reboot", .session_lost = 1, .reboot = 1, .open_file = 1, .reclaim_loss = LOSS_RECLAIM, .reclaim_reboot = 1},
                {.name = "reboot-held-repeat", .session_lost = 1, .reboot = 1, .open_file = 1, .repeat = 1}
        };
        const struct scenario *scenario;
        struct fixture f = {.listener = -1, .peer = -1, .clientid = 100, .create_sequence = 1};
        struct completion mount = {0};
        struct completion opened = {0}, closed = {0};
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t length = sizeof(addr);
        unsigned index;
        int lost_state;

        if (argc == 2 && !strcmp(argv[1], "--serve"))
                return serve_mount();
        if (argc == 1) {
                int failed = 0;
                for (index = 0; index < sizeof(scenarios) / sizeof(*scenarios); index++) {
                        int status;
                        pid_t child = fork(), waited;
                        CHECK(child >= 0, "fork: %s", strerror(errno));
                        if (!child) {
                                execl(argv[0], argv[0], scenarios[index].name, (char *)NULL);
                                _exit(127);
                        }
                        do {
                                waited = waitpid(child, &status, 0);
                        } while (waited < 0 && errno == EINTR);
                        CHECK(waited == child, "waitpid: %s", strerror(errno));
                        if (!WIFEXITED(status) || (WEXITSTATUS(status) && WEXITSTATUS(status) != 77))
                                failed = 1;
                }
                return failed;
        }
        CHECK(argc == 2, "expected one scenario argument");
        for (index = 0; index < sizeof(scenarios) / sizeof(*scenarios); index++)
                if (!strcmp(argv[1], scenarios[index].name))
                        break;
        CHECK(index < sizeof(scenarios) / sizeof(*scenarios), "unknown scenario %s", argv[1]);
        scenario = &scenarios[index];
#if !defined(HAVE_MULTITHREADING) || !defined(HAVE_STDATOMIC_H)
        if (scenario->threaded) {
                puts("SKIP: threaded recovery requires pthread and C atomics");
                return 77;
        }
#endif
        lost_state = scenario->verifier_change || (scenario->reboot && (scenario->lock_file ||
                (scenario->dirty && !scenario->fsync_before_reboot)));
        f.name = scenario->name;
        f.reuse_stateid = scenario->new_after_loss;
        f.deadline = rpc_current_time() + 20000;
        f.listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(f.listener >= 0 && !bind(f.listener, (struct sockaddr *)&addr, sizeof(addr)) &&
              !listen(f.listener, 4) && !getsockname(f.listener, (struct sockaddr *)&addr, &length), "loopback listener");
        f.nfs = nfs_init_context();
        CHECK(f.nfs && !nfs_set_version(f.nfs, NFS_V4_2), "NFSv4.2 context");
        nfs_set_nfsport(f.nfs, ntohs(addr.sin_port));
        nfs_set_autoreconnect(f.nfs, -1);
        CHECK(!nfs_mount_async(f.nfs, "127.0.0.1", "/", complete, &mount), "submit initial mount");
        while (!mount.calls)
                step(&f);
        CHECK(!mount.status && f.creates == 1 && f.valid, "initial mount did not establish a session");
        probe(&f);

        if (scenario->open_file) {
                if (scenario->open_uid) {
                        nfs_set_uid(f.nfs, 21111);
                        nfs_set_gid(f.nfs, 21111);
                }
                CHECK(!nfs_open_async(f.nfs, "/file", scenario->lock_file || scenario->dirty || scenario->active_write ? O_RDWR : O_RDONLY,
                                      open_complete, &opened), "submit OPEN");
                while (!opened.calls)
                        step(&f);
                CHECK(!opened.status && opened.fh, "initial OPEN");
                read_probe(&f, opened.fh);
                if (scenario->lock_file)
                        lock_file(&f, opened.fh, 0);
                if (scenario->dirty) {
                        struct completion written = {0}, synced = {0};
                        CHECK(!nfs_pwrite_async(f.nfs, opened.fh, "file payload", 12, 0,
                                               complete, &written), "submit unstable WRITE");
                        while (!written.calls)
                                step(&f);
                        CHECK(written.status == 12, "unstable WRITE result");
                        if (scenario->fsync_before_reboot) {
                                f.verifier_change = scenario->verifier_change;
                                CHECK(!nfs_fsync_async(f.nfs, opened.fh, complete, &synced), "submit pre-reboot fsync");
                                while (!synced.calls)
                                        step(&f);
                                CHECK(synced.status == (scenario->verifier_change ? -EIO : 0), "pre-reboot fsync/verifier");
                        }
                }
        }
        if (scenario->open_uid) {
                nfs_set_uid(f.nfs, 1001);
                nfs_set_gid(f.nfs, 1001);
        }
        if (scenario->switch_uid) {
                nfs_set_uid(f.nfs, 21111);
                nfs_set_gid(f.nfs, 21111);
        }
        if (scenario->threaded) {
#if defined(HAVE_MULTITHREADING) && defined(HAVE_STDATOMIC_H)
                CHECK(!nfs_mt_service_thread_start(f.nfs), "start real service thread");
                f.threaded = 1;
#else
                CHECK(0, "threaded recovery requires pthread and C atomics");
#endif
        }

        if (scenario->session_lost && !scenario->lost_mutation_reply)
                f.valid = 0;
        if (scenario->reboot) {
                ++f.clientid;
                f.create_sequence = 1;
                f.file_open = f.locked = f.reclaim_complete = 0;
                f.no_grace = scenario->no_grace;
                f.reclaim_error = scenario->reclaim_error;
                f.reopen_delays = scenario->reopen_delays;
                f.reclaim_stale = scenario->reclaim_stale;
                f.reclaim_delays = scenario->reclaim_delays;
                f.post_grace = scenario->post_grace;
                f.reclaim_loss = scenario->reclaim_loss;
                f.reclaim_reboot = scenario->reclaim_reboot;
        }
        f.create_delays = scenario->create_delays;
        f.delay = scenario->delays;
        f.drop_when_delayed = scenario->drop_when_delayed;
        if (scenario->reconnect) {
                close(f.peer);
                f.peer = -1;
                while (!f.binds || rpc_queue_length(f.nfs->rpc))
                        step(&f);
        } else if (!scenario->active) {
                /* Exercise the real idle callback without waiting thirty seconds. */
                f.nfs->rpc->nfs4_renew_due = rpc_current_time() - 1;
                while (!f.renews || rpc_queue_length(f.nfs->rpc)) {
                        step(&f);
                        if (scenario->destroy_when_delayed && f.nfs->rpc->nfs4_delay_queue_len) {
                                nfs_destroy_context(f.nfs);
                                close(f.peer);
                                close(f.listener);
                                puts("PASS: destroy during keepalive backoff");
                                return 0;
                        }
                }
        }
        CHECK(!scenario->destroy_when_delayed, "no keepalive backoff to destroy");
        if (scenario->new_open) {
                CHECK(!nfs_open_async(f.nfs, "/file", O_RDONLY, open_complete, &opened), "OPEN during outage");
                while (!opened.calls)
                        step(&f);
                CHECK(!opened.status && opened.fh && f.opens == 1, "OPEN during client recovery");
                read_probe(&f, opened.fh);
                CHECK(!nfs_close_async(f.nfs, opened.fh, complete, &closed), "close new OPEN");
                while (!closed.calls)
                        step(&f);
                CHECK(!closed.status, "close new OPEN result");
        }
        if (scenario->rejected_mutation) {
                struct completion removed = {0};
                CHECK(!nfs_unlink_async(f.nfs, "/file", complete, &removed), "REMOVE during outage");
                while (!removed.calls)
                        step(&f);
                CHECK(!removed.status && f.removes == 1, "rejected mutation did not run exactly once after recovery");
        }
        if (scenario->lost_mutation_reply) {
                struct mutation_completion cb = {0};
#ifdef HAVE_MULTITHREADING
                /* Exercise the queue mutex without a second service-loop owner. */
                f.nfs->rpc->multithreading_enabled = 1;
#endif
                f.drop_mutation_reply = 1;
                CHECK(!nfs_unlink_async(f.nfs, "/file", mutation_complete, &cb), "submit mutation");
                while (!cb.mutation.calls || !cb.followup.calls)
                        step(&f);
                CHECK(!cb.followup.status && f.removes == 1 && !f.drop_mutation_reply,
                      "mutation replayed or recovery callback deadlocked");
        }
        if (scenario->cancel || scenario->destroy) {
                struct completion cancelled = {0};
                struct rpc_pdu *pending = rpc_nfs4_renew_session_task(f.nfs->rpc, raw_complete, &cancelled);
                CHECK(pending, "submit request to cancel during recovery");
                while (!f.nfs->rpc->nfs4_delay_queue_len)
                        step(&f);
                if (scenario->destroy) {
                        nfs_destroy_context(f.nfs);
                        CHECK(cancelled.calls == 1 && cancelled.status == RPC_STATUS_CANCEL,
                              "destroy did not cancel the deferred request exactly once");
                        close(f.peer);
                        close(f.listener);
                        puts("PASS: destroy during session recovery");
                        return 0;
                }
                CHECK(!rpc_cancel_pdu(f.nfs->rpc, pending) && !cancelled.calls,
                      "cancel during session recovery");
                probe(&f);
                CHECK(!cancelled.calls, "cancelled callback fired after recovery");
        }
        if (scenario->concurrent)
                concurrent_probe(&f);
        if (scenario->reclaim_destroy || scenario->reclaim_close) {
                struct completion pending = {0};
                char payload[32];
                CHECK(!nfs_pread_async(f.nfs, opened.fh, payload, sizeof(payload), 0,
                                      complete, &pending), "queue READ before reclaim");
                while (!f.reclaims || !f.nfs->rpc->nfs4_delay_queue_len)
                        step(&f);
                if (scenario->reclaim_destroy) {
                        nfs_destroy_context(f.nfs);
                        CHECK(pending.calls == 1 && pending.status < 0,
                              "destroy during reclaim did not cancel the held READ exactly once");
                        close(f.peer);
                        close(f.listener);
                        puts("PASS: destroy with pending reclaim OPEN and held READ");
                        return 0;
                }
                CHECK(!nfs_close_async(f.nfs, opened.fh, complete, &closed), "CLOSE during reclaim");
                while (!pending.calls || !closed.calls)
                        step(&f);
                CHECK(pending.status == 12 && !memcmp(payload, "file payload", 12) &&
                      !closed.status && !f.file_open && f.opens == 2 && f.closes == 1,
                      "CLOSE during reclaim lost an operation or leaked remote state");
                goto after_open;
        }
        if (scenario->open_file) {
                if (scenario->active_write) {
                        struct completion written = {0}, synced = {0};
                        CHECK(!nfs_pwrite_async(f.nfs, opened.fh, "file payload", 12, 0,
                                               complete, &written), "WRITE during recovery");
                        while (!written.calls)
                                step(&f);
                        CHECK(written.status == 12, "WRITE was not resumed on reclaimed state");
                        CHECK(!nfs_fsync_async(f.nfs, opened.fh, complete, &synced), "fsync recovered WRITE");
                        while (!synced.calls)
                                step(&f);
                        CHECK(!synced.status, "fsync recovered WRITE result");
                }
                if (scenario->reclaim_stale || lost_state) {
                        struct completion read = {0};
                        char buffer[16];
                        if (scenario->new_after_loss) {
                                struct completion fresh = {0}, synced = {0}, released = {0};
                                CHECK(!nfs_open_async(f.nfs, "/file", O_RDWR, open_complete, &fresh),
                                      "open same object while lost descriptor is still held");
                                while (!fresh.calls)
                                        step(&f);
                                CHECK(!fresh.status && fresh.fh, "new open after lost state");
                                read_probe(&f, fresh.fh);
                                CHECK(!nfs_fsync_async(f.nfs, fresh.fh, complete, &synced), "fsync new open");
                                while (!synced.calls)
                                        step(&f);
                                CHECK(!synced.status, "old descriptor poisoned fsync on the new open");
                                CHECK(!nfs_close_async(f.nfs, fresh.fh, complete, &released), "close new open");
                                while (!released.calls)
                                        step(&f);
                                CHECK(!released.status, "close new open result");
                        }
                        CHECK(!nfs_pread_async(f.nfs, opened.fh, buffer, sizeof(buffer), 0,
                                              complete, &read), "submit stale READ");
                        while (!read.calls)
                                step(&f);
                        CHECK(read.status == (lost_state ? -EIO : -ESTALE) &&
                              f.reads == (scenario->new_after_loss ? 2U : 1U),
                              "unrecoverable file was silently reopened/read");
                        if (lost_state) {
                                struct completion synced = {0};
                                CHECK(!nfs_fsync_async(f.nfs, opened.fh, complete, &synced), "submit lost-state fsync");
                                while (!synced.calls)
                                        step(&f);
                                CHECK(synced.status == -EIO, "fsync silently accepted lost data/locks");
                        }
                } else {
                        read_probe(&f, opened.fh);
                        if (scenario->repeat) {
                                f.valid = 0;
                                ++f.clientid;
                                f.create_sequence = 1;
                                f.file_open = f.locked = f.reclaim_complete = 0;
                                read_probe(&f, opened.fh);
                        }
                }
                if (scenario->lock_file && !lost_state)
                        lock_file(&f, opened.fh, 1);
                CHECK(!nfs_close_async(f.nfs, opened.fh, complete, &closed), "submit CLOSE");
                while (!closed.calls)
                        step(&f);
                if (scenario->reclaim_stale || lost_state) {
                        CHECK(closed.status == (lost_state ? -EIO : -ESTALE) &&
                              f.opens == (scenario->new_after_loss ? 2U : 1U) &&
                              f.closes == (scenario->verifier_change || scenario->new_after_loss ? 1U : 0U),
                              "CLOSE of stale open");
                } else {
                        CHECK(!closed.status && f.opens == (scenario->repeat ? 3U : scenario->reboot ? 2U : 1U) &&
                              f.reads == (scenario->repeat ? 3U : 2U) && f.closes == 1 && !f.file_open,
                              "open state lifetime across session/client replacement");
                }
                if (scenario->reboot)
                        CHECK((lost_state || f.reclaims > 0) && f.reclaim_complete, "reclaim ordering");
        }
after_open:
        probe(&f);
        if (scenario->repeat && !scenario->open_file) {
                f.valid = 0;
                probe(&f);
                CHECK(f.creates == 3, "second session loss was not recovered");
        }
        CHECK(mount.calls == 1, "recovery repeated the mount completion");
#ifdef HAVE_MULTITHREADING
        if (f.threaded) {
                nfs_mt_service_thread_stop(f.nfs);
                f.threaded = 0;
        }
#endif
        CHECK(!rpc_queue_length(f.nfs->rpc) && !f.nfs->rpc->nfs4_slots_in_use, "requests or slots left outstanding");
        if (!scenario->session_lost)
                CHECK(f.creates == 1, "surviving session was needlessly replaced");
        else
                CHECK(f.creates > 1 && f.rejections > 0, "session loss was not exercised and recovered");
        if (scenario->reboot)
                CHECK(f.exchanges > 1, "server reboot did not establish a new clientid");
        if (scenario->drop_when_delayed && !scenario->create_delays)
                CHECK(!f.drop_when_delayed && f.binds == 1, "reconnect during backoff was not exercised");
        if (scenario->delays)
                CHECK(!f.delayed_length && f.rejections == (unsigned)scenario->delays,
                      "keepalive DELAY was not exercised and completed");
        if (scenario->create_delays)
                CHECK(!f.create_delays && !f.create_request_length &&
                      (!scenario->drop_when_delayed || !f.drop_when_delayed),
                      "CREATE_SESSION DELAY was not exercised and completed");
        CHECK(!f.reclaim_delays && !f.post_grace && !f.reopen_delays, "recovery/grace backoff did not complete");
        CHECK(f.reclaim_faults == (unsigned)!!scenario->reclaim_loss, "session loss during reclaim was not exercised");
        nfs_destroy_context(f.nfs);
        close(f.peer);
        close(f.listener);
        printf("PASS: %s (%u RPCs, %u sessions, %u rejections)\n", f.name, f.requests, f.creates, f.rejections);
        return 0;
}
#endif
