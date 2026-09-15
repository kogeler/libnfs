/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Slot ownership across session replacement, without a server. */
#include "config.h"
#ifndef HAVE_NFS4_2
int main(void) { return 77; }
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"

#define CHECK(expr, message) do { if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", message); exit(1); \
} } while (0)

static void
unexpected_callback(struct rpc_context *rpc, int status, void *data, void *opaque)
{
        (void)rpc;
        (void)status;
        (void)data;
        (void)opaque;
        CHECK(0, "cancelled slot fixture invoked its callback");
}

static struct rpc_pdu *
take_slot(struct rpc_context *rpc)
{
        struct rpc_pdu *pdu = rpc_nfs4_renew_session_task(rpc, unexpected_callback, NULL);

        CHECK(pdu != NULL, "allocate SEQUENCE request");
        CHECK(nfs4_pdu_take_slot(rpc, pdu) == 0, "take slot");
        CHECK(pdu->nfs4_slot_held, "request owns its slot");
        return pdu;
}

static void
same_session(void)
{
        struct rpc_context *rpc = rpc_init_context();
        struct rpc_pdu *pdu, *waiting;
        sessionid4 id = {1};

        CHECK(rpc != NULL, "allocate context");
        rpc->nfs4_minorversion = 2;
        CHECK(nfs4_session_init(rpc, id, 1) == 0, "initialize session");
        pdu = take_slot(rpc);
        waiting = rpc_nfs4_renew_session_task(rpc, unexpected_callback, NULL);
        CHECK(waiting != NULL, "queue request while all slots are busy");
        CHECK(nfs4_pdu_take_slot(rpc, waiting) == -1, "slot exhaustion");
        CHECK(rpc_cancel_pdu(rpc, pdu) == 0, "cancel unsent request");
        CHECK(rpc->nfs4_slots_in_use == 0 && rpc->nfs4_slots[0].seqid == 0,
              "unsent request rolls back sequence");
        CHECK(nfs4_pdu_take_slot(rpc, waiting) == 0, "waiting request takes released slot");
        waiting->nfs4_slot_sent = 1;
        CHECK(rpc_cancel_pdu(rpc, waiting) == 0, "cancel sent request");
        CHECK(rpc->nfs4_slots_in_use == 0 && rpc->nfs4_slots[0].seqid == 1,
              "sent request does not roll back sequence");
        pdu = take_slot(rpc);
        CHECK(rpc->nfs4_slots[0].seqid == 2, "next request advances sequence");
        CHECK(rpc_cancel_pdu(rpc, pdu) == 0, "cancel final request");
        CHECK(rpc_queue_length(rpc) == 0, "all requests removed");
        rpc_destroy_context(rpc);
        puts("PASS: same-session slot release and rollback");
}

static void
replacement(int sent, int destroy, int reuse_id)
{
        struct rpc_context *rpc = rpc_init_context();
        struct rpc_pdu *old, *current, *next;
        sessionid4 id = {1};

        CHECK(rpc != NULL, "allocate context");
        rpc->nfs4_minorversion = 2;
        CHECK(nfs4_session_init(rpc, id, 2) == 0, "initialize old session");
        old = take_slot(rpc);
        old->nfs4_slot_sent = sent;
        if (destroy)
                nfs4_session_destroy(rpc);
        if (!reuse_id)
                id[0]++;
        CHECK(nfs4_session_init(rpc, id, 1) == 0, "replace session with smaller slot table");
        current = take_slot(rpc);
        CHECK(old->nfs4_slot == current->nfs4_slot, "old and current requests reuse slot number");
        CHECK(nfs4_session_init(rpc, id, 0) == -1, "reject unusable replacement");
        CHECK(rpc_cancel_pdu(rpc, old) == 0, "release old request");
        CHECK(rpc->nfs4_slots_in_use == 1 && rpc->nfs4_slots[0].in_use,
              "old completion must not release current slot");
        CHECK(rpc->nfs4_slots[0].seqid == 1,
              "old completion must not roll back current sequence");
        next = rpc_nfs4_renew_session_task(rpc, unexpected_callback, NULL);
        CHECK(next != NULL && nfs4_pdu_take_slot(rpc, next) == -1,
              "current slot remains exclusive");
        CHECK(rpc_cancel_pdu(rpc, current) == 0, "release current request");
        CHECK(nfs4_pdu_take_slot(rpc, next) == 0 && rpc->nfs4_slots[0].seqid == 1,
              "current rollback remains effective");
        CHECK(rpc_cancel_pdu(rpc, next) == 0, "release final request");
        CHECK(rpc_queue_length(rpc) == 0 && rpc->nfs4_slots_in_use == 0,
              "no outstanding requests or slots");
        rpc_destroy_context(rpc);
        printf("PASS: replacement sent=%d destroy=%d reuse_id=%d\n", sent, destroy, reuse_id);
}

int main(void)
{
        int sent, destroy, reuse_id;

        same_session();
        for (sent = 0; sent < 2; sent++)
                for (destroy = 0; destroy < 2; destroy++)
                        for (reuse_id = 0; reuse_id < 2; reuse_id++)
                                replacement(sent, destroy, reuse_id);
        return 0;
}
#endif
