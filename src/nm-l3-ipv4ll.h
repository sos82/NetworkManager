// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_L3_IPV4LL_H__
#define __NM_L3_IPV4LL_H__

#include "nm-l3cfg.h"

typedef enum _nm_packed {
    NM_L3_IPV4LL_STATE_RESTARTING,
    NM_L3_IPV4LL_STATE_EXTERNAL,
} NML3IPv4LLState;

typedef struct _NML3IPv4LL NML3IPv4LL;

static inline gboolean
NM_IS_L3_IPV4LL(const NML3IPv4LL *self)
{
    nm_assert(!self
              || (NM_IS_L3CFG(*((NML3Cfg **) self))
                  && (*((int *) (((char *) self) + sizeof(gpointer)))) > 0));
    return !!self;
}

NML3IPv4LL *nm_l3_ipv4ll_new(NML3Cfg *self);

NML3IPv4LL *nm_l3_ipv4ll_ref(NML3IPv4LL *self);
void        nm_l3_ipv4ll_unref(NML3IPv4LL *self);

/*****************************************************************************/

NML3Cfg *nm_l3_ipv4ll_get_l3cfg(NML3IPv4LL *self);

int nm_l3_ipv4ll_get_ifindex(NML3IPv4LL *self);

NMPlatform *nm_l3_ipv4ll_get_platform(NML3IPv4LL *self);

/*****************************************************************************/

NML3IPv4LLState nm_l3_ipv4ll_get_state(NML3IPv4LL *self);

in_addr_t nm_l3_ipv4ll_get_addr(NML3IPv4LL *self);

const NML3ConfigData *nm_l3_ipv4ll_get_l3cd(NML3IPv4LL *self);

/*****************************************************************************/

void nm_l3_ipv4ll_restart(NML3IPv4LL *self);

#endif /* __NM_L3_IPV4LL_H__ */
