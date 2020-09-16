// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-l3-ipv4ll.h"

#include <net/if.h>

#include "n-acd/src/n-acd.h"
#include "nm-core-utils.h"

/*****************************************************************************/

struct _NML3IPv4LL {
    NML3Cfg *                l3cfg;
    NML3CfgCommitTypeHandle *l3cfg_commit_handle;
    GSource *                source_handle;
    const NML3ConfigData *   l3cd;
    const NMPObject *        plobj;
    struct {
        nm_le64_t value;
        nm_le64_t generation;
    } seed;
    gulong          l3cfg_signal_notify_id;
    int             ref_count;
    in_addr_t       addr;
    NML3IPv4LLState state;
    NMEtherAddr     seed_mac;
    NMEtherAddr     mac;
    bool            seed_set : 1;
    bool            mac_set : 1;
    bool            addr_changed : 1;
    bool            mac_changed : 1;
    bool            link_seen_not_ready : 1;
};

#define L3CD_TAG(self) (&(((const char *) self)[1]))

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_IP4
#define _NMLOG_PREFIX_NAME "ipv4ll"
#define _NMLOG(level, ...)                                                             \
    G_STMT_START                                                                       \
    {                                                                                  \
        nm_log((level),                                                                \
               (_NMLOG_DOMAIN),                                                        \
               NULL,                                                                   \
               NULL,                                                                   \
               _NMLOG_PREFIX_NAME "[" NM_HASH_OBFUSCATE_PTR_FMT                        \
                                  ",ifindex=%d]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
               NM_HASH_OBFUSCATE_PTR(self),                                            \
               nm_l3_ipv4ll_get_ifindex(self) _NM_UTILS_MACRO_REST(__VA_ARGS__));      \
    }                                                                                  \
    G_STMT_END

/*****************************************************************************/

static gboolean _reset(NML3IPv4LL *self);

/*****************************************************************************/

NML3Cfg *
nm_l3_ipv4ll_get_l3cfg(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->l3cfg;
}

int
nm_l3_ipv4ll_get_ifindex(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return nm_l3cfg_get_ifindex(self->l3cfg);
}

NMPlatform *
nm_l3_ipv4ll_get_platform(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return nm_l3cfg_get_platform(self->l3cfg);
}

/*****************************************************************************/

NML3IPv4LLState
nm_l3_ipv4ll_get_state(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->state;
}

in_addr_t
nm_l3_ipv4ll_get_addr(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->addr;
}

const NML3ConfigData *
nm_l3_ipv4ll_get_l3cd(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    return self->l3cd;
}

/*****************************************************************************/

static gboolean
_plobj_link_is_ready(const NMPObject *plobj)
{
    const NMPlatformLink *pllink;

    if (!plobj)
        return FALSE;

    pllink = NMP_OBJECT_CAST_LINK(plobj);
    if (!NM_FLAGS_HAS(pllink->n_ifi_flags, IFF_UP))
        return FALSE;
    if (pllink->l_address.len != ETH_ALEN)
        return FALSE;

    return TRUE;
}

/*****************************************************************************/

static NMPlatformIP4Address *
_l3cd_config_plat_init_addr(NMPlatformIP4Address *a, int ifindex, in_addr_t addr)
{
    nm_assert(nm_utils_ip4_address_is_link_local(addr));

    *a = (NMPlatformIP4Address){
        .ifindex      = ifindex,
        .address      = addr,
        .peer_address = addr,
        .plen         = 16,
        .addr_source  = NM_IP_CONFIG_SOURCE_IP4LL,
    };
    return a;
}

static NMPlatformIP4Route *
_l3cd_config_plat_init_route(NMPlatformIP4Route *r, int ifindex)
{
    *r = (NMPlatformIP4Route){
        .ifindex    = ifindex,
        .network    = htonl(0xE0000000u),
        .plen       = 4,
        .rt_source  = NM_IP_CONFIG_SOURCE_IP4LL,
        .table_any  = TRUE,
        .metric_any = TRUE,
    };
    return r;
}

static const NML3ConfigData *
_l3cd_config_create(int ifindex, in_addr_t addr, NMDedupMultiIndex *multi_idx)
{
    nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
    NMPlatformIP4Address                    a;
    NMPlatformIP4Route                      r;

    nm_assert(nm_utils_ip4_address_is_link_local(addr));
    nm_assert(ifindex > 0);
    nm_assert(multi_idx);

    l3cd = nm_l3_config_data_new(multi_idx, ifindex);
    nm_l3_config_data_set_source(l3cd, NM_IP_CONFIG_SOURCE_IP4LL);

    nm_l3_config_data_add_address_4(l3cd, _l3cd_config_plat_init_addr(&a, ifindex, addr));
    nm_l3_config_data_add_route_4(l3cd, _l3cd_config_plat_init_route(&r, ifindex));

    return nm_l3_config_data_seal(g_steal_pointer(&l3cd));
}

/*****************************************************************************/

_nm_unused  //XXX
    static void
    _ipv4ll_addrgen(NML3IPv4LL *self, gboolean reset_generation, gboolean generate_new_addr)
{
    CSipHash  state;
    char      sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];
    char      sbuf_mac[ETH_ALEN * 3];
    gboolean  seed_changed = FALSE;
    in_addr_t addr_new;
    guint64   h;

    nm_assert(NM_IS_L3_IPV4LL(self));

    if (self->mac_set && (!self->seed_set || !nm_ether_addr_equal(&self->mac, &self->seed_mac))) {
        /* MAC_HASH_KEY is the same as used by systemd. */
#define MAC_HASH_KEY          \
    ((const guint8[16]){0xdf, \
                        0x04, \
                        0x22, \
                        0x98, \
                        0x3f, \
                        0xad, \
                        0x14, \
                        0x52, \
                        0xf9, \
                        0x87, \
                        0x2e, \
                        0xd1, \
                        0x9c, \
                        0x70, \
                        0xe2, \
                        0xf2})

        /* systemd's ipv4ll library by default only hashes the MAC address (as we do here).
         * This is also what previous versions of NetworkManager did (whenn using sd_ipv4ll).
         *
         * On the other hand, systemd-networkd uses net_get_name_persistent() of the device
         * mixed with /etc/machine-id.
         *
         * See also: https://tools.ietf.org/html/rfc3927#section-2.1 */

        c_siphash_init(&state, MAC_HASH_KEY);
        c_siphash_append(&state, self->mac.ether_addr_octet, ETH_ALEN);

        /* FIXME(l3cfg): At this point, maybe we should also mix it with nm_utils_host_id_get().
         * This would get the behavior closer to what systemd-networkd does.
         * Don't do that for now, because it would be a change in behavior compared
         * to earlier versions of NetworkManager.  */

        h = c_siphash_finalize(&state);

        _LOGT("addr-gen: %sset seed (for %s)",
              self->seed_set ? "re" : "",
              _nm_utils_hwaddr_ntoa(&self->mac, ETH_ALEN, FALSE, sbuf_mac, sizeof(sbuf_mac)));

        self->seed_set        = TRUE;
        self->seed_mac        = self->mac;
        self->seed.generation = htole64(0);
        self->seed.value      = htole64(h);

        seed_changed = TRUE;
    }

    if (!self->seed_set) {
        /* we have no seed set (and consequently no MAC address set either).
         * We cannot generate an address. */
        nm_assert(self->addr == 0u);
        return;
    }

    nm_assert(seed_changed || self->seed.generation != htole64(0u));
    nm_assert(nm_utils_ip4_address_is_link_local(self->addr));

    if (reset_generation && !seed_changed) {
        _LOGT("addr-gen: reset seed (generation only)");
        self->seed.generation = htole64(0);
        seed_changed          = TRUE;
    }

    if (!seed_changed && !generate_new_addr) {
        /* neither did the caller request a new address, nor was the seed changed. The current
         * address is still to be used. */
        return;
    }

gen_addr:

#define PICK_HASH_KEY         \
    ((const guint8[16]){0x15, \
                        0xac, \
                        0x82, \
                        0xa6, \
                        0xd6, \
                        0x3f, \
                        0x49, \
                        0x78, \
                        0x98, \
                        0x77, \
                        0x5d, \
                        0x0c, \
                        0x69, \
                        0x02, \
                        0x94, \
                        0x0b})
    h = c_siphash_hash(PICK_HASH_KEY, (const guint8 *) &self->seed, sizeof(self->seed));

    self->seed.generation = htole64(le64toh(self->seed.generation) + 1u);

    addr_new = htonl((h & UINT32_C(0x0000FFFF)) | NM_IPV4LL_NETWORK);

    if (addr_new == self->addr || NM_IN_SET(ntohl(addr_new) & 0x0000FF00u, 0x0000u, 0xFF00u))
        goto gen_addr;

    nm_assert(nm_utils_ip4_address_is_link_local(addr_new));

    _LOGT("addr-gen: set address %s", _nm_utils_inet4_ntop(addr_new, sbuf_addr));
    self->addr         = addr_new;
    self->addr_changed = TRUE;
}

/*****************************************************************************/

static void
_ipv4ll_update_link(NML3IPv4LL *self, const NMPObject *plobj)
{
    char                 sbuf[ETH_ALEN * 3];
    nm_auto_nmpobj const NMPObject *pllink_old = NULL;
    const NMEtherAddr *             mac_new;
    gboolean                        changed;

    if (self->plobj == plobj)
        return;

    pllink_old  = g_steal_pointer(&self->plobj);
    self->plobj = nmp_object_ref(plobj);

    mac_new = NULL;
    if (plobj) {
        const NMPlatformLink *pllink = NMP_OBJECT_CAST_LINK(plobj);

        if (pllink->l_address.len == ETH_ALEN)
            mac_new = &pllink->l_address.ether_addr;
    }

    changed = FALSE;
    if (!mac_new) {
        if (self->mac_set) {
            changed       = TRUE;
            self->mac_set = FALSE;
        }
    } else {
        if (!self->mac_set || !nm_ether_addr_equal(mac_new, &self->mac)) {
            changed       = TRUE;
            self->mac_set = TRUE;
            self->mac     = *mac_new;
        }
    }

    if (changed) {
        self->mac_changed = TRUE;
        _LOGT("mac changed: %s",
              self->mac_set ? _nm_utils_hwaddr_ntoa(&self->mac, ETH_ALEN, TRUE, sbuf, sizeof(sbuf))
                            : "unset");
    }
}

/*****************************************************************************/

static void
_l3cfg_emit_signal_notify_ipv4ll_event(NML3IPv4LL *self)
{
    NML3ConfigNotifyData notify_data;

    nm_assert(NM_IS_L3_IPV4LL(self));

    notify_data.notify_type  = NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT;
    notify_data.ipv4ll_event = (typeof(notify_data.ipv4ll_event)){
        .ipv4ll = self,
    };
    _nm_l3cfg_emit_signal_notify(self->l3cfg, &notify_data);
}

/*****************************************************************************/

static void
_l3cd_config_add(NML3IPv4LL *self, gboolean with_timeout)
{
    nm_assert(NM_IS_L3_IPV4LL(self));
    nm_assert(NM_IS_L3_CONFIG_DATA(self->l3cd));

    nm_l3cfg_add_config(self->l3cfg,
                        L3CD_TAG(self),
                        TRUE,
                        self->l3cd,
                        NM_L3CFG_CONFIG_PRIORITY_IPV4LL,
                        0,
                        0,
                        NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
                        NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                        0,
                        0,
                        with_timeout ? N_ACD_TIMEOUT_RFC5227 : 0u,
                        NM_L3_CONFIG_MERGE_FLAGS_ONLY_FOR_ACD);

    self->l3cfg_commit_handle = nm_l3cfg_commit_type_register(self->l3cfg,
                                                              NM_L3_CFG_COMMIT_TYPE_ASSUME,
                                                              self->l3cfg_commit_handle);
}

static gboolean
_l3cd_config_remove(NML3IPv4LL *self)
{
    nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;

    nm_assert(NM_IS_L3_IPV4LL(self));

    if (!self->l3cd)
        return FALSE;

    l3cd = g_steal_pointer(&self->l3cd);
    if (!nm_l3cfg_remove_config(self->l3cfg, L3CD_TAG(self), l3cd))
        nm_assert_not_reached();

    nm_l3cfg_commit_type_unregister(self->l3cfg, g_steal_pointer(&self->l3cfg_commit_handle));
    return TRUE;
}

/*****************************************************************************/

_nm_unused  //XXX
    static const NMPObject *
    _platform_find_existing_ll4(NML3IPv4LL *self)
{
    NMDedupMultiIter iter;
    NMPLookup        lookup;
    const NMPObject *obj;

    nmp_lookup_init_object(&lookup, NMP_OBJECT_TYPE_IP4_ADDRESS, nm_l3_ipv4ll_get_ifindex(self));

    nm_platform_iter_obj_for_each(&iter, nm_l3_ipv4ll_get_platform(self), &lookup, &obj)
    {
        const NMPlatformIP4Address *a = NMP_OBJECT_CAST_IP4_ADDRESS(obj);

        if (nm_utils_ip4_address_is_link_local(a->address) && a->plen == 16
            && a->address == a->peer_address)
            return obj;
    }

    return NULL;
}

/*****************************************************************************/

static void
_start(NML3IPv4LL *self)
{
    const NMPObject *ll4_external;
    char             sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];

    nm_assert(NM_IS_L3_IPV4LL(self));

    ll4_external = _platform_find_existing_ll4(self);

    if (ll4_external) {
        nm_auto_unref_l3cd const NML3ConfigData *l3cd = NULL;
        in_addr_t                                addr;

        addr = NMP_OBJECT_CAST_IP4_ADDRESS(ll4_external)->address;

        _LOGT("state: external, %s (%sexternally configured)",
              _nm_utils_inet4_ntop(addr, sbuf_addr),
              self->addr == addr ? "still " : "");

        self->addr = addr;

        l3cd = _l3cd_config_create(nm_l3_ipv4ll_get_ifindex(self),
                                   self->addr,
                                   nm_l3cfg_get_multi_idx(self->l3cfg));

        if (!nm_l3_config_data_equal(l3cd, self->l3cd))
            NM_SWAP(&l3cd, &self->l3cd);

        self->state = NM_L3_IPV4LL_STATE_EXTERNAL;

        _l3cd_config_add(self, FALSE);

        _l3cfg_emit_signal_notify_ipv4ll_event(self);
        return;
    }

    _reset(self);
    /* XXX */
}

static gboolean
_start_schedule_cb(gpointer user_data)
{
    NML3IPv4LL *self = user_data;

    _start(self);
    return G_SOURCE_REMOVE;
}

static void
_start_schedule(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    nm_assert(NM_IN_SET(self->state, NM_L3_IPV4LL_STATE_RESTARTING));

    nm_clear_g_source_inst(&self->source_handle);

    self->source_handle =
        nm_g_source_attach(nm_g_idle_source_new(G_PRIORITY_DEFAULT, _start_schedule_cb, self, NULL),
                           NULL);
}

static gboolean
_reset(NML3IPv4LL *self)
{
    gboolean l3cfg_changed = FALSE;

    nm_assert(NM_IS_L3_IPV4LL(self));

    if (_l3cd_config_remove(self))
        l3cfg_changed = TRUE;

    nm_clear_g_source_inst(&self->source_handle);
    self->seed_set = FALSE;
    self->state    = NM_L3_IPV4LL_STATE_RESTARTING;
    return l3cfg_changed;
}

/*****************************************************************************/

void
nm_l3_ipv4ll_restart(NML3IPv4LL *self)
{
    nm_assert(NM_IS_L3_IPV4LL(self));

    if (self->state == NM_L3_IPV4LL_STATE_RESTARTING)
        return;

    self->state = NM_L3_IPV4LL_STATE_RESTARTING;

    _start(self);
}

/*****************************************************************************/

static void
_l3cfg_notify_cb(NML3Cfg *l3cfg, const NML3ConfigNotifyData *notify_data, NML3IPv4LL *self)
{
    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE) {
        const NMPObject *obj = notify_data->platform_change.obj;

        /* we only process the link changes on the idle handler. That means, we may miss
         * events. If we saw the link down for a moment, remember it. Note that netlink
         * anyway can loose signals, so we might still miss to see the link down. This
         * is as good as we get it. */
        if (NMP_OBJECT_GET_TYPE(obj) == NMP_OBJECT_TYPE_LINK) {
            if (notify_data->platform_change.change_type == NM_PLATFORM_SIGNAL_REMOVED)
                self->link_seen_not_ready = TRUE;
            else if (!_plobj_link_is_ready(obj))
                self->link_seen_not_ready = TRUE;
        }
        return;
    }

    if (notify_data->notify_type == NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE) {
        /* NMl3Cfg only reloads the platform link during the idle handler. Pick it up now. */
        _ipv4ll_update_link(self, nm_l3cfg_get_plobj(l3cfg, FALSE));
        return;
    }

    if (NM_IN_SET(self->state, NM_L3_IPV4LL_STATE_RESTARTING))
        return;

    //XXX
}

/*****************************************************************************/

NML3IPv4LL *
nm_l3_ipv4ll_new(NML3Cfg *l3cfg)
{
    NML3IPv4LL *self;

    g_return_val_if_fail(NM_IS_L3CFG(l3cfg), NULL);

    self  = g_slice_new(NML3IPv4LL);
    *self = (NML3IPv4LL){
        .l3cfg               = g_object_ref(l3cfg),
        .ref_count           = 1,
        .l3cfg_commit_handle = NULL,
        .source_handle       = NULL,
        .l3cd                = NULL,
        .plobj               = NULL,
        .addr                = 0u,
        .state               = NM_L3_IPV4LL_STATE_RESTARTING,
        .l3cfg_signal_notify_id =
            g_signal_connect(l3cfg, NM_L3CFG_SIGNAL_NOTIFY, G_CALLBACK(_l3cfg_notify_cb), self),
    };

    _LOGT("created: l3cfg=" NM_HASH_OBFUSCATE_PTR_FMT, NM_HASH_OBFUSCATE_PTR(l3cfg));

    _ipv4ll_update_link(self, nm_l3cfg_get_plobj(l3cfg, FALSE));

    _start_schedule(self);

    return self;
}

NML3IPv4LL *
nm_l3_ipv4ll_ref(NML3IPv4LL *self)
{
    nm_assert(!self || NM_IS_L3_IPV4LL(self));

    if (self) {
        nm_assert(self->ref_count < G_MAXINT);
        self->ref_count++;
    }
    return self;
}

void
nm_l3_ipv4ll_unref(NML3IPv4LL *self)
{
    nm_assert(!self || NM_IS_L3_IPV4LL(self));

    if (!self)
        return;

    if (--self->ref_count > 0)
        return;

    _LOGT("finalize");

    if (_reset(self))
        nm_l3cfg_commit_on_idle_schedule(self->l3cfg);

    nm_clear_g_signal_handler(self->l3cfg, &self->l3cfg_signal_notify_id);

    g_object_unref(self->l3cfg);
    nmp_object_unref(self->plobj);
    nm_g_slice_free(self);
}
