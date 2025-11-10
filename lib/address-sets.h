/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ADDRESS_SETS_H
#define ADDRESS_SETS_H

#include <stdbool.h>

#include "openvswitch/shash.h"
#include "sset.h"
#include "ovn-sb-idl.h"
#include "ovn/expr.h"

/*
 * Representation of all address sets currently tracked in the controller
 * together with their state and possibly diff for incremental updates.
 */
struct addr_sets {
    struct shash const_sets; /* Tracked address sets */
    struct shash updated;    /* Sets changed, try incremental update */
    struct sset addded;      /* Sets changed/added, trigger recompute */
    struct sset deleted;     /* Sets deleted, trigger recompute */
};

/*
 * A diff between to versions of the same address set that is used to perform
 * incremental updates to flows using the address set.
 */
struct addr_set_diff {
    struct expr_constant_set *added;   /* Added by new address set */
    struct expr_constant_set *deleted; /* Removed by new address set */
};

void addr_sets_init(struct addr_sets *as);
void addr_sets_clear(struct addr_sets *as);
void addr_sets_clear_tracked_changes(struct addr_sets *as);
void addr_sets_destroy(struct addr_sets *as);
void addr_sets_add(struct addr_sets *as, const struct sbrec_address_set *sb);
void addr_sets_del(struct addr_sets *as, const struct sbrec_address_set *sb);

static inline bool
addr_sets_changed(struct addr_sets *as)
{
    return !sset_is_empty(&as->addded) || !shash_is_empty(&as->updated) ||
           !sset_is_empty(&as->deleted);
}

#endif /* lib/address-sets.h */
