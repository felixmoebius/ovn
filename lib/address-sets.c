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

#include <config.h>
#include <stdarg.h>

#include "address-sets.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/vlog.h"
#include "ovn/lex.h"
#include "vec.h"

VLOG_DEFINE_THIS_MODULE(address_sets);

static const union mf_subvalue exact_match_mask_ethernet = {
    .be16 = { [61] = OVS_BE16_MAX, [62] = OVS_BE16_MAX, [63] = OVS_BE16_MAX, }
};

static const union mf_subvalue exact_match_mask_ipv4 = {
    .be32 = { [31] = OVS_BE32_MAX, }
};

static const union mf_subvalue exact_match_mask_ipv6 = {
    .be64 = { [14] = OVS_BE64_MAX, [15] = OVS_BE64_MAX, }
};

static bool
addr_set_get_type(struct expr_constant_set *as, enum lex_format *type)
{
    struct expr_constant *first = vector_get_ptr(&as->values, 0);
    if (!first) {
        return false;
    }

    *type = first->format;
    return true;
}

/* Add address to address set and do some validation. */
static void
addr_set_add_address(struct expr_constant_set *as, char *address)
{
    struct lex_token *tok;
    struct lexer lex;

    lexer_init(&lex, address);
    lexer_get(&lex);
    tok = &lex.token;

    if (tok->type != LEX_T_INTEGER && tok->type != LEX_T_MASKED_INTEGER) {
        VLOG_WARN("Invalid address set entry: '%s', token type: %d",
                  address, tok->type);
        goto out;
    }

    const union mf_subvalue *exact_match_mask_type;
    switch (tok->format) {
    case LEX_F_ETHERNET:
        exact_match_mask_type = &exact_match_mask_ethernet;
        break;
    case LEX_F_IPV4:
        exact_match_mask_type = &exact_match_mask_ipv4;
        break;
    case LEX_F_IPV6:
        exact_match_mask_type = &exact_match_mask_ipv6;
        break;
    case LEX_F_HEXADECIMAL:
    case LEX_F_DECIMAL:
        VLOG_WARN("Invalid address set entry: '%s', invalid format: %s",
                  address, lex_format_to_string(tok->format));
        goto out;
    default:
        OVS_NOT_REACHED();
    }

    enum lex_format type;
    if (addr_set_get_type(as, &type) && type != tok->format) {
        VLOG_WARN("Invalid address set entry: '%s' expected format: %s",
                  address, lex_format_to_string(type));
        goto out;
    }

    struct expr_constant constant = {
        .value = lex.token.value,
        .format = lex.token.format,
        .masked = false,
    };

    /* Treat entries with exact match mask as unmasked. */
    if (tok->type == LEX_T_MASKED_INTEGER) {
        if (memcmp(&tok->mask, exact_match_mask_type, sizeof tok->mask)) {
            constant.masked = true;
            constant.mask = lex.token.mask;
        }
    }

    vector_push(&as->values, &constant);

out:
    lexer_destroy(&lex);
}

/* Add an address set.
 * When called with an unknown address set, it will be marked as 'added' to
 * trigger a recompute of related flows.
 * When called with an address set that already exists in 'as', it will be
 * marked as 'updated' and compute a diff of the old and new set to try an
 * incremental update of related flows, except where it determines that this
 * is not possible in which case it will be marked as 'added'. */
void
addr_sets_add(struct addr_sets *as, const struct sbrec_address_set *sb)
{
    struct expr_constant_set *as_new = xzalloc(sizeof *as_new);
    enum lex_format new_type, old_type;

    as_new->type = EXPR_C_INTEGER;
    as_new->in_curlies = true;
    as_new->values = VECTOR_CAPACITY_INITIALIZER(struct expr_constant,
                                                 sb->n_addresses);

    for (int i = 0; i < sb->n_addresses; i++) {
        addr_set_add_address(as_new, sb->addresses[i]);
    }

    vector_qsort(&as_new->values, compare_expr_constant_integer_cb);
    vector_dedup(&as_new->values, compare_expr_constant_integer_cb);

    struct expr_constant_set *as_old = shash_find_data(&as->const_sets,
                                                       sb->name);

    /* We treat this as a new address set in terms of incremental updating
     * of the set if either: it is actually new, the new set is empty, the
     * old set was empty, the type of value contained in the has changed. */
    if (!as_old || !addr_set_get_type(as_new, &new_type) ||
        !addr_set_get_type(as_old, &old_type) || new_type != old_type) {
        expr_const_sets_add(&as->const_sets, sb->name, as_new);
        sset_add(&as->addded, sb->name);
        return;
    }

    struct addr_set_diff *diff = xmalloc(sizeof *diff);
    expr_constant_set_integers_diff(as_old, as_new, &diff->added,
                                    &diff->deleted);

    /* The address set may have been updated, but the change doesn't haave any
     * impact to the generated constant-set.  For example, ff::01 is changed to
     * ff::00:01. */
    if (diff->added || diff->deleted) {
        expr_const_sets_add(&as->const_sets, sb->name, as_new);
        shash_add(&as->updated, sb->name, diff);
        return;
    }

    free(diff);
    expr_constant_set_destroy(as_new);
    free(as_new);
}

/* Delete an address set. This will mark the set as 'deleted' to trigger a
 * recompute of related flows. */
void
addr_sets_del(struct addr_sets *as, const struct sbrec_address_set *sb)
{
    expr_const_sets_remove(&as->const_sets, sb->name);
    sset_add(&as->deleted, sb->name);
}

void
addr_sets_init(struct addr_sets *as)
{
    shash_init(&as->const_sets);
    shash_init(&as->updated);
    sset_init(&as->addded);
    sset_init(&as->deleted);
}

/* Clear 'added', 'deleted' and 'updated' markers. */
void
addr_sets_clear_tracked_changes(struct addr_sets *as)
{
    struct shash_node *node;

    sset_clear(&as->addded);
    sset_clear(&as->deleted);

    SHASH_FOR_EACH_SAFE (node, &as->updated) {
        struct addr_set_diff *diff = node->data;
        expr_constant_set_destroy(diff->added);
        expr_constant_set_destroy(diff->deleted);
        free(diff->added);
        free(diff->deleted);
    }

    shash_clear_free_data(&as->updated);
}

/* Delete all address sets in 'as' and clear the 'added', 'deleted'
 * and 'updated' markers. */
void
addr_sets_clear(struct addr_sets *as)
{
    addr_sets_clear_tracked_changes(as);
    expr_const_sets_destroy(&as->const_sets);
}

/* Free memory used by 'as', which may only be used again after calling
 * addr_sets_init(). */
void
addr_sets_destroy(struct addr_sets *as)
{
    struct shash_node *node;

    expr_const_sets_destroy(&as->const_sets);
    shash_destroy(&as->const_sets);

    sset_destroy(&as->addded);
    sset_destroy(&as->deleted);

    SHASH_FOR_EACH_SAFE (node, &as->updated) {
        struct addr_set_diff *diff = node->data;
        expr_constant_set_destroy(diff->added);
        expr_constant_set_destroy(diff->deleted);
        free(diff->added);
        free(diff->deleted);
    }

    shash_destroy(&as->updated);
}
