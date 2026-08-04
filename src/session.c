#include "vpn/session.h"
#include <string.h>

void vpn_session_table_init(struct vpn_session_table *table)
{
    if (!table) {
        return;
    }

    table->session_count = 0;
    memset(table->sessions, 0, sizeof(table->sessions));
}

struct vpn_session *vpn_session_table_find_by_id(struct vpn_session_table *table, uint64_t session_id)
{
    if (!table) {
        return NULL;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].session_id == session_id) {
            return &table->sessions[i];
        }
    }

    return NULL;
}

int vpn_session_table_insert(struct vpn_session_table *table, const struct vpn_session *session)
{
    if (!table || !session || table->session_count >= VPN_SESSION_TABLE_MAX_SESSIONS) {
        return -1;
    }

    table->sessions[table->session_count++] = *session;
    return 0;
}

int vpn_session_table_remove(struct vpn_session_table *table, uint64_t session_id)
{
    if (!table) {
        return -1;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].session_id == session_id) {
            if (i + 1 < table->session_count) {
                memmove(&table->sessions[i], &table->sessions[i + 1],
                        (table->session_count - i - 1) * sizeof(table->sessions[0]));
            }
            --table->session_count;
            return 0;
        }
    }

    return -1;
}

struct vpn_session *vpn_session_table_find_by_virtual_ip(struct vpn_session_table *table, uint32_t virtual_ip)
{
    if (!table) {
        return NULL;
    }

    for (size_t i = 0; i < table->session_count; ++i) {
        if (table->sessions[i].assigned_virtual_ip == virtual_ip) {
            return &table->sessions[i];
        }
    }

    return NULL;
}
