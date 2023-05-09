#include <identities.h>

#if defined(__cplusplus) && __cplusplus
extern "C"
{
#endif

__attribute((weak)) ident_remote_devices_t remote_devices = { .n_devices = 0 };
__attribute((weak)) ident_nodes_t          remote_nodes = { .n_nodes = 0 };
__attribute((section(".enclro.trusted"))) ident_slots_t remote_slots;

#if defined(__cplusplus) && __cplusplus
}
#endif

ident_remote_device_t*
find_device(uuid_t device_id)
{
    for (size_t i = 0; i < remote_devices.n_devices; i++)
    {
        if (remote_devices.devices[i].device_id == device_id)
        {
            return &remote_devices.devices[i];
        }
    }
    return NULL;
}

ident_node_t*
find_node(uuid_t node_id)
{
    for (size_t i = 0; i < remote_nodes.n_nodes; i++)
    {
        if (remote_nodes.nodes[i].node_id == node_id)
        {
            return &remote_nodes.nodes[i];
        }
    }
    return NULL;
}

err_t
get_identity(uuid_t node_id, char ** pem, size_t * pem_size, uint8_t ** hash)
{
    ident_node_t * node = find_node(node_id);
    if (node == NULL)
    {
        return ERR_NOT_FOUND;
    }
    ident_remote_device_t * device = find_device(node->device_id);
    if (device == NULL)
    {
        return ERR_NOT_FOUND;
    }

    *pem = device->pem;
    *pem_size = device->pem_size;
    *hash = remote_slots.slots[node->slot];

    return ERR_OK;
}
