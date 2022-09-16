#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#define DRIVER_AUTHOR	"Hao Chen <hao.chen@yale.edu>"
#define DRIVER_DESC		"Attestation driver for Linux"

MODULE_LICENSE("GPL");

//MODULE_LICENSE("Dual BSD/GPL");
//MODULE_AUTHOR(DRIVER_AUTHOR);
//MODULE_DESCRIPTION(DRIVER_DESC);


#include <enclave.h>

struct enclave_key_store_t root_key;
struct crypto_ds_public_key_t pubkey;

char buffer[1024];

void print_key(char * name, void * key, size_t sz)
{
    int i;
    sprintf(buffer, "%s: ", name);
    for (i = 0; i < sz; i++)
    {
        sprintf(&buffer[strlen(name)], "%02x", ((unsigned char *)key)[i]);
    }
    printk(KERN_NOTICE "%s", buffer);
}

static int attestation_dev_init(void)
{
    printk(KERN_INFO "attestation device init\n");
    printk(KERN_INFO "enclave key store size: %d\n", SIZE_MAX);
    crypto_init();
    enclave_key_native(&root_key);
    crypto_ds_export_public_key(&root_key.device_key, &pubkey);
    print_key("root_key", pubkey.key, pubkey.len);

    return 0;
}

static void attestation_dev_exit(void)
{
    printk(KERN_INFO "attestation device exit\n");
}


module_init(attestation_dev_init);
module_exit(attestation_dev_exit);

