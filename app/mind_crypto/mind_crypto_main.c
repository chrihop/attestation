#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/bug.h>
#include <linux/hashtable.h>
#include <linux/random.h>

#define DRIVER_AUTHOR	"Hao Chen <hao.chen@yale.edu>"
#define DRIVER_DESC		"Mind Crypto Driver"

#include <enclave.h>


static char buffer[1024];

static void print_key(char * name, void * key, size_t sz)
{
    int i;
    printk(KERN_INFO "%s (size %lu): ", name, sz);
    for (i = 0; i < sz; i++)
    {
        sprintf(&buffer[i * 2], "%02x", ((unsigned char *)key)[i]);
    }
    buffer[i * 2] = '\0';
    printk(KERN_INFO "%s\n", buffer);
}

static struct crypto_rac_context_t encoder, decoder;
static uint8_t key[32];



struct crypto_registry_t
{
    size_t addr;
    size_t tgid;
    uint8_t mac[16];
    uint8_t nonce[12];
    struct hlist_node node;
};

DECLARE_HASHTABLE(crypto_registry, 16);

static struct crypto_registry_t * crypto_registry_find_entry(size_t tgid, size_t addr)
{
    struct crypto_registry_t *entry;
    hash_for_each_possible(crypto_registry, entry, node, tgid ^ addr)
    {
        if (entry->addr == addr)
        {
            printk(KERN_INFO "Found entry for tgid %lx, addr %lx\n", tgid, addr);
            print_key("mac", entry->mac, 16);
            print_key("nonce", entry->nonce, 12);
            return entry;
        }
    }
    printk(KERN_INFO "No entry found for tgid %lx, addr %lx\n", tgid, addr);
    return NULL;
}

static int encrypt_page(void * page, size_t tgid, size_t addr)
{
    void * encrypted = kmalloc(4096 + 16, GFP_KERNEL);
    size_t len, nonce_len;
    uint8_t nonce[12];

    crypto_rac_encrypt(&encoder, page, 4096, encrypted, &len, nonce, &nonce_len);
    BUG_ON(len != 4096 + 16);
    BUG_ON(nonce_len != 12);

    struct crypto_registry_t * entry = kmalloc(sizeof(struct crypto_registry_t), GFP_KERNEL);
    entry->addr = addr;
    entry->tgid = tgid;
    memcpy(entry->mac, encrypted + 4096, 16);
    memcpy(entry->nonce, nonce, 12);
    hash_add(crypto_registry, &entry->node, addr ^ tgid);

    memcpy(page, encrypted, 4096 + 16);
    kfree(encrypted);

    return 0;
}

static int decrypt_page(void * page, size_t tgid, size_t addr)
{
    struct crypto_registry_t * entry = crypto_registry_find_entry(tgid, addr);
    if (entry == NULL)
    {
        return -1;
    }
    void * encrypted = kmalloc(4096 + 16, GFP_KERNEL);
    memcpy(encrypted, page, 4096);
    memcpy(encrypted + 4096, entry->mac, 16);

    size_t len;
    int succ = crypto_rac_decrypt(&decoder, entry->nonce, 12, encrypted, 4096 + 16, page, &len);
    BUG_ON(len != 4096);
    BUG_ON(succ != 0);

    memcpy(page, encrypted, 4096);
    kfree(encrypted);
//    hash_del(&entry->node);
    return 0;
}

static void test_program(void)
{
    void * page = kmalloc(4096 * 15, GFP_KERNEL);
    void * backup = kmalloc(4096 * 15, GFP_KERNEL);
    int i;
    for (i = 0; i < 4096 * 15; i++)
    {
        ((uint8_t *)page)[i] = i % 256;
    }
    memcpy(backup, page, 4096 * 15);

    size_t tgid = 3821;
    size_t base = 0x7f7f7f7f0000lu;
    for (i = 0; i < 15; i++)
    {
        printk(KERN_INFO "encrypting page %d\n", i);
        encrypt_page(page + i * 4096, tgid, base + i);

        struct crypto_registry_t * entry = crypto_registry_find_entry(tgid, base + i);
        BUG_ON(entry == NULL);
        print_key("nonce: ", entry->nonce, 12);
        print_key("mac: ", entry->mac, 16);
    }

    int k = 100;
    uint8_t rand[1];
    while(k -- > 0)
    {
        get_random_bytes(rand, 1);
        i = rand[0] % 15;
        printk(KERN_INFO "decrypting page %d\n", i);

        decrypt_page(page + i * 4096, tgid, base + i);
        BUG_ON(memcmp(page + i * 4096, backup + i * 4096, 4096) != 0);
        printk(KERN_INFO "decryption successful\n");
    }

    kfree(page);
    kfree(backup);
}

static __init int mind_crypto_init(void)
{
    printk(KERN_INFO "Mind crypto module startup ...\n");
    crypto_init();
    crypto_rng(key, 32);
    print_key("private key: ", key, 32);
    crypto_rac_init(&encoder, key, 32);
    crypto_rac_init(&decoder, key, 32);
    hash_init(crypto_registry);

    printk(KERN_INFO "Mind crypto module startup ... done\n");

    printk(KERN_INFO "Testing crypto module ...\n");
    test_program();
    printk(KERN_INFO "Testing crypto module ... done\n");

    return 0;
}

static __exit void mind_crypto_exit(void)
{
    printk(KERN_INFO "Mind crypto module finalize ...\n");
}


module_init(mind_crypto_init);
module_exit(mind_crypto_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
