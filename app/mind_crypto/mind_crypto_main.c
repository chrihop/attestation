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

static void print_key(char * name, void * key, size_t sz)
{
    int i;
    printk(KERN_INFO "%s (size %lu): ", name, sz);
    for (i = 0; i < sz; i++)
    {
        printk(KERN_CONT "%02x", ((unsigned char *)key)[i]);
    }
}

static struct crypto_rac_context_t encoder, decoder;
static uint8_t key[32];

#define PAGE_SIZE 4096

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
            print_key("mac", entry->mac, 16);
            print_key("nonce", entry->nonce, 12);
            return entry;
        }
    }
    return NULL;
}

static int encrypt_page(void * page, size_t tgid, size_t addr)
{
    void * encrypted = kmalloc(PAGE_SIZE + 16, GFP_KERNEL);
    size_t len, nonce_len;
    uint8_t nonce[12];

    crypto_rac_encrypt(&encoder, page, PAGE_SIZE, encrypted, &len, nonce, &nonce_len);
    BUG_ON(len != PAGE_SIZE + 16);
    BUG_ON(nonce_len != 12);

    struct crypto_registry_t * entry = kmalloc(sizeof(struct crypto_registry_t), GFP_KERNEL);
    entry->addr = addr;
    entry->tgid = tgid;
    memcpy(entry->mac, encrypted + PAGE_SIZE, 16);
    memcpy(entry->nonce, nonce, 12);
    hash_add(crypto_registry, &entry->node, addr ^ tgid);

    memcpy(page, encrypted, PAGE_SIZE);
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
    void * encrypted = kmalloc(PAGE_SIZE + 16, GFP_KERNEL);
    memcpy(encrypted, page, PAGE_SIZE);
    memcpy(encrypted + PAGE_SIZE, entry->mac, 16);

    size_t len;
    int succ = crypto_rac_decrypt(&decoder, entry->nonce, 12, encrypted, PAGE_SIZE + 16, page, &len);
    BUG_ON(len != PAGE_SIZE);
    BUG_ON(succ != 1);

    kfree(encrypted);
    hash_del(&entry->node);
    return 0;
}

static void test_program(void)
{
    void * page = kmalloc(PAGE_SIZE * 15, GFP_KERNEL);
    void * backup = kmalloc(PAGE_SIZE * 15, GFP_KERNEL);
    int i;
    for (i = 0; i < PAGE_SIZE * 15; i++)
    {
        ((uint8_t *)page)[i] = i % 256;
    }
    memcpy(backup, page, PAGE_SIZE * 15);
    BUG_ON(memcmp(page, backup, PAGE_SIZE * 15) != 0);

    size_t tgid = 3821;
    size_t base = 0x7f7f7f7f0000lu;
    for (i = 0; i < 15; i++)
    {
        printk(KERN_INFO "encrypting page %d\n", i);
        encrypt_page(page + i * PAGE_SIZE, tgid, base + i);

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
        if (crypto_registry_find_entry(tgid, base + i) == NULL)
        {
            /* this page is already decrypted */
            continue ;
        }
        printk(KERN_INFO "decrypting page %d\n", i);
        decrypt_page(page + i * PAGE_SIZE, tgid, base + i);

        BUG_ON(memcmp(page + i * PAGE_SIZE, backup + i * PAGE_SIZE, PAGE_SIZE) != 0);
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
