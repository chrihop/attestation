#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#define DRIVER_AUTHOR	"Hao Chen <hao.chen@yale.edu>"
#define DRIVER_DESC		"Attestation driver for Linux"

static int attestation_dev_init(void)
{
    printk(KERN_INFO "attestation device init\n");
    crypto_init();

    return 0;
}

static void attestation_dev_exit(void)
{
    printk(KERN_INFO "attestation device exit\n");
}


module_init(attestation_dev_init);
module_exit(attestation_dev_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
