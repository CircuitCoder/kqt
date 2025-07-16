#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h> 

static int __init kqt_module_init(void) {
  pr_info("kqt: init\n");
  return 0;
}

static void __exit kqt_module_exit(void) {
  pr_info("kqt: exit\n");
}

module_init(kqt_module_init);
module_exit(kqt_module_exit);

MODULE_LICENSE("GPL");
