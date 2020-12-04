#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/hello.h>



int regular_msg_fn(int a, struct hello_info * info) {
	printk(KERN_INFO "Hello from regular_msg_fn, a=%d, info->a=%lu\n", a, info->a);
	//printk(KERN_INFO "The msg is: %s\n", msg);
	return 0;
};

static struct hello_struct default_hello = {
	.name = "regular_hello",
	.print_msg = regular_msg_fn,
};

struct hello_struct * current_hello = &default_hello;

SYSCALL_DEFINE0(hello)
{
//  char buf[256];
//  long copied = strncpy_from_user(buf, msg, sizeof(buf));
//  if (copied < 0 || copied == sizeof(buf))
//    return -EFAULT;
//  printk(KERN_INFO "hello syscall called with \"%s\"\n", buf);
  
  struct hello_info info = {
  	.a = 2,
	.b = 3,
	.c = "someinfo",
  };

  int val = current_hello->print_msg(13, &info);
  printk(KERN_INFO "hello syscall returning %d\n", val);
  return val;
}

int hello_register(struct hello_struct * hs) {
	printk(KERN_INFO "HELLO register \n");
	if (!hs) {
		printk(KERN_INFO "hs is null\n");
		return 0;
	}
	printk(KERN_INFO "hs->name=%s\n", hs->name);
	if (!hs->print_msg) {
		printk(KERN_INFO "COULD NOT find hs->print_msg\n");
		return 0;
	}
	

	printk(KERN_INFO "HELLO register SUCCESS\n");
	current_hello = hs;
	return 0;
}

EXPORT_SYMBOL_GPL(hello_register);

void hello_unregister(struct hello_struct * hs) {
	current_hello = &default_hello;
}
EXPORT_SYMBOL_GPL(hello_unregister);
