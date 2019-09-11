//#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#define MAXLEN 256

SYSCALL_DEFINE2(s2_encrypt, const char __user *, str, int, key) 
{
	long retval;
	char buf[MAXLEN];
	int i;

	if (unlikely(key < 1 || key > 5)) 
		return EINVAL;

	/* strncpy_from_user returns length of string on success*/
	retval = strncpy_from_user(buf, str, MAXLEN);
        if (likely(retval >= 0)) {
	    for(i=0; i<retval; i++) {
	    	buf[i] = buf[i] + key;
	    }		    

	    printk(KERN_INFO "The encrypted string is: %s\n", buf);
	    retval=0;	
	}
	
	return retval;
}
