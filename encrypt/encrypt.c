/* Cathlyn Stone
 * Linux Kernel Programming
 * Project #1
 */ 

#include <linux/kernel.h>
#include <linux/syscalls.h>

#define MAXLEN 256

/* Add a new system call to the linux kernel.
 * Encrypts a NULL-terminated string using an encryption key between 1 and 5 */
SYSCALL_DEFINE2(s2_encrypt, const char __user *, str, int, key) 
{
	long retval;
	char buf[MAXLEN];
	int i;

	/* Return EINVAL if the encryption key is out-of-bounds */
	if (unlikely(key < 1 || key > 5)) 
		return EINVAL;

	/* Copy string provided by user into bufffer.
	 * strncpy_from_user returns length of string on success */
	retval = strncpy_from_user(buf, str, MAXLEN);
        if (likely(retval >= 0)) {

 	    /* Encrypt the string using the key now */		
	    for(i=0; i<retval; i++) {
	    	buf[i] = buf[i] + key;
	    }		    

	    /* Print encypted string and return 0 */
	    printk(KERN_INFO "The encrypted string is: %s\n", buf);
	    retval=0;	
	}
	
	return retval;
}
