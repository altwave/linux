#ifndef LINUX_HELLO_H
#define LINUX_HELLO_H

struct hello_info {
	unsigned long a;
	unsigned long b;
	char c[16];
};


struct hello_struct {
	int (*print_msg)(int a, struct hello_info * info);
	char name[16];
};


int hello_register(struct hello_struct * hs);
void hello_unregister(struct hello_struct * hs);

#endif /* LINUX_HELLO_H */
