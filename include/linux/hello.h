#ifndef LINUX_HELLO_H
#define LINUX_HELLO_H

struct hello_struct {
	int (*print_msg)(int a);
	char name[16];
};


int hello_register(struct hello_struct * hs);
void hello_unregister(struct hello_struct * hs);

#endif /* LINUX_HELLO_H */
