#define STRLEN 16

struct A {
	unsigned int index;
	int num_a; 
	char string_b[STRLEN]; 
	int num_c;
	char string_d[STRLEN]; 
	int num_e;
	char string_f[STRLEN]; 
	int num_g; 
	int num_h; 
	int (*op0)(char *, char *);
};

extern int upload_A( struct A *a, char *buf );
