#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cse543-format-29.h"

int upload_A(struct A *a, char *buf)
{
	char *ptr = strtok( buf, "\n" );

	do {
		if ( strncmp( ptr, "num_a", 5 ) == 0) {
			a->num_a = atoi( ptr+6 );
		}

		if ( strncmp( ptr, "string_b", 8 ) == 0) {
			a->op0( a->string_b, ptr+9 );
		}

		if ( strncmp( ptr, "num_c", 5 ) == 0) {
			a->num_c = atoi( ptr+6 );
		}

		if ( strncmp( ptr, "string_d", 8 ) == 0) {
			a->op0( a->string_d, ptr+9 );
		}

		if ( strncmp( ptr, "num_e", 5 ) == 0) {
			a->num_e = atoi( ptr+6 );
		}

		if ( strncmp( ptr, "string_f", 8 ) == 0) {
			a->op0( a->string_f, ptr+9 );
		}

		if ( strncmp( ptr, "num_g", 5 ) == 0) {
			a->num_g = atoi( ptr+6 );
		}

		if ( strncmp( ptr, "num_h", 5 ) == 0) {
			a->num_h = atoi( ptr+6 );
		}

	} while (( ptr = strtok(NULL, "\n")) != NULL );
	return 0;
}
