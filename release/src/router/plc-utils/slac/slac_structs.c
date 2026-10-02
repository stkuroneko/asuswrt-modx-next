/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void slac_structs ()
 *
 *   slac.h
 *
 *--------------------------------------------------------------------*/

#include <unistd.h>

#include "../slac/slac.h"

void slac_structs () 

{ 
	fprintf (stderr, "sizeof struct cm_sta_identity_request %d\n", sizeof (struct cm_sta_identity_request)); 
	fprintf (stderr, "sizeof struct cm_sta_identity_confirm %d\n", sizeof (struct cm_sta_identity_confirm)); 
	fprintf (stderr, "sizeof struct cm_slac_param_request %d\n", sizeof (struct cm_slac_param_request)); 
	fprintf (stderr, "sizeof struct cm_slac_param_confirm %d\n", sizeof (struct cm_slac_param_confirm)); 
	fprintf (stderr, "sizeof struct cm_start_atten_char_indicate %d\n", sizeof (struct cm_start_atten_char_indicate)); 
	fprintf (stderr, "sizeof struct cm_start_atten_char_response %d\n", sizeof (struct cm_start_atten_char_response)); 
	fprintf (stderr, "sizeof struct cm_atten_char_indicate %d\n", sizeof (struct cm_atten_char_indicate)); 
	fprintf (stderr, "sizeof struct cm_atten_char_response %d\n", sizeof (struct cm_atten_char_response)); 
	fprintf (stderr, "sizeof struct cm_mnbc_sound_indicate %d\n", sizeof (struct cm_mnbc_sound_indicate)); 
	fprintf (stderr, "sizeof struct cm_validate_request %d\n", sizeof (struct cm_validate_request)); 
	fprintf (stderr, "sizeof struct cm_validate_confirm %d\n", sizeof (struct cm_validate_confirm)); 
	fprintf (stderr, "sizeof struct cm_slac_match_request %d\n", sizeof (struct cm_slac_match_request)); 
	fprintf (stderr, "sizeof struct cm_slac_match_confirm %d\n", sizeof (struct cm_slac_match_confirm)); 
	return; 
} 

