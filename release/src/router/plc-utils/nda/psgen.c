/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   psgen.c - generate prescaler values based on trace results;
 *
 *   Contributor(s):
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/error.h"
#include "../tools/flags.h"
#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/symbol.h"
#include "../tools/types.h"
#include "../tools/version.h"
#include "../nda/psgen.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/error.c"
#include "../tools/lookup.c"
#include "../tools/todigit.c"
#include "../tools/fdchecksum32.c"
#endif

#ifndef MAKEFILE
#include "../pib/pibscalers.c"
#include "../pib/lightning_pib_file.c"
#include "../pib/lightning_pib_lock.c"
#endif

#ifndef MAKEFILE
#include "../nda/psgen_util.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define PSGEN_SILENCE (1 << 0)
#define PSGEN_VERBOSE (1 << 1)
#define PSGEN_FLATTEN (1 << 2)

/*====================================================================*
 *   USA notches;
 *--------------------------------------------------------------------*/

struct notch usa_notches [] =

{
	{
		1806636.000000,
		2099604.000000
	},
	{
		3417960.000000,
		4101552.000000
	},
	{
		5249010.000000,
		5517564.000000
	},
	{
		6909162.000000,
		7397442.000000
	},
	{
		10009740.000000,
		10253880.000000
	},
	{
		13915980.000000,
		14453088.000000
	},
	{
		17993118.000000,
		18286086.000000
	},
	{
		20922798.000000,
		21557562.000000
	},
	{
		24804624.000000,
		25097592.000000
	},
	{
		27929616.000000,
		30004806.000000
	}
};

/*--------------------------------------------------------------------*
 *   Japan notches;
 *--------------------------------------------------------------------*/

struct notch japan_notches [] =

{
	{
		1806636.000000,
		2124018.000000
	},
	{
		3417960.000000,
		4125966.000000
	},
	{
		5249010.000000,
		5517564.000000
	},
	{
		5932602.000000,
		6249984.000000
	},
	{
		6884748.000000,
		7446270.000000
	},
	{
		9472632.000000,
		9887670.000000
	},
	{
		9985326.000000,
		10302708.000000
	},
	{
		13891566.000000,
		14477502.000000
	},
	{
		17993118.000000,
		18286086.000000
	},
	{
		20922798.000000,
		21557562.000000
	},
	{
		24804624.000000,
		25097592.000000
	},
	{
		27929616.000000,
		30004806.000000
	}
};

/*--------------------------------------------------------------------*
 * Permanent EN50561 Notches;
 *--------------------------------------------------------------------*/

struct notch permanent_en50561_notches [] =

{
	{
		1800000.000000,
		2000000.000000
	},
	{
		2850000.000000,
		3025000.000000
	},
	{
		3400000.000000,
		4000000.000000
	},
	{
		4650000.000000,
		4700000.000000
	},
	{
		5250000.000000,
		5450000.000000
	},
	{
		5480000.000000,
		5680000.000000
	},
	{
		6525000.000000,
		6685000.000000
	},
	{
		7000000.000000,
		7300000.000000
	},
	{
		8815000.000000,
		8965000.000000
	},
	{
		10005000.000000,
		10150000.000000
	},
	{
		11275000.000000,
		11400000.000000
	},
	{
		13260000.000000,
		13360000.000000
	},
	{
		14000000.000000,
		14350000.000000
	},
	{
		17900000.000000,
		17970000.000000
	},
	{
		18068000.000000,
		18168000.000000
	},
	{
		21000000.000000,
		21450000.000000
	},
	{
		21924000.000000,
		22000000.000000
	},
	{
		24890000.000000,
		24990000.000000
	},
	{
		26960000.000000,
		27410000.000000
	},
	{
		28000000.000000,
		29700000.000000
	}
};

/*--------------------------------------------------------------------*
 * Dynamic EN50561 Notches;
 *--------------------------------------------------------------------*/

struct notch dynamic_en50561_notches [] =

{
	{
		2300000.000000,
		2498000.000000
	},
	{
		3200000.000000,
		3400000.000000
	},
	{
		3900000.000000,
		4050000.000000
	},
	{
		4750000.000000,
		5110000.000000
	},
	{
		5750000.000000,
		6200000.000000
	},
	{
		7200000.000000,
		7700000.000000
	},
	{
		9300000.000000,
		9950000.000000
	},
	{
		11550000.000000,
		12100000.000000
	},
	{
		13550000.000000,
		13900000.000000
	},
	{
		15050000.000000,
		15850000.000000
	},
	{
		17400000.000000,
		17900000.000000
	},
	{
		18900000.000000,
		19020000.000000
	},
	{
		21450000.000000,
		21850000.000000
	},
	{
		25650000.000000,
		26100000.000000
	}
};

/*--------------------------------------------------------------------*
 * All EN50561 Notches;
 *--------------------------------------------------------------------*/

struct notch all_en50561_notches [] =

{
	{
		1806640.625000,
		2514648.438000
	},
	{
		2832031.250000,
		4077148.438000
	},
	{
		4638671.875000,
		6225585.938000
	},
	{
		6494140.625000,
		6713867.188000
	},
	{
		6982421.875000,
		7739257.812500
	},
	{
		8789062.500000,
		9008789.062500
	},
	{
		9277343.750000,
		10180664.062500
	},
	{
		11230468.750000,
		12133789.062500
	},
	{
		13232421.875000,
		14379882.812500
	},
	{
		15039062.500000,
		15893554.687500
	},
	{
		17382812.500000,
		18188476.562500
	},
	{
		18896484.375000,
		19067382.812500
	},
	{
		20996093.750000,
		22045898.437500
	},
	{
		24853515.625000,
		25024414.062500
	},
	{
		25634765.625000,
		26147460.937500
	},
	{
		26953125.000000,
		27416992.187500
	},
	{
		27978515.625000,
		29760742.187500
	},
};

/*--------------------------------------------------------------------*
 *   notch sets;
 *--------------------------------------------------------------------*/

#define NOTCH_SET_NONE       0
#define NOTCH_SET_USA        1
#define NOTCH_SET_JAPAN      2
#define NOTCH_SET_EN50561_PERM 3
#define NOTCH_SET_EN50561_ALL 4
#define NOTCH_SETS           5

struct _code_ notch_set_names [NOTCH_SETS] =

{
	{
		NOTCH_SET_NONE,
		"none"
	},
	{
		NOTCH_SET_USA,
		"usa"
	},
	{
		NOTCH_SET_JAPAN,
		"japan"
	},
	{
		NOTCH_SET_EN50561_PERM,
		"en50561_perm"
	},
	{
		NOTCH_SET_EN50561_ALL,
		"en50561_all"
	}
};

/*--------------------------------------------------------------------*
 *
 *--------------------------------------------------------------------*/

struct notch_set notch_sets [NOTCH_SETS] =

{
	{
		0,
		0,
		NULL
	},
	{
		SIZEOF (usa_notches),
		-1000,
		usa_notches
	},
	{
		SIZEOF (japan_notches),
		-1000,
		japan_notches
	},
	{
		SIZEOF (permanent_en50561_notches),
		-1000,
		permanent_en50561_notches
	},
	{
		SIZEOF (all_en50561_notches),
		-1000,
		all_en50561_notches
	}
};

/*--------------------------------------------------------------------*
 *
 *--------------------------------------------------------------------*/

#define DEVICE_SPEC_AR6400  0
#define DEVICE_SPEC_AR7400  1
#define DEVICE_SPEC_QCA6410 2
#define DEVICE_SPEC_QCA7420 3
#define DEVICE_SPEC_QCA7500 4
#define DEVICE_SPECS        5

#define AR7400_NAME "ar7400"
#define AR6400_NAME "ar6400"
#define QCA7420_NAME "ar7420"
#define QCA6410_NAME "qca6410"
#define QCA7500_NAME "qca7500"

struct _code_ device_spec_name [DEVICE_SPECS] =

{
	{
		DEVICE_SPEC_AR6400,
		AR6400_NAME
	},
	{
		DEVICE_SPEC_AR7400,
		AR7400_NAME
	},
	{
		DEVICE_SPEC_QCA6410,
		QCA6410_NAME
	},
	{
		DEVICE_SPEC_QCA7420,
		QCA7420_NAME
	},
	{
		DEVICE_SPEC_QCA7500,
		QCA7500_NAME
	}
};

struct device_spec device_spec [DEVICE_SPECS] =

{
	{
		AR6400_NAME,
		1155,
		256,
		511,
		1,
		1070,
		update_pib,
		set_tx_gain_6400,
		check_tx_gain_6400
	},
	{
		AR7400_NAME,
		2880,
		512,
		1023,
		1,
		2690,
		update_pib,
		NULL,
		NULL
	},
	{
		QCA6410_NAME,
		578,
		128,
		255,
		2,
		-1,
		NULL,
		NULL,
		NULL
	},
	{
		QCA7420_NAME,
		1345,
		128,
		255,
		2,
		-1,
		NULL,
		NULL,
		NULL
	},
	{
		QCA7500_NAME,
		1345,
		128,
		255,
		2,
		-1,
		NULL,
		NULL,
		NULL
	}
};

/*--------------------------------------------------------------------*
 * define program defaults;
 *--------------------------------------------------------------------*/

#define DEFAULT_DEVICE_NAME "ar6400"
#define DEFAULT_NOTCH_SET "usa"
#define DEFAULT_INPUT_FORMAT "rs"
#define DEFAULT_CARRIER_REPLACE_WIDTH 0
#define DEFAULT_GAIN_ADJUST 0

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

int main (int argc, const char * argv [])

{
	static const char * optv [] =
	{
		"d:F:G:i:N:n:P:p:r:T:v",
		"input_file [> output file]",
		"Prescaler Generator",
		"d s\tTarget device is (s) [" LITERAL (DEFAULT_DEVICE_NAME) "] (ar6400, ar7400, qca6410, ar7420)",
		"F n\tFlatten trace to level (n) (units match units of spectrum analyzer trace)",
		"G n\tOutput power level gain adjustment is (n) dB [" LITERAL (DEFAULT_GAIN_ADJUST) "]",
		"i s\tInput format is (s) [" LITERAL (DEFAULT_INPUT_FORMAT) "]",
		"N s\tNotch to match regulatory requirements for (s) [" LITERAL (NOTCH_SET_DEFAULT) "] (none, usa, japan, en50561_perm, en50561_all)",
		"n x\tReplace (x) carriers around notches [" LITERAL (DEFAULT_CARRIER_REPLACE_WIDTH) "]",
		"P f\tSave prescalers and gain to pib file (f)",
		"p f\tLoad prescaler values used during spectrum analyzer capture from prescaler file (f) (otherwise unity is assumed)",
		"r x-y\tModify prescalers in frequency range [x,y] (eg. 0-30M is 0Hz to 30MHz)",
		"T sf,ef,sd,ed\tTweak prescalers from sf to ef (start freq, end freq) by sd (start delta) at sf, linearly changing to ed (end delta) at ef",
		"v\tverbose messages",
		(const char *) (0)
	};
	unsigned scale = 2;
	double flatten;
	signed gain_adj = DEFAULT_GAIN_ADJUST;
	char * notch_type = DEFAULT_NOTCH_SET;
	signed notch_set;
	char * target_device = DEFAULT_DEVICE_NAME;
	int device_type;
	char * input_format = DEFAULT_INPUT_FORMAT;
	char * pib_path = NULL;
	char * input_prescaler_path = NULL;
	struct rs_file rs_file;
	struct trace trace;
	struct trace orig_trace;
	struct trace shaped_trace;
	struct tweak * tweak = NULL;
	struct tweak * tweak_tail = NULL;
	struct dev_config * dconf;
	struct device_spec * dspec;
	uint32_t carrier_replace_width = DEFAULT_CARRIER_REPLACE_WIDTH;
	double start_freq = -1;
	double end_freq = -1;
	const char * p;
	struct tweak * t = (struct tweak *) (0);
	struct prescalers * input_ps;
	signed index;
	flag_t flags = (flag_t) (0);
	signed c;
	optind = 1;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'd':
			target_device = optarg;
			break;
		case 'F':
			_setbits (flags, PSGEN_FLATTEN);
			p = strtodouble (optarg, & flatten);
			if (* p != '\0')
			{
				error (1, 0, "invalid value provided to option -F: %s", optarg);
			}
			break;
		case 'G':
			gain_adj = atoi (optarg);
			break;
		case 'i':
			input_format = optarg;
			break;
		case 'N':
			notch_type = optarg;
			break;
		case 'n':
			carrier_replace_width = atoi (optarg);
			break;
		case 'P':
			pib_path = optarg;
			break;
		case 'p':
			input_prescaler_path = optarg;
			break;
		case 'r':
			if (parse_range (optarg, & start_freq, & end_freq) == -1)
			{
				error (1, 0, "invalid value provided to option -r: %s", optarg);
			}
			if (start_freq < 0 || end_freq < 0 || start_freq > end_freq)
			{
				error (1, 0, "invalid value provided to option -r: %s", optarg);
			}
			break;
		case 'T':
			{
				struct tweak * new_tweak;
				new_tweak = malloc (sizeof (* new_tweak));
				if (new_tweak == NULL)
				{
					error (1, errno, "out of memory");
				}
				memset (new_tweak, 0, sizeof (* new_tweak));
				if (parse_tweak (new_tweak, optarg) == -1)
				{
					error (1, 0, "invalid tweak provided to option -T: %s", optarg);
				}
				if (tweak_tail != NULL)
				{
					tweak_tail->next = new_tweak;
				}
				if (tweak == NULL)
				{
					tweak = new_tweak;
				}
				tweak_tail = new_tweak;
			}
			break;
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
	{
		putoptv (optv);
		exit (1);
	}
	device_type = lookup (target_device, device_spec_name, DEVICE_SPECS);
	if (device_type == -1)
	{
		error (1, 0, "unknown device type \"%s\"", target_device);
	}
	dspec = & device_spec [device_type];
	notch_set = lookup (notch_type, notch_set_names, NOTCH_SETS);
	if (notch_set == -1)
	{
		error (1, 0, "unknown notch set \"%s\"", notch_type);
	}
	if (strcasecmp (input_format, DEFAULT_INPUT_FORMAT))
	{
		error (1, 0, "only input format rs is currently supported");
	}
	if (gain_adj != 0)
	{
		if (dspec->check_tx_gain == NULL)
		{
			error (1, 0, "gain adjustment is not (yet) supported for device type %s", target_device);
		}
		if (dspec->check_tx_gain (gain_adj) == -1)
		{
			error (1, 0, "invalid gain adjustment provided");
		}
	}
	if (load_rs_file (argv [0], & rs_file) == -1)
	{
		error (1, 0, "failed to load %s", argv [0]);
	}
	if (create_trace_rs (& rs_file, & orig_trace) == -1)
	{
		error (1, 0, "could not convert input file into internal format");
	}
	free_rs_file (& rs_file);
	if (reshape_trace (& shaped_trace, & orig_trace, dspec, start_freq, end_freq) == -1)
	{
		error (1, 0, "could not reshape trace to match prescalers");
	}
	free_trace_data (& orig_trace);

/* make copy of shaped trace */

	if (create_trace_copy (& trace, & shaped_trace) == -1)
	{
		error (1, 0, "could not copy trace");
	}

/* flatten trace */

	if (_anyset (flags, PSGEN_FLATTEN))
	{
		for (index = 0; index < trace.count; ++ index)
		{
			trace.value [index] = flatten;
		}
	}

/* apply tweaks */

	for (t = tweak; t != NULL; t = t->next)
	{
  		apply_tweak (& trace, t, TWEAK_RELATIVE);
	}

/* apply notching */

	if (notch_set != NOTCH_SET_NONE)
	{
		for (index = 0; index < notch_sets [notch_set].count; ++ index)
		{
			struct tweak tw;
			tw.sf = notch_sets [notch_set].notch [index].sf;
			tw.ef = notch_sets [notch_set].notch [index].ef;
			tw.ev = tw.sv = notch_sets [notch_set].depth;
			apply_tweak (& trace, & tw, TWEAK_ABSOLUTE);
		}

/* remove the tail (if any) */

		if (dspec->tail_start != -1)
		{
			for (index = dspec->tail_start; index < trace.count; ++ index)
			{
				trace.value [index] = notch_sets [notch_set].depth;
			}
		}
	}

/* load input prescalers (or generate default set if NULL is specified for input file) */

	input_ps = load_prescalers (input_prescaler_path, dspec);
	if (input_ps == NULL)
	{
		error (1, 0, "failed to load/generate input prescaler file");
	}

/* generate prescalers based on device spec, two traces, and gain adjustment */

	dconf = generate_config (& shaped_trace, & trace, dspec, gain_adj, input_ps, start_freq, end_freq);
	if (dconf == NULL)
	{
		error (1, 0, "could not generate device configuration");
	}
	show_prescalers (dconf->ps, scale);

/* post process -- adjust config around the notches */

	if (carrier_replace_width)
	{
		if (replace_prescalers_around_notches (dconf->ps, carrier_replace_width) == -1)
		{
			error (1, 0, "could not replace prescaler data around notches");
		}
	}
	if (pib_path == NULL)
	{
		print_config_stats (dconf, stdout);
		print_config (dconf, stdout);
	}
	else 
	{
		if (dspec->update_pib == NULL)
		{
			error (1, 0, "a PIB is not yet supported for device type %s", dspec->name);
		}
		if (dspec->update_pib (pib_path, dconf) == -1)
		{
			error (1, 0, "could not save configuration to PIB");
		}
	}
	print_config_stats (dconf, stderr);
	free_trace_data (& trace);
	free_trace_data (& shaped_trace);
	free_dev_config (dconf);
	free_tweaks (tweak);
	return (0);
}

