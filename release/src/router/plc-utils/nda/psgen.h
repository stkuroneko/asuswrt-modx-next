/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   psgen.h - header for psgen utility
 *
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PSGEN_HEADER
#define PSGEN_HEADER

#define _GETOPT_H

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/files.h"

/*====================================================================*
 *  program constants;
 *--------------------------------------------------------------------*/

#define GAIN_ENABLE_OFFSET_6400 0x1F6E
#define AMP_CARRIERS 2880
#define INT_CARRIERS 1155
#define HPAV_CARRIER_WIDTH 24414
#define TWEAK_ABSOLUTE 0
#define TWEAK_RELATIVE 1

/*====================================================================*
 *   program macros;
 *--------------------------------------------------------------------*/

#define PRESCALER_FREQ_WIDTH(x) ((x)->carriers_per_prescaler * HPAV_CARRIER_WIDTH)

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

struct rs_item

{
	char * name;
	char * value;
	char * unit;
};

struct rs_file

{
	int item_count;
	int trace_start;
	int trace_end;
	char * path;
	struct rs_item * item;
};

struct notch

{
	double sf;
	double ef;
};

struct notch_set

{
	int count;
	double depth;
	struct notch * notch;
};

struct dev_config

{
	struct device_spec * dspec;
	struct prescalers * ps;
	signed gain_adj;
	uint32_t truncated;
	uint32_t notched;
	double average;
};

struct device_spec

{
	const char * name;
	unsigned prescaler_count;
	unsigned prescaler_unity;
	unsigned prescaler_max;
	unsigned carriers_per_prescaler;
	int tail_start;
	int (* update_pib) (const char *, struct dev_config *);
	int (* set_tx_gain) (struct _file_ *, int);
	int (* check_tx_gain) (int);
};

struct trace

{
	int count;
	double * freq;
	double * value;
};

struct prescalers

{
	uint32_t count;
	uint32_t * value;
};

struct tweak

{
	double sf;
	double ef;
	double sv;
	double ev;
	struct tweak * next;
};

const char * strtodouble (const char *, double *);
double estimate_trace_value (struct trace *, double, double);
int create_trace_rs (struct rs_file *, struct trace *);
int load_rs_file (const char *, struct rs_file *);
void free_rs_file (struct rs_file *);
void free_tweaks (struct tweak *);
int parse_tweak (struct tweak *, const char *);
int parse_range (const char *, double *, double *);
int create_trace_copy (struct trace *, struct trace *);
int reshape_trace (struct trace *, struct trace *, struct device_spec *, double, double);
void free_trace_data (struct trace *);
int find_trace_index_range (struct trace *, double, double, uint32_t *, uint32_t *);
int apply_tweak (struct trace *, struct tweak *, int);
int output_prescalers (struct trace *, struct trace *, struct device_spec *, int);
int replace_prescalers_around_notches (struct prescalers *, uint32_t);

/*====================================================================*
 *   currently generic
 *--------------------------------------------------------------------*/

double ps_to_amp (uint32_t, uint32_t);
uint32_t amp_to_ps (double, uint32_t, struct device_spec *);
uint32_t freq_to_index (double, struct device_spec *);
double index_to_freq (uint32_t, struct device_spec *);

/*--------------------------------------------------------------------*
 *   lynx/panther
 *--------------------------------------------------------------------*/

int psin (struct _file_ *, struct dev_config *);
int update_pib (const char *, struct dev_config *);
int set_tx_gain_6400 (struct _file_ *, int);
int set_tx_gain_7400 (struct _file_ *, int);
int check_tx_gain_6400 (int);
int check_tx_gain_7400 (int);
void dump_trace (struct trace *);
struct dev_config * generate_config (struct trace *, struct trace *, struct device_spec *, int, struct prescalers *, double, double);
struct prescalers * load_prescalers (const char *, struct device_spec *);
void print_config (struct dev_config *, FILE *);
void print_config_stats (struct dev_config *, FILE *);
void free_dev_config (struct dev_config *);
void show_prescalers (struct prescalers *, unsigned scale);
void show_trace (struct trace *, unsigned scale);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#ifdef WIN32

double rint (double);

#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



