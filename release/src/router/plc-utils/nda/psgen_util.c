/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   psgen_util.c - helpers for the psgen program
 *
 *   Contributor(s):
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PSGEN_UTIL_SOURCE
#define PSGEN_UTIL_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/chars.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/number.h"
#include "../nda/psgen.h"
#include "../pib/pib.h"

/*====================================================================*
 *
 * Read a double in from string s, scaling with a suffix;
 *
 * Returns pointer character where parsing stopped.
 *
 *--------------------------------------------------------------------*/

const char * strtodouble (const char * s, double * d)

{
	const char * p;
	int sign = 1;
	double div;
	div = 0;
	* d = 0;
	p = s;
	if (* p == '-')
	{
		sign = -1;
		++ p;
	}
	else if (* p == '+')
	{
		sign = 1;
		++ p;
	}
	while (* p != '\0')
	{
		if (isdigit ((unsigned char)* p))
		{
			if (div == 0)
			{
				* d = * d * 10 +  (* p - '0');
			}
			else 
			{
				* d = * d +  (* p - '0') / div;
				div *= 10;
			}
		}
		else if (* p == '.' && div == 0)
		{
			div = 10;
		}
		else 
		{
			break;
		}
		++ p;
	}
	* d *= sign;
	switch (* p)
	{
	case 'M':
		* d *= 1000000;
		++ p;
		break;
	case 'K':
	case 'k':
		* d *= 1000;
		++ p;
		break;
	}
	return (p);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

uint32_t freq_to_index (double freq, struct device_spec * d)

{
	return (rint ((freq / HPAV_CARRIER_WIDTH - 74.0) / d->carriers_per_prescaler));
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

double index_to_freq (uint32_t index, struct device_spec * d)

{
	return (HPAV_CARRIER_WIDTH * (index * d->carriers_per_prescaler +  74.0));
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

double ps_to_amp (uint32_t new_ps_val, uint32_t old_ps_val)

{
	if (old_ps_val == 0)
	{

/* XXX: what should really be done here? */

		old_ps_val = 1;
	}
	return (20 * log10 ((double) new_ps_val / old_ps_val));
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

uint32_t amp_to_ps (double amp, uint32_t old_ps_val, struct device_spec * d)

{
	double new_ps_val = rint (pow (10.0, amp / 20.0) * old_ps_val);
	if (new_ps_val > d->prescaler_max)
	{
		return (d->prescaler_max +  1);
	}
	return (uint32_t) new_ps_val;
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int create_trace_rs (struct rs_file * rs_file, struct trace * trace)

{
	int i;
	int j;
	const char * p;
	for (i = 0; i < rs_file->item_count; ++ i)
	{
		if (! strcasecmp (rs_file->item [i].name, "Values"))
		{
			rs_file->trace_start = i +  1;
			rs_file->trace_end = rs_file->trace_start +  atoi (rs_file->item [i].value) -1;
			if (rs_file->trace_end >= rs_file->item_count)
			{
				error (1, 0, "spectrum analyzer trace \"Values\" field is incorrect in file %s", rs_file->path);
			}
			break;
		}
	}
	if (i == rs_file->item_count)
	{
		error (1, 0, "no trace data found in input file %s", rs_file->path);
	}
	memset (trace, 0, sizeof (* trace));
	trace->count = rs_file->trace_end - rs_file->trace_start +  1;
	trace->freq = calloc (trace->count, sizeof (* trace->freq));
	if (trace->freq == NULL)
	{
		error (1, errno, "out of memory");
	}
	trace->value = calloc (trace->count, sizeof (* trace->value));
	if (trace->value == NULL)
	{
		error (1, errno, "out of memory");
	}
	for (i = 0, j = rs_file->trace_start; i < trace->count; ++ i, ++ j)
	{
		p = strtodouble (rs_file->item [j].name, & trace->freq [i]);
		if (* p != '\0')
		{
			error (1, 0, "invalid frequency value in spectrum analyzer trace: %s", rs_file->item [j].name);
		}
		p = strtodouble (rs_file->item [j].value, & trace->value [i]);
		if (* p != '\0')
		{
			error (1, 0, "invalid amplitude value in spectrum analyzer trace: %s", rs_file->item [j].value);
		}
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int load_rs_file (const char * path, struct rs_file * rs_file)

{
	int c;
	off_t fsize;
	char * data;
	char * p;
	char * start;
	int count;
	FILE * fp;
	fp = fopen (path, "r");
	if (fp == NULL)
	{
		error (1, errno, "could not open file %s", path);
	}
	memset (rs_file, 0, sizeof (* rs_file));
	if (fseek (fp, 0, SEEK_END) == -1)
	{
		error (1, errno, "could not seek in file %s", path);
	}
	fsize = ftell (fp);
	if (fseek (fp, 0, SEEK_SET) == -1)
	{
		error (1, errno, "could not seek in file %s", path);
	}
	if (fsize == 0)
	{
		error (1, 0, "input file %s is empty", path);
	}
	data = malloc (fsize);
	if (data == NULL)
	{
		error (1, errno, "out of memory");
	}
	p = data;
	while ((c = fgetc (fp)) != EOF)
	{
		if (c == '\n')
		{
			++ rs_file->item_count;
		}
		* p = c;
		++ p;
	}
	fclose (fp);
	rs_file->path = strdup (path);
	if (rs_file->path == NULL)
	{
		error (1, errno, "out of memory");
	}
	rs_file->item = calloc (rs_file->item_count, sizeof (struct rs_item));
	if (rs_file->item == NULL)
	{
		error (1, errno, "out of memory");
	}
	p = data;
	count = 0;
	while (count < rs_file->item_count)
	{

/* collect name */

		start = p;
		while (* p != ';' && * p != '\n' && * p != '\0')
		{
			++ p;
		}
		if (* p != ';')
		{
			error (1, 0, "unexpected end of line %d in file %s", count +  1, rs_file->path);
		}
		* p = '\0';
		++ p;
		rs_file->item [count].name = start;

/* collect value */

		start = p;
		while (* p != ';' && * p != '\n' && * p != '\0')
		{
			++ p;
		}
		if (* p != ';')
		{
			error (1, 0, "unexpected end of line %d in file %s", count +  1, rs_file->path);
		}
		* p = '\0';
		++ p;
		rs_file->item [count].value = start;

/* collect unit */

		start = p;
		while (* p != ';' && * p != '\n' && * p != '\0')
		{
			++ p;
		}
		if (* p != '\n')
		{
			error (1, 0, "unexpected item on line %d in file %s", count +  1, rs_file->path);
		}
		* p = '\0';
		++ p;
		rs_file->item [count].unit = start;
		++ count;
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void free_rs_file (struct rs_file * rs_file)

{
	free (rs_file->item [0].name);
	free (rs_file->path);
	free (rs_file->item);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void free_tweaks (struct tweak * t)

{
	if (t == NULL)
	{
		return;
	}
	free_tweaks (t->next);
	free (t);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void free_dev_config (struct dev_config * dconf)

{
	free (dconf->ps->value);
	free (dconf->ps);
	free (dconf);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int parse_range (const char * s, double * start, double * end)

{
	const char * p;
	p = s;
	p = strtodouble (p, start);
	if (* p != '-')
	{
		return (-1);
	}
	++ p;
	p = strtodouble (p, end);
	if (* p != '\0')
	{
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int parse_tweak (struct tweak * t, const char * s)

{
	const char * p;
	p = s;
	p = strtodouble (p, & t->sf);
	if (* p != ',')
	{
		return (-1);
	}
	++ p;
	p = strtodouble (p, & t->ef);
	if (* p != ',')
	{
		return (-1);
	}
	++ p;
	p = strtodouble (p, & t->sv);
	if (* p != ',')
	{
		return (-1);
	}
	++ p;
	p = strtodouble (p, & t->ev);
	if (* p != '\0')
	{
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int create_trace_copy (struct trace * dst, struct trace * src)

{
	memcpy (dst, src, sizeof (* dst));
	dst->freq = calloc (dst->count, sizeof (* dst->freq));
	if (dst->freq == NULL)
	{
		return (-1);
	}
	dst->value = calloc (dst->count, sizeof (* dst->value));
	if (dst->value == NULL)
	{
		free (dst->freq);
		return (-1);
	}
	memcpy (dst->freq, src->freq, dst->count * sizeof (* dst->freq));
	memcpy (dst->value, src->value, dst->count * sizeof (* dst->value));
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int reshape_trace (struct trace * dst, struct trace * src, struct device_spec * dspec, double start_freq, double end_freq)

{
	int i;
	dst->count = dspec->prescaler_count;
	dst->freq = calloc (dst->count, sizeof (* dst->freq));
	if (dst->freq == NULL)
	{
		return (-1);
	}
	dst->value = calloc (dst->count, sizeof (* dst->value));
	if (dst->value == NULL)
	{
		free (dst->freq);
		return (-1);
	}
	if (start_freq == -1)
	{
		start_freq = index_to_freq (0, dspec);
	}
	if (end_freq == -1)
	{
		end_freq = index_to_freq (dst->count, dspec);
	}
	for (i = 0; i < dst->count; ++ i)
	{
		dst->freq [i] = index_to_freq (i, dspec);
		if (dst->freq [i] < start_freq || dst->freq [i] +  PRESCALER_FREQ_WIDTH (dspec) > end_freq)
		{
			dst->value [i] = 0;
		}
		else 
		{
			dst->value [i] = estimate_trace_value (src, dst->freq [i], PRESCALER_FREQ_WIDTH (dspec));
		}
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void free_trace_data (struct trace * t)

{
	free (t->freq);
	free (t->value);
	memset (t, 0, sizeof (* t));
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int find_trace_index_range (struct trace * t, double freq_start, double freq_end, uint32_t * idx_start, uint32_t * idx_end)

{
	int i;
	int found_start = 0;
	* idx_start = * idx_end = 0;
	for (i = 0; i < t->count; ++ i)
	{
		if (t->freq [i] >= freq_end)
		{
			break;
		}
		if (t->freq [i] >= freq_start)
		{
			if (found_start == 0)
			{
				* idx_start = i;
				* idx_end = i;
				found_start = 1;
			}
			else 
			{
				* idx_end = i;
			}
		}
	}
	if (! found_start)
	{
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

double estimate_trace_value (struct trace * t, double freq, double width)

{
	uint32_t start_idx,
	end_idx;
	if (find_trace_index_range (t, freq, freq +  width, & start_idx, & end_idx) == -1)
	{
		error (1, 0, "could not find trace value for frequency range %f -> %f", freq, freq +  width);
	}
	else 
	{
		uint32_t i;
		double sum;
		sum = 0;
		for (i = start_idx; i <= end_idx; ++ i)
		{
			sum += t->value [i];
		}
		return (sum / (end_idx - start_idx +  1));
	}
	exit (1);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int apply_tweak (struct trace * trace, struct tweak * tweak, int mode)

{
	uint32_t i;
	double slope;
	uint32_t index_sf,
	index_ef;
	if (find_trace_index_range (trace, tweak->sf, tweak->ef, & index_sf, & index_ef) == -1)
	{
		error (1, 0, "could not find trace frequency range %f -> %f", tweak->sf, tweak->ef);
	}
	slope = (tweak->ev - tweak->sv) / (index_ef - index_sf);
	switch (mode)
	{
	case TWEAK_ABSOLUTE:
		for (i = index_sf; i <= index_ef; ++ i)
		{
			trace->value [i] = tweak->sv +  slope * (i - index_sf);
		}
		break;
	case TWEAK_RELATIVE:
		for (i = index_sf; i <= index_ef; ++ i)
		{
			trace->value [i] += tweak->sv +  slope * (i - index_sf);
		}
		break;
	default: 
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

struct dev_config * generate_config (struct trace * tr_old, struct trace * tr_new, struct device_spec * dspec, int gain_adj, struct prescalers * input_ps, double start_freq, double end_freq)

{
	unsigned i;
	double old_val;
	double new_val;
	double diff;
	uint32_t ps_val;
	struct dev_config * dconf;
	dconf = malloc (sizeof (* dconf));
	if (dconf == NULL)
	{
		error (0, errno, "out of memory");
		return (NULL);
	}
	dconf->ps = malloc (sizeof (* dconf->ps));
	if (dconf->ps == NULL)
	{
		error (0, errno, "out of memory");
		free (dconf);
		return (NULL);
	}
	dconf->ps->count = dspec->prescaler_count;
	dconf->ps->value = calloc (dconf->ps->count, sizeof (* dconf->ps->value));
	if (dconf->ps->value == NULL)
	{
		error (0, errno, "out of memory");
		free (dconf);
		return (NULL);
	}
	dconf->dspec = dspec;
	dconf->gain_adj = gain_adj;
	dconf->truncated = 0;
	dconf->average = 0;
	dconf->notched = 0;
	if (start_freq == -1)
	{
		start_freq = index_to_freq (0, dspec);
	}
	if (end_freq == -1)
	{
		end_freq = index_to_freq (dspec->prescaler_count, dspec);
	}
	for (i = 0; i < dspec->prescaler_count; ++ i)
	{
		double index_start_freq = index_to_freq (i, dspec);
		if (index_start_freq < start_freq || index_start_freq +  PRESCALER_FREQ_WIDTH (dspec) > end_freq)
		{
			diff = 0;
		}
		else 
		{
			old_val = tr_old->value [i];
			new_val = tr_new->value [i];
			diff = new_val - (old_val +  dconf->gain_adj);
		}
		ps_val = amp_to_ps (diff, input_ps->value [i], dspec);
		if (ps_val > dspec->prescaler_max)
		{
			ps_val = dspec->prescaler_max;
			++ dconf->truncated;
		}
		if (ps_val == 0)
		{
			++ dconf->notched;
		}
		dconf->ps->value [i] = ps_val;
		dconf->average += ps_val;
	}
	dconf->average /= dspec->prescaler_count;
	return (dconf);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void print_config_stats (struct dev_config * dconf, FILE * fp)

{
	fprintf (fp, "# Output Prescaler Information\n");
	fprintf (fp, "#\n");
	fprintf (fp, "# Average Prescaler Value: %f\n", dconf->average);
	fprintf (fp, "# Carriers Notched: %d\n", dconf->notched);
	fprintf (fp, "# AFE Gain Adjustment: %d dB\n", dconf->gain_adj);
	if (dconf->truncated)
	{
		fprintf (fp, "#\n");
		fprintf (fp, "# WARNING! Actual gain is lower than desired gain for %d carriers!\n", dconf->truncated);
		fprintf (fp, "#          The overall AFE gain may need to be increased.\n");
	}
	fprintf (fp, "#\n");
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void print_config (struct dev_config * dconf, FILE * fp)

{
	unsigned i;
	for (i = 0; i < dconf->ps->count; ++ i)
	{
		fprintf (fp, "%08d %08x\n", i, dconf->ps->value [i]);
	}
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int set_tx_gain_6400 (struct _file_ * pib, int gain)

{
	uint8_t gain_value;
	uint8_t gain_enable;
	if (lseek (pib->file, GAIN_ENABLE_OFFSET_6400, SEEK_SET) != GAIN_ENABLE_OFFSET_6400)
	{
		return (-1);
	}
	switch (gain)
	{
	case - 6:
		gain_value = 0x05;
		break;
	case - 4:
		gain_value = 0x03;
		break;
	case - 2:
		gain_value = 0x01;
		break;
	case 0:
		gain_value = 0x00;
		break;
	case 2:
	case 4:
	case 6:
		gain_value = gain;
		break;
	default: 
		error (0, 0, "invalid gain value: %d", gain);
		return (-1);
	}
	if (gain_value == 0)
	{
		gain_enable = 0;
	}
	else 
	{
		gain_enable = 1;
	}
	if (write (pib->file, & gain_enable, sizeof (gain_enable)) != 1)
	{
		error (1, errno, "could not enable output power level adjustment");
	}
	if (write (pib->file, & gain_value, sizeof (gain_value)) != 1)
	{
		error (1, errno, "could set output power level adjustment");
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int update_pib (const char * path, struct dev_config * dconf)

{
	struct _file_ pib;
	pib.name = path;
	pib.file = open (path, O_BINARY | O_RDWR);
	if (pib.file == -1)
	{
		error (1, errno, "could not open PIB file %s for updating", path);
	}
	if (lightning_pib_file (& pib))
	{
		error (1, 0, "invalid PIB file %s", path);
	}
	if (psin (& pib, dconf))
	{
		error (1, 0, "could not read prescalers from PIB file %s", path);
	}
	if (lightning_pib_lock (& pib))
	{
		error (1, 0, "could not update checksum in PIB file %s", path);
	}
	if (dconf->dspec->set_tx_gain != NULL)
	{
		if (dconf->dspec->set_tx_gain (& pib, dconf->gain_adj) == -1)
		{
			error (1, 0, "could not update TX gain in PIB file %s", path);
		}
	}
	if (lightning_pib_lock (& pib))
	{
		error (1, 0, "could not update checksum in PIB file %s", path);
	}
	close (pib.file);
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int ar7x00_psin (struct _file_ * pib, uint32_t value, uint32_t index)

{
	off_t offset = AMP_PRESCALER_OFFSET +  (index * 10 / 8);
	uint8_t bit_offset = (index * 10) % 8;
	uint16_t tmp;
	if (lseek (pib->file, offset, SEEK_SET) != offset)
	{
		return (-1);
	}
	if (read (pib->file, & tmp, sizeof (tmp)) != sizeof (tmp))
	{
		return (-1);
	}
	if (lseek (pib->file, offset, SEEK_SET) != offset)
	{
		return (-1);
	}
	value &= 0x03FF;
	tmp = LE16TOH (tmp);
	tmp &= ~ (0x03FF << bit_offset);
	tmp |= value << bit_offset;
	tmp = HTOLE16 (tmp);
	if (write (pib->file, & tmp, sizeof (tmp)) != sizeof (tmp))
	{
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int psin (struct _file_ * pib, struct dev_config * dconf)

{
	uint32_t value;
	unsigned limit;
	unsigned i;
	limit = pibscalers (pib);
	if ((limit != INT_CARRIERS) && (limit != AMP_CARRIERS))
	{
		error (1, 0, "Don't understand this PIB's prescaler format");
	}
	if (limit == INT_CARRIERS)
	{
		if (lseek (pib->file, INT_PRESCALER_OFFSET, SEEK_SET) != INT_PRESCALER_OFFSET)
		{
			error (1, errno, "Can't seek %s", pib->name);
		}
	}
	if (dconf->dspec->prescaler_count != limit)
	{
		error (1, 0, "PIB file type does not match device target type");
	}
	for (i = 0; i < limit; ++ i)
	{
		value = dconf->ps->value [i];
		if (limit == INT_CARRIERS)
		{
			if (write (pib->file, & value, sizeof (value)) != sizeof (value))
			{
				error (1, errno, "Can't save %s", pib->name);
			}
		}
		else if (limit == AMP_CARRIERS)
		{
			if (value & ~ 0x03FF)
			{
				error (1, errno, "Position %d has invalid prescaler value", i);
			}
			if (ar7x00_psin (pib, value, i))
			{
				error (1, errno, "Can't update %s", pib->name);
			}
		}
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int check_tx_gain_6400 (int gain_adj)

{
	if ((gain_adj & 1) || gain_adj < - 6 || gain_adj > 6)
	{
		error (1, 0, "invalid gain adjustment, must be one of -6, -4, -2, 0, 2, 4, 6");
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

#ifdef WIN32

double rint (double x)

{
	if (x > 0)
	{
		return (floor (x +  0.5));
	}
	else if (x < 0)
	{
		return (ceil (x - 0.5));
	}
	return (x);
}

#endif

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

struct prescalers * load_prescalers (const char * path, struct device_spec * d)

{
	struct prescalers * ps;
	uint32_t i;
	FILE * fp;
	int c;
	uint32_t count;
	uint32_t index;
	uint32_t value;
	ps = malloc (sizeof (* ps));
	if (ps == NULL)
	{
		error (1, errno, "out of memory");
	}
	memset (ps, 0, sizeof (* ps));
	ps->count = d->prescaler_count;
	ps->value = calloc (sizeof (* ps->value), ps->count);
	if (path == NULL)
	{
		for (i = 0; i < ps->count; ++ i)
		{
			ps->value [i] = d->prescaler_unity;
		}
		return (ps);
	}
	fp = fopen (path, "rb");
	if (fp == NULL)
	{
		error (1, errno, "could not open %s", path);
		free (ps);
		return (NULL);
	}
	count = 0;
	while ((c = getc (fp)) != EOF)
	{
		if (isspace (c))
		{
			continue;
		}
		if ((c == '#') || (c == ';'))
		{
			do 
			{
				c = getc (fp);
			}
			while (nobreak (c));
			continue;
		}
		index = 0;
		while (isdigit (c))
		{
			index *= 10;
			index += c - '0';
			c = getc (fp);
		}
		if (index != count)
		{
			error (1, ECANCELED, "Carrier %d out of order", index);
		}
		while (isblank (c))
		{
			c = getc (fp);
		}
		value = 0;
		while (isxdigit (c))
		{
			value *= 16;
			value += todigit (c);
			c = getc (fp);
		}
		if (count < d->prescaler_count)
		{
			ps->value [count] = value;
		}
		while (nobreak (c))
		{
			c = getc (fp);
		}
		count++;
	}
	if (count < d->prescaler_count)
	{
		error (1, 0, "Not enough prescalers");
	}
	else if (count > d->prescaler_count)
	{
		fprintf (stderr, "Warning: %d prescalers ignored at end of input file\n", count - d->prescaler_count);
	}
	fclose (fp);
	return (ps);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int replace_ps_around_notch (struct prescalers * ps, uint32_t width, uint32_t notch_start, uint32_t notch_end)

{
	uint32_t i;
	uint32_t avg;

/* replace notches on left of notch */

	if (notch_start > 0)
	{
		if (notch_start < width * 2)
		{
			fprintf (stderr, "error: not enough prescalers on left side of notch to copy data from\n");
			return (-1);
		}
		avg = 0;
		for (i = notch_start - 2 * width; i < notch_start - width; ++ i)
		{
			avg += ps->value [i];
		}
		avg /= width;
		for (i = notch_start - width; i < notch_start; ++ i)
		{
			ps->value [i] = avg;
		}
	}

/* replace carriers on right of notch */

	if (notch_end +  1 < ps->count)
	{
		if (notch_end +  2 * width > ps->count)
		{
			fprintf (stderr, "error: not enough prescalers on right side of notch to copy data from\n");
			return (-1);
		}
		avg = 0;
		for (i = notch_end +  width; i < notch_end +  2 * width; ++ i)
		{
			avg += ps->value [i];
		}
		avg /= width;
		for (i = notch_end; i < notch_end +  width; ++ i)
		{
			ps->value [i] = avg;
		}
	}
	return (0);
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

int replace_prescalers_around_notches (struct prescalers * ps, uint32_t width)

{
	uint32_t i = 0;
	uint32_t notch_start,
	notch_end;
	int in_notch = 0;
	for (i = 0; i < ps->count; i ++)
	{
		if (ps->value [i] != 0)
		{
			break;
		}
	}
	for (; i < ps->count; ++ i)
	{

// for (i = 0; i < ps->count; ++i) {

		if (ps->value [i] == 0)
		{
			if (in_notch == 0)
			{
				in_notch = 1;
				notch_start = i;
			}
		}
		else 
		{
			if (in_notch)
			{
				in_notch = 0;
				notch_end = i;
				if (replace_ps_around_notch (ps, width, notch_start, notch_end) == -1)
				{
					return (-1);
				}
			}
		}
	}
	if (in_notch)
	{
		notch_end = i -1;
		if (replace_ps_around_notch (ps, width, notch_start, notch_end) == -1)
		{
			return (-1);
		}
	}
	return (0);
}

/*====================================================================*
 *
 *   void show_prescalers (struct prescalers * ps, uint32_t scale);
 *
 *
 *--------------------------------------------------------------------*/

void show_prescalers (struct prescalers * ps, unsigned scale)

{
	uint32_t index;
	for (index = 0; index < ps->count; index++)
	{
		uint32_t value = ps->value [index];
		printf ("%04d %3d", index, value);
		if (value)
		{
			printf (" ");
			while (value > (scale >> 1))
			{
				printf ("#");
				value -= scale;
			}
		}
		printf ("\n");
	}
	printf ("\n");
	return;
}

/*====================================================================*
 *
 *
 *
 *--------------------------------------------------------------------*/

void show_trace (struct trace * trace, unsigned scale)

{
	signed index = trace->count;
	for (index = 0; index < trace->count; index++)
	{
		printf ("%8.3f %8.3f", trace->freq [index], trace->value [index]);
		printf ("\n");
	}
	printf ("\n");
	return;
}

#endif

