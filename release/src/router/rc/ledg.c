/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <shared.h>
#include <shutils.h>
#include <rc.h>
#include <math.h>

#define NUM_OF_COLOR		4
#if defined(GSAX3000) || defined(GSAX5400)
#define NUM_OF_CLED		15
#elif defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
#define NUM_OF_CLED		9
#else
#define NUM_OF_CLED		12
#endif

static struct itimerval itv;
static int direction = 2;
static float fH = 0, fS = 0, fV = 0;
static int reverse = 0;
static int idx = 0;
#if defined(GSAX3000) || defined(GSAX5400)
int cled_gpio[NUM_OF_CLED] = { 1, 3, 4, 7, 8, 9, 10, 12, 15, 23, 17, 16, 14, 27, 30 };
#elif defined(DSL_AX82U)
int cled_gpio[NUM_OF_CLED] = { 28, 30, 10, 13, 14, 19, 7, 8, 9, 4, 27, 2 };
#elif defined(TUFAX5400)
int cled_gpio[NUM_OF_CLED] = { 12, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
#elif defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
int cled_gpio[NUM_OF_CLED] = { 2, 4, 3, 5, 8, 7, 14, 16, 15, -1, -1, -1 };
#else
int cled_gpio[NUM_OF_CLED] = { 1, 3, 4, 7, 8, 9, 10, 12, 15, 23, 17, 16 };
#endif
#if 0
#ifdef GTAX6000
int cled_gpio2[4] = { 18, 19, 20, 21 };
#endif
#endif
static int color_valid;
static int color_manual_valid[LEDG_SCHEME_MAX - 2] = { 0, 0, 0, 0, 0, 0, 0, 0 };
static int color_manual[LEDG_SCHEME_MAX - 2][NUM_OF_CLED] = {
#if defined(GSAX3000) || defined(GSAX5400)
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
#else
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
				{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
			};
static int color[NUM_OF_COLOR][NUM_OF_CLED] = {
#if defined(GSAX3000) || defined(GSAX5400)
				{ 0, 100, 128, 0, 50, 128, 0, 0, 128, 30, 0, 128, 30, 0, 128 },
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
				{ 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128 },
				{ 0, 50, 128, 0, 50, 128, 0, 50, 128, 0, 50, 128, 0, 50, 128 },
#elif defined(GTAXE16000)
				{ 20, 0, 128, 110, 0, 100, 128, 0, 80 },
				{ 128, 0, 128, 128, 0, 128, 128, 0, 128 },
				{ 20, 0, 128, 110, 0, 100, 128, 0, 80 },
				{ 0, 50, 128, 0, 50, 128, 0, 50, 128 },
#else
#ifdef GTAX6000
				{ 128, 0, 0, 128, 20, 0, 128, 50, 0 },
#else
				{ 0, 100, 128, 0, 50, 128, 0, 0, 128, 30, 0, 128 },
#endif
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
#if defined(TUFAX5400)
				{ 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
#elif defined(GTAX6000)
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
#else
				{ 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128 },
#endif
#ifdef TUFAX5400
				{ 0, 30, 128, 0, 50, 128, 0, 50, 128, 0, 50, 128 }
#else
				{ 0, 50, 128, 0, 50, 128, 0, 50, 128, 0, 50, 128 },
#endif
#endif
			};
/* Evolution Mode Color Set*/
static int color2[6][NUM_OF_CLED] = {
#if defined(GSAX3000) || defined(GSAX5400)
				{ 0, 60, 128, 0, 128, 100, 0, 128, 60, 0, 128, 30, 0, 128, 30 },
				{ 0, 0, 128, 0, 50, 128, 0, 80, 128, 0, 128, 128, 0, 128, 128 },
				{ 100, 0, 128, 60, 0, 128, 30, 0, 128, 0, 0, 128, 0, 0, 128 },
				{ 0, 0, 128, 30, 0, 128, 60, 0, 128, 100, 0, 128, 100, 0, 128 },
				{ 0, 100, 128, 0, 80, 128, 0, 50, 128, 0, 0, 128, 0, 0, 128 },
				{ 0, 128, 30, 0, 128, 60, 0, 128, 100, 0, 60, 128, 0, 60, 128 },
#elif defined(GTAX6000)
				{ 128, 0, 0, 128, 50, 0, 128, 100, 0 },
				{ 128, 0, 0, 60, 0, 60, 0, 0, 128 },
 				{ 128, 0, 0, 80, 0, 60, 40, 0, 80 },
				{ 50, 128, 128, 80, 100, 80, 128, 30, 0 },
				{ 80, 128, 128, 0, 0, 128, 0, 0, 128 },
				{ 128, 0, 0, 0, 128, 0, 0, 0, 128 },
#elif defined(GTAXE16000)
				{ 0, 60, 100, 0, 110, 60, 0, 128, 30 },
				{ 0, 10, 128, 0, 90, 128, 0, 110, 128 },
 				{ 90, 0, 128, 20, 0, 128, 0, 0, 128 },
				{ 20, 0, 128, 110, 0, 100, 128, 0, 80 },
				{ 0, 100, 128, 0, 30, 128, 0, 10, 128 },
				{ 0, 128, 30, 0, 110, 60, 0, 60, 100 },
#else
				{ 0, 60, 128, 0, 128, 100, 0, 128, 60, 0, 128, 30 },
				{ 0, 0, 128, 0, 50, 128, 0, 80, 128, 0, 128, 128 },
				{ 100, 0, 128, 60, 0, 128, 30, 0, 128, 0, 0, 128 },
				{ 0, 0, 128, 30, 0, 128, 60, 0, 128, 100, 0, 128 },
				{ 0, 100, 128, 0, 80, 128, 0, 50, 128, 0, 0, 128 },
				{ 0, 128, 30, 0, 128, 60, 0, 128, 100, 0, 60, 128 },
#endif
			};
/* Evolution Mode Cb2 Model Color set */
static int color2_cb2[5][NUM_OF_CLED] = {
				{ 76, 128, 110, 90, 100, 70, 128, 70, 50, 128, 50, 35 },
				{ 76, 128, 110, 70, 128, 90, 60, 128, 50, 50, 128, 20 },
				{ 76, 128, 110, 70, 100, 128, 50, 60, 128, 0, 0, 128 },
				{ 76, 128, 110, 100, 80, 50, 110, 70, 30, 128, 30, 0 },
				{ 76, 128, 110, 70, 80, 90, 60, 20, 40, 40, 10, 40 },
			};
/* General Rainbow Mode Color Set*/
static int color3[17][NUM_OF_CLED] = {
#if defined(GSAX3000) || defined(GSAX5400)
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
				{ 128, 40, 0, 128, 40, 0, 128, 40, 0, 128, 40, 0, 128, 40, 0 },
				{ 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0 },
				{ 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0 },
				{ 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0 },
				{ 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0 },
				{ 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0 },
				{ 0, 128, 40, 0, 128, 40, 0, 128, 40, 0, 128, 40, 0, 128, 40 },
				{ 0, 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80 },
				{ 0, 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128 },
				{ 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128 },
				{ 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128 },
				{ 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128 },
				{ 32, 0, 128, 32, 0, 128, 32, 0, 128, 32, 0, 128, 32, 0, 128 },
				{ 96, 0, 128, 96, 0, 128, 96, 0, 128, 96, 0, 128, 96, 0, 128 },
				{ 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80 },
				{ 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40 },
#else
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
				{ 128, 40, 0, 128, 40, 0, 128, 40, 0, 128, 40, 0 },
				{ 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0 },
				{ 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0 },
				{ 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0 },
				{ 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0 },
				{ 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0 },
				{ 0, 128, 40, 0, 128, 40, 0, 128, 40, 0, 128, 40 },
				{ 0, 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80 },
				{ 0, 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128 },
				{ 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80, 128 },
				{ 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40, 128 },
				{ 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128 },
				{ 32, 0, 128, 32, 0, 128, 32, 0, 128, 32, 0, 128 },
				{ 96, 0, 128, 96, 0, 128, 96, 0, 128, 96, 0, 128 },
				{ 128, 0, 80, 128, 0, 80, 128, 0, 80, 128, 0, 80 },
				{ 128, 0, 40, 128, 0, 40, 128, 0, 40, 128, 0, 40 },
#endif
			};
/* No Use rihgt now */
static int color4[7][NUM_OF_CLED] = {
#if defined(GSAX3000) || defined(GSAX5400)
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
				{ 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0 },
				{ 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0 },
				{ 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0 },
				{ 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128 },
				{ 32, 0, 128, 32, 0, 128, 32, 0, 128, 32, 0, 128, 32, 0, 128 },
				{ 96, 0, 128, 96, 0, 128, 96, 0, 128, 96, 0, 128, 96, 0, 128 },
#elif defined(GTAX6000)
				{ 128, 0, 0, 128, 50, 0, 128, 100, 0 },
				{ 128, 0, 0, 60, 0, 60, 0, 0, 128 },
				{ 128, 0, 0, 80, 0, 60, 40, 0, 80 },
				{ 50, 128, 128, 80, 100, 80, 128, 30, 0 },
				{ 80, 128, 128, 0, 0, 128, 0, 0, 128 },
				{ 128, 0, 0, 0, 128, 0, 0, 0, 128 },
#else
				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
				{ 128, 80, 0, 128, 80, 0, 128, 80, 0, 128, 80, 0 },
				{ 128, 128, 0, 128, 128, 0, 128, 128, 0, 128, 128, 0 },
				{ 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0 },
				{ 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128 },
				{ 32, 0, 128, 32, 0, 128, 32, 0, 128, 32, 0, 128 },
				{ 96, 0, 128, 96, 0, 128, 96, 0, 128, 96, 0, 128 },
#endif
			};
/* Rainbow Mode For TUF-AX54000 */
#ifdef TUFAX5400
static int color5[7][NUM_OF_CLED] = {

 				{ 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0, 128, 0, 0 },
				{ 120, 80, 0, 120, 80, 0, 120, 80, 0, 120, 80, 0, 120, 80, 0 },
				{ 0, 120, 40, 0, 120, 40, 0, 120, 40, 0, 120, 40, 0, 120, 40 },
				{ 0, 50, 128, 0, 50, 128, 0, 50, 128, 0, 50, 128, 0, 50, 128 },
				{ 60, 0, 128, 60, 0, 128, 60, 0, 128, 60, 0, 128, 60, 0, 128 },
				{ 128, 0, 60, 128, 0, 60, 128, 0, 60, 128, 0, 60, 128, 0, 60 },
				{ 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128 },
			};
#endif

/* For Mode 6, CoBrand Wave Mode Color

        0 => Cobrand 2

*/
static int color6_cb[1][NUM_OF_CLED] = {
				{128, 50, 30, 128, 50, 30, 128, 50, 30, 128, 50, 30}
};

#if defined(GTAXE16000) || defined(GTAX11000_PRO)
static int color_default[NUM_OF_CLED] = {0, 50, 128, 0, 50, 128, 0, 50, 128};
#endif

static int ledg_mode = 0;
static int ledg_color = 0;
static int ledg_scheme = 0;

static void RGBtoHSV(float fR, float fG, float fB) {
	float fCMax = max(max(fR, fG), fB);
	float fCMin = min(min(fR, fG), fB);
	float fDelta = fCMax - fCMin;

	if (fDelta > 0) {
		if (fCMax == fR) {
			fH = 60 * (fmod(((fG - fB) / fDelta), 6));
		} else if (fCMax == fG) {
			fH = 60 * (((fB - fR) / fDelta) + 2);
		} else if (fCMax == fB) {
			fH = 60 * (((fR - fG) / fDelta) + 4);
		}

		if (fCMax > 0) {
			fS = fDelta / fCMax;
		} else {
			fS = 0;
		}

		fV = fCMax;
	} else {
		fH = 0;
		fS = 0;
		fV = fCMax;
	}

	if (fH < 0)
		fH = 360 + fH;
}

static void HSVtoRGB(int H, float S, float V, int output[3]) {
	float C = S * V;
	float X = C * (1 - fabs(fmod((double)H / 60.0, 2) - 1));
	float m = V - C;
	float Rs, Gs, Bs;

	if (H >= 0 && H < 60) {
		Rs = C;
		Gs = X;
		Bs = 0;
	} else if (H >= 60 && H < 120) {
		Rs = X;
		Gs = C;
		Bs = 0;
	} else if (H >= 120 && H < 180) {
		Rs = 0;
		Gs = C;
		Bs = X;
	} else if (H >= 180 && H < 240) {
		Rs = 0;
		Gs = X;
		Bs = C;
	} else if (H >= 240 && H < 300) {
		Rs = X;
		Gs = 0;
		Bs = C;
	} else {
		Rs = C;
		Gs = 0;
		Bs = X;
	}

	output[0] = (Rs + m) * 255;
	output[1] = (Gs + m) * 255;
	output[2] = (Bs + m) * 255;
}

static void
alarmtimer(unsigned long sec, unsigned long usec)
{
	itv.it_value.tv_sec = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void ledg_exit(int sig)
{
	alarmtimer(0, 0);

	remove("/var/run/ledg.pid");
	exit(0);
}

static void ledg_init()
{
	char *nv, *nvp, *b;
	int count = 0, idx_color = 0, val, i, j;
	struct cled_config0 cc0;
	struct cled_config1 cc1;
	struct cled_config2 cc2;
	struct cled_config3 cc3;
	int pdelay = 100;
	float fR = 0, fG = 0, fB = 0;
	int color_output[3];
	char nvname[32];
	int blinking = 0;
	int lock = file_lock("ledg_init");

	idx = (direction == 1) ? (NUM_OF_COLOR - 1) : 0;
	reverse = 0;
	fH = fS = fV = 0;
	ledg_mode = ledg_color = 0;

	if (nvram_get("ledg_scheme_tmp")) {
		ledg_scheme = nvram_get_int("ledg_scheme_tmp");
		nvram_unset("ledg_scheme_tmp");
	} else
		ledg_scheme = nvram_get_int("ledg_scheme");

#ifdef GTAX6000
	if (!nvram_get_int("x_Setting") && ledg_scheme == LEDG_SCHEME_STEADY_RED)
		ledg_scheme = LEDG_SCHEME_PULSATING;
#endif
#if defined(GTAXE16000) || defined(GTAX11000_PRO)
	if (!nvram_get_int("x_Setting") && ledg_scheme == LEDG_SCHEME_WATER_FLOW)
		ledg_scheme = LEDG_SCHEME_STEADY_RED;
#endif
	switch(ledg_scheme) {
		default:
		case LEDG_SCHEME_GRADIENT:
			ledg_mode = LEDG_STEADY_MODE;
			ledg_color = 0;
			break;
		case LEDG_SCHEME_STEADY_RED:
			ledg_mode = LEDG_STEADY_MODE;
			ledg_color = 1;
			break;
		case LEDG_SCHEME_PULSATING:
			ledg_mode = LEDG_PULSATING_WITH_DELAY_MODE;
			ledg_color = 2;
			break;
		case LEDG_SCHEME_RAINBOW:
			ledg_mode = LEDG_RAINBOW_MODE;
			break;
		case LEDG_SCHEME_COLOR_CYCLE:
			ledg_mode = LEDG_COLOR_CYCLE_MODE;
			break;
		case LEDG_SCHEME_WATER_FLOW:
			ledg_mode = LEDG_WATER_FLOW_MODE;
			break;
		case LEDG_SCHEME_SCROLLING:
			ledg_mode = LEDG_SCROLLING_MODE;
			ledg_color = 2;
			break;
		case LEDG_SCHEME_CUSTOM:
			val = nvram_get_int("ledg_mode");
			if (val >= 0 && val <= (LEDG_MODE_MAX - 2))
				ledg_mode = val;

			val = nvram_get_int("ledg_color");
			if (val >= 0 && val < NUM_OF_COLOR)
				ledg_color = val;
			break;
		case LEDG_SCHEME_BLINKING:
			ledg_mode = LEDG_BLINKING_MODE;
			ledg_color = 3;
			break;
		case LEDG_SCHEME_OFF:
			ledg_mode = LEDG_OFF;
			break;
	}

	if (ledg_mode == LEDG_OFF || !nvram_get_int("AllLED")
#if defined(RTCONFIG_TURBO_BTN)
		|| !nvram_get_int("ledg_led_enable")
#endif
		) {
		LEDGroupReset(LED_OFF);
		file_unlock(lock);
		return;
	}

	for (i = LEDG_SCHEME_GRADIENT; i <= LEDG_SCHEME_MAX - 2; i++) {
		memset(nvname, 0, sizeof(nvname));
		sprintf(nvname, "ledg_rgb%d", i);
		nv = nvp = strdup(nvram_safe_get(nvname));
		if (nv) {
			count = 0;
			while ((b = strsep(&nvp, ",")) != NULL) {
				if (strlen(b) == 0) continue;

				val = atoi(b);

				if (val < 0)
					val = 0;

				if (val > 128)
					val = 128;

				if (val >= 0 && val <= 128) {
					color_manual[i][count++] = val;
				}
			}

			color_manual_valid[i - 1] = (count == NUM_OF_CLED) ? 1 : 0;
			free(nv);
		}
	}

	color_valid = color_manual_valid[ledg_scheme - 1];

	switch(ledg_mode) {
		case LEDG_STEADY_MODE:
		case LEDG_BLINKING_MODE:
			blinking = 0;
			val = ledg_color;
			if (val >= 0 && val < NUM_OF_COLOR) idx_color = val;

			memset(&cc0, 0, sizeof(struct cled_config0));
			cc0.bright_change_dir = 1;

			while (blinking++ < 3) {
				if (ledg_mode == LEDG_BLINKING_MODE) {
					LEDGroupReset(LED_OFF);
					usleep(500 * 1000);
				}

				for (i = 0; i < NUM_OF_CLED; i++) {
					if ((ledg_scheme != LEDG_SCHEME_BLINKING) && color_valid)
					{
#ifdef TUFAX5400
						if (!nvram_get_int("x_Setting"))
						{
							int color_local[NUM_OF_CLED] = { 0, 30, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
							cc0.bright_ctl = color_local[i];
						}
						else
#elif defined(GTAXE16000) || defined(GTAX11000_PRO)
						if (!nvram_get_int("x_Setting")) {
							cc0.bright_ctl = color_default[i];
						}
						else
#endif
#if defined(GTAXE16000) || defined(GTAX11000_PRO)
						if (!nvram_get_int("x_Setting"))
							cc0.bright_ctl = color_default[i];
						else
#endif
						cc0.bright_ctl = color_manual[ledg_scheme][i];
					}
					else
						cc0.bright_ctl = color[idx_color][i];
					cled_set(cled_gpio[i], *(uint32_t *)&cc0, 0x0, 0x0, 0x0);
				}

				if (ledg_mode == LEDG_STEADY_MODE)
					break;

				usleep(500 * 1000);
			}

			if (ledg_mode == LEDG_BLINKING_MODE) {
				if (nvram_default_get("ledg_scheme"))
					nvram_set("ledg_scheme", nvram_default_get("ledg_scheme"));
				nvram_commit();
				notify_rc("restart_ledg");
				ledg_exit(0);
			}

			break;

		case LEDG_FADING_REVERSE_MODE:
			idx_color = 0;

			memset(&cc0, 0, sizeof(struct cled_config0));
			memset(&cc1, 0, sizeof(struct cled_config1));
			memset(&cc2, 0, sizeof(struct cled_config2));
			memset(&cc3, 0, sizeof(struct cled_config3));

			cc0.mode = 1;
			cc0.bright_change_dir = 1;
			cc1.tstep1 = 3;
			cc1.nstep1 = 10;
			cc1.tstep2 = 4;
			cc1.nstep2 = 12;
			cc2.tstep3 = 3;
			cc2.nstep3 = 10;
			cc3.phase_delay1 = 128;
			cc3.phase_delay2 = 128;

			for (i = 0; i < NUM_OF_CLED; i++) {
				cc0.bright_ctl = 0;
				cc1.bstep1 = color[idx_color][i] / 32;
				cc1.bstep2 = color[idx_color][i] / 32;
				cc2.bstep3 = color[idx_color][i] / 32;
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, *(uint32_t *)&cc2, *(uint32_t *)&cc3);
			}

			break;

		case LEDG_PULSATING_MODE:
		case LEDG_PULSATING_WITH_DELAY_MODE:
			val = ledg_color;
			if (val >= 0 && val < NUM_OF_COLOR) idx_color = val;
			val = nvram_get_int("pdelay");
			if (val > 0) pdelay = val;

			memset(&cc0, 0, sizeof(struct cled_config0));
			memset(&cc1, 0, sizeof(struct cled_config1));
			memset(&cc2, 0, sizeof(struct cled_config2));
			memset(&cc3, 0, sizeof(struct cled_config3));

			cc0.mode = 2;
			cc0.repeat_cycle = 1;
			cc0.bright_change_dir = 1;
			cc1.tstep1 = 2;
			cc1.nstep1 = 10;
			cc1.tstep2 = 3;
			cc1.nstep2 = 12;
			cc2.tstep3 = 2;
			cc2.nstep3 = 10;
#if defined(TUFAX5400)
			cc3.phase_delay1 = 2;
			cc3.phase_delay2 = 2;
#else
			cc3.phase_delay1 = 128;
			cc3.phase_delay2 = 128;
#endif

			for (i = 0; i < NUM_OF_CLED; i++) {
				if (color_valid)
					cc0.bright_ctl = color_manual[ledg_scheme][i];
				else
					cc0.bright_ctl = color[idx_color][i];
#if defined(TUFAX5400)
				cc1.bstep1 = cc0.bright_ctl / 48;
				cc1.bstep2 = cc0.bright_ctl / 48;
				cc2.bstep3 = cc0.bright_ctl / 48;
#else
				cc1.bstep1 = cc0.bright_ctl / 32;
				cc1.bstep2 = cc0.bright_ctl / 32;
				cc2.bstep3 = cc0.bright_ctl / 32;
#endif
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, *(uint32_t *)&cc2, *(uint32_t *)&cc3);

				if (((ledg_mode == LEDG_PULSATING_WITH_DELAY_MODE)) && ((i % 3) == 2) && (i != (NUM_OF_CLED - 1)))
					usleep(pdelay * 1000);
			}
#if 0
#ifdef GTAX6000
                        for (i = 0; i < 4; i++) {
				cc0.bright_ctl = 128;
				cc1.bstep1 = cc0.bright_ctl / 32;
				cc1.bstep2 = cc0.bright_ctl / 32;
				cc2.bstep3 = cc0.bright_ctl / 32;
				cled_set(cled_gpio2[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, *(uint32_t *)&cc2, *(uint32_t *)&cc3);
                        }
#endif
#endif
			break;

		case LEDG_WATER_FLOW_MODE:
			memset(&cc0, 0, sizeof(struct cled_config0));
			memset(&cc1, 0, sizeof(struct cled_config1));
			memset(&cc2, 0, sizeof(struct cled_config2));
			memset(&cc3, 0, sizeof(struct cled_config3));

			cc0.mode = 2;
			cc0.repeat_cycle = 1;
			cc0.bright_change_dir = 0;
			cc1.tstep1 = 2;
			cc1.nstep1 = 10;
			cc1.tstep2 = 3;
			cc1.nstep2 = 12;
			cc2.tstep3 = 2;
			cc2.nstep3 = 10;
			cc3.phase_delay1 = 1;
			cc3.phase_delay2 = 1;

			for (i = 0; i < NUM_OF_CLED; i++) {
				if (color_valid)
					cc0.bright_ctl = color_manual[ledg_scheme][i];
				else
					cc0.bright_ctl = color[2][i];
#if defined(TUFAX5400)

				if (i==2 || i==5 || i==8 || i==11 || i==14) {
					cc1.bstep1 = 0;
					cc1.bstep2 = 0;
					cc2.bstep3 = 0;
				} else if(i==1 || i==4 || i==7 || i==10 || i==13){
					cc1.bstep1 = cc0.bright_ctl/20;
					cc1.bstep2 = cc0.bright_ctl/20;
					cc2.bstep3 = cc0.bright_ctl/20;
				} else {
					cc1.bstep1 = cc0.bright_ctl/60;
					cc1.bstep2 = cc0.bright_ctl/60;
					cc2.bstep3 = cc0.bright_ctl/60;
				}
#else

				if (nvram_get_int("CoBrand") == 2){

					if (i==0 || i==3 || i==6 || i==9) {
						cc1.bstep1 = cc0.bright_ctl/40;
						cc1.bstep2 = cc0.bright_ctl/40;
						cc2.bstep3 = cc0.bright_ctl/40;
					} else if(i==1 || i==4 || i==7 || i==10){
						cc1.bstep1 = cc0.bright_ctl/30;
						cc1.bstep2 = cc0.bright_ctl/30;
						cc2.bstep3 = cc0.bright_ctl/30;
					} else{
						cc1.bstep1 = cc0.bright_ctl/30;
						cc1.bstep2 = cc0.bright_ctl/30;
						cc2.bstep3 = cc0.bright_ctl/30;

					}

				}
				else{
#if defined(GTAX6000)
					if (i==1 || i==2 || i==4 || i==5 || i==7 || i==8) {
						cc1.bstep1 = 0;
						cc1.bstep2 = 0;
						cc2.bstep3 = 0;
					} else {
						cc1.bstep1 = 1;
						cc1.bstep2 = 1;
 						cc2.bstep3 = 1;
 					}
#elif defined(GTAXE16000)
					if (i==0 || i==1 || i==2) {
						cc1.bstep1 = cc0.bright_ctl/40;
						cc1.bstep2 = cc0.bright_ctl/40;
						cc2.bstep3 = cc0.bright_ctl/40;
					} else if(i==3 || i==4 || i==5){
						cc1.bstep1 = cc0.bright_ctl/25;
						cc1.bstep2 = cc0.bright_ctl/25;
						cc2.bstep3 = cc0.bright_ctl/25;
					} else {
						cc1.bstep1 = cc0.bright_ctl/35;
						cc1.bstep2 = cc0.bright_ctl/35;
						cc2.bstep3 = cc0.bright_ctl/35;
					}
#else
					if (i==0 || i==1 || i==3 || i==4 || i==6 || i==7 || i==9 || i==10 || i==12 || i==13) {
						cc1.bstep1 = 0;
						cc1.bstep2 = 0;
						cc2.bstep3 = 0;
					} else {
						cc1.bstep1 = 1;
						cc1.bstep2 = 1;
						cc2.bstep3 = 1;
					}
#endif
				}
#endif
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, *(uint32_t *)&cc2, *(uint32_t *)&cc3);


				if (((i % 3) == 2) && (i != (NUM_OF_CLED - 1)))
					usleep(100 * 4 * 1000); //0.4
			}

			break;
		case LEDG_RUNNING_LIGHT_MODE:
		case LEDG_OFF:
		default:
			LEDGroupReset(LED_OFF);
			break;
	}

	file_unlock(lock);
}

static void ledg(int sig)
{
	struct cled_config0 cc0;
	struct cled_config1 cc1;
	struct cled_config2 cc2;
	struct cled_config3 cc3;
#if defined(TUFAX5400)
	static int RainbowColor=1;
#else
	static int RainbowColor=0;
#endif
	static int RunCount=0;
	int pdelay = 100;
	int val, fdelay = 8, idx_color = 0, i;

	color_valid = color_manual_valid[ledg_scheme - 1];

	val = nvram_get_int("fdelay");
	if ((val > 0 && val <= 15)) fdelay = val;
	val = ledg_color;
	if (val >= 0 && val < NUM_OF_COLOR) idx_color = val;

	memset(&cc0, 0, sizeof(struct cled_config0));
	memset(&cc1, 0, sizeof(struct cled_config1));
	memset(&cc2, 0, sizeof(struct cled_config2));
	memset(&cc3, 0, sizeof(struct cled_config3));

	if (ledg_mode == LEDG_RUNNING_LIGHT_MODE) {
		direction = 2;

		cc0.mode = 1;
		cc0.initial_delay = 1;
		cc1.nstep1 = 15;
		cc1.tstep1 = fdelay;
		cc1.bstep1 = 9;

		for (i = 0; i < NUM_OF_CLED; i++) {
			if ((i / 3) == idx || (i / 3) == (idx + 1)) {
				cc0.bright_ctl = color[idx_color][i]/2;
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, 0x0, 0x0);
			}
		}

		if (direction == 0) {
			idx = (idx + 1) % NUM_OF_COLOR;
		} else if (direction == 1) {
			if (idx)
				idx--;
			else
				idx = NUM_OF_COLOR - 1;
		} else if (direction == 2) {
			if (!reverse) {
				if (idx == (NUM_OF_COLOR - 1)) {
					reverse = 1;
					idx = NUM_OF_COLOR - 2;
				} else idx++;
			} else {
				if (idx == 0) {
					reverse = 0;
					idx = 1;

				} else idx--;
	
			}
		}
	}
#if defined(TUFAX5400)
	// Rainbow = New Evolution Mode At TUF-AX5400
	else if(ledg_mode == LEDG_RAINBOW_MODE){
 			val = ledg_color;
 			if (val >= 0 && val < NUM_OF_COLOR) idx_color = val;
 			val = nvram_get_int("pdelay");
 			if (val > 0) pdelay = val;
 
 			if ((RunCount/1) == 1 && RunCount != 0) {
 				RainbowColor++;
 
 				if ((RainbowColor/7) == 1) {
 					RainbowColor=0;
 				}
 
 				RunCount=0;
 			}
 
 
 			memset(&cc0, 0, sizeof(struct cled_config0));
 			memset(&cc1, 0, sizeof(struct cled_config1));
 			memset(&cc2, 0, sizeof(struct cled_config2));
 			memset(&cc3, 0, sizeof(struct cled_config3));
 
 			cc0.mode = 2;
 			cc0.repeat_cycle = 1;
 			cc0.bright_change_dir = 1;
 			cc1.tstep1 = 3;
 			cc1.nstep1 = 8;
 			cc1.tstep2 = 4;
 			cc1.nstep2 = 9;
 			cc2.tstep3 = 3;
 			cc2.nstep3 = 8;
 			cc3.phase_delay1 = 2;
 			cc3.phase_delay2 = 2;
 
			for (i = 0; i < 3; i++) {
 				cc0.bright_ctl = color5[RainbowColor][i];
 				cc1.bstep1 = cc0.bright_ctl / 48;
 				cc1.bstep2 = cc0.bright_ctl / 48;
 				cc2.bstep3 = cc0.bright_ctl / 48;
 				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, *(uint32_t *)&cc2, *(uint32_t *)&cc3);
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
 				if (((ledg_mode == LEDG_RAINBOW_MODE)) && ((i % 3) == 2) && (i != (3 - 1)))
 					usleep(pdelay * 1000);
 				}
 
 				RunCount++;
 	}
#else
	else if (ledg_mode == LEDG_RAINBOW_MODE) {
		direction = 0;

		if ((RunCount/3) == 1 && RunCount != 0) {
			RainbowColor++;

			if ((RainbowColor/17) == 1) {
				RainbowColor=0;
			}

			RunCount=0;
		}

		cc0.mode = 1;
		cc0.initial_delay = 1;
		cc1.nstep1 = 15;
		cc1.tstep1 = fdelay;
		cc1.bstep1 = 1;

		//cc1.nstep2 = 15;
		//cc1.tstep2 = 8;
		//cc1.bstep2 = 9;

		for (i = 0; i < 17; i++) {
			if ((i / 3) == idx || (i / 3) == (idx+1)) {

				cc0.bright_ctl = color3[RainbowColor][i];
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, 0x0, 0x0);
			}
		}

		if (direction == 0) {
#if defined(GSAX3000) || defined(GSAX5400)
			idx = (idx + 1) % NUM_OF_COLOR;
#else
			idx = (idx + 1) % 3;
#endif
		} else if (direction == 1) {
			if (idx)
				idx--;
			else
				idx = NUM_OF_COLOR - 1;
		} else if (direction == 2) {
			if (!reverse) {
				if (idx == (NUM_OF_COLOR - 1)) {
					reverse = 1;
					idx = NUM_OF_COLOR - 2;
				} else idx++;
			} else {
				if (idx == 0) {
					reverse = 0;
					idx = 1;

				} else idx--;
			}
		}

		RunCount++;
	}
#endif
	else if (ledg_mode == LEDG_COLOR_CYCLE_MODE || ledg_mode == LEDG_SCROLLING_MODE) {
			val = nvram_get_int("pdelay");
			if (val > 0) pdelay = val;

			direction = 0;

			cc0.mode = 2;
			cc0.repeat_cycle = 1;
			cc0.bright_change_dir = 1;
			cc1.tstep1 = 2;
			cc1.nstep1 = 10;
			cc1.tstep2 = 3;
			cc1.nstep2 = 12;
			cc2.tstep3 = 2;
			cc2.nstep3 = 10;
			cc3.phase_delay1 = 128;
			cc3.phase_delay2 = 128;

			for (i = 0; i < NUM_OF_CLED; i++) {

				if (ledg_mode == LEDG_SCROLLING_MODE){
					if (color_valid)
						cc0.bright_ctl = color_manual[ledg_scheme][i];
					else
						cc0.bright_ctl = color[idx_color][i];
				} else {
#ifdef RTAX82U
					if (nvram_get_int("CoBrand") == 2)
						cc0.bright_ctl = color2_cb2[idx][i];
					else
#endif
						cc0.bright_ctl = color2[idx][i];
				}
				cc1.bstep1 = cc0.bright_ctl / 32;
				cc1.bstep2 = cc0.bright_ctl / 32;
				cc2.bstep3 = cc0.bright_ctl / 32;
#ifdef GTAX6000
				cled_set(cled_gpio[i], 0x0, 0x0, 0x0, 0x0);
#endif
				cled_set(cled_gpio[i], *(uint32_t *)&cc0, *(uint32_t *)&cc1, *(uint32_t *)&cc2, *(uint32_t *)&cc3);

				if (ledg_mode == LEDG_COLOR_CYCLE_MODE && ((i % 3) == 2) && (i != (NUM_OF_CLED - 1)))
					usleep(pdelay * 1 * 1000); //0.1
				else if (ledg_mode == LEDG_SCROLLING_MODE && ((i % 3) == 2) && (i != (NUM_OF_CLED - 1)))
					usleep(pdelay * 4 * 1000); //0.4

			}

			// Total 6 color in group in rainbow 5
#ifdef RTAX82U
			if ((idx+1) < ((nvram_get_int("CoBrand") == 2) ? 5 : 6))
#else
			if ((idx+1) < 6)
#endif
				idx++;
			else
				idx=0;
	}
}

static void ledg_alarmtimer()
{
	if (ledg_mode == LEDG_RUNNING_LIGHT_MODE ||
	    ledg_mode == LEDG_COLOR_CYCLE_MODE ||
	    ledg_mode == LEDG_RAINBOW_MODE ||
		ledg_mode == LEDG_SCROLLING_MODE)
		ledg(SIGALRM);

	if (ledg_mode == LEDG_RUNNING_LIGHT_MODE)
		alarmtimer(0, (nvram_get_int("ldelay") ? : 600) * 1000);	/* 0.6 second by default */
	else if (ledg_mode == LEDG_COLOR_CYCLE_MODE)
		alarmtimer(3, (nvram_get_int("ldelay") ? : 600) * 1000);	/* 3.6 second by default */
	else if (ledg_mode == LEDG_SCROLLING_MODE)
		alarmtimer(3, (nvram_get_int("ldelay") ? : 600) * 1000);	/* 3.6 second by default */
#if defined(TUFAX5400)
	else if (ledg_mode == LEDG_RAINBOW_MODE)
	    	alarmtimer(2, (nvram_get_int("ldelay") ? : 100) * 1000);        /* 2.1 second by default */
#else
	else if (ledg_mode == LEDG_RAINBOW_MODE)
		alarmtimer(0, (nvram_get_int("ldelay") ? : 600) * 1000); 	/* 0.6 second by default */
#endif
}

static void ledg_reinit(int sig)
{
	alarmtimer(0, 0);

	if (ledg_mode == LEDG_RUNNING_LIGHT_MODE ||
	    ledg_mode == LEDG_COLOR_CYCLE_MODE ||
	    ledg_mode == LEDG_RAINBOW_MODE ||
	    ledg_mode == LEDG_SCROLLING_MODE)
		notify_rc("restart_ledg");
	else {
		ledg_init();
		ledg_alarmtimer();
	}
}

int
ledg_main(int argc, char *argv[])
{
	FILE *fp;
	sigset_t sigs_to_catch;

	/* write pid */
	if ((fp = fopen("/var/run/ledg.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigaddset(&sigs_to_catch, SIGTSTP);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, ledg);
	signal(SIGTERM, ledg_exit);
	signal(SIGTSTP, ledg_reinit);

	ledg_init();
	ledg_alarmtimer();

	/* Most of time it goes to sleep */
	while (1)
	{
		pause();
	}

	return 0;
}
