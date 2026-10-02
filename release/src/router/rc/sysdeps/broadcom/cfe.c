/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2014, ASUSTeK Inc.
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
#include <bcmnvram.h>
#include <shared.h>
#include <rc.h>
#if defined(RTAC3200) || defined(RTAX55) || defined(RTAX1800) || defined(DSL_AX82U) || defined(TUFAX5400) || defined(RPAX56) || defined(RPAX58)
#include <sys/reboot.h>
#endif

#ifdef RTAC68U
void check_regrev_tmo()
{
	system("nvram set `cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set `cat /tmp/mtd0 | grep 1:regrev`");

	if (nvram_match("1:regrev", "0")) {
		if (nvram_match("1:ccode", "Q2")) {
			system("nvram set asuscfe1:regrev=33");
			system("nvram set asuscfecommit=1");
			nvram_set("1:regrev", "33");
			nvram_commit();
		}
	}
}

void update_cfe_tmo(int force)
{
	system("cp /dev/mtd0 /tmp/mtd0");

	check_regrev_tmo();

	if (force && nvram_match("fw_check", "1"))
		goto flash;

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("2.1.2.6")) || nvram_match("cpurev", "c0")) {
		system("rm -f /tmp/mtd0");
		return;
	}

flash:
	system("/rom/cfe/mtd-write /rom/cfe/cfe_tmo.bin boot");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep et0macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw402gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb3`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep secret_code`");

	system("nvram set asuscfeATEMODE=2");
	system("nvram unset asuscfeno_rescue");
	system("nvram unset asuscfenospare");

	system("nvram set asuscfecommit=1");

	nvram_set("ATEMODE", "2");
	system("nvram set `cat /dev/mtd0 | grep bl_version`");
	system("nvram set `cat /dev/mtd0 | grep odmpid`");
	nvram_commit();

	system("rm -f /tmp/mtd0");
}

void check_regrev()
{
	if (!nvram_match("bl_version", "1.0.2.0"))
		return;

	system("nvram set `cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set `cat /tmp/mtd0 | grep 1:regrev`");

	if (nvram_match("1:regrev", "0")) {
		if (nvram_match("1:ccode", "CN")) {
			system("nvram set asuscfe1:regrev=1");
			nvram_set("1:regrev", "1");
		} else if (nvram_match("1:ccode", "EU")) {
			system("nvram set asuscfe1:regrev=13");
			nvram_set("1:regrev", "13");
		} else if (nvram_match("1:ccode", "JP")) {
			system("nvram set asuscfe1:regrev=47");
			nvram_set("1:regrev", "47");
		}

		system("nvram set asuscfecommit=1");
		nvram_commit();
	}
}

void update_cfe_ac66u_b1()
{
	system("cp /dev/mtd0 /tmp/mtd0");
	system("nvram set `cat /tmp/mtd0 | grep bl_version`");

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("1.1.1.9"))) {
		system("rm -f /tmp/mtd0");
		return;
	}

	system("/rom/cfe/mtd-write /rom/cfe/cfe_ac66u_b1_1.1.2.0.bin boot");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep et0macaddr`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:aa2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:agbg0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:agbg1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:agbg2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:antswitch`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:femctrl`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:gainctrlsph`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:papdcap2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:tworangetssi2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdgain2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:epagain2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:tssiposslope2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:maxp2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:maxp2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:maxp2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:cckbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:cckbw20ul2gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw402gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:dot11agofdmhrbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ofdmlrbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:sb20in40hrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:sb20in40lrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:dot11agduphrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:dot11agduplrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdoffset2g40ma0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdoffset2g40ma1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdoffset2g40ma2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:sar2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aa5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:antswitch`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:femctrl`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:subband5gver`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:gainctrlsph`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:papdcap5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:tworangetssi5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdgain5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:epagain5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:tssiposslope5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:maxp5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:maxp5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:maxp5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset40ma0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset40ma1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset40ma2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset80ma0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset80ma1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset80ma2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw1605glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw1605gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw1605ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcslr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcslr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcslr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in40hrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160hr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80hr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160hr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80hr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160hr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80hr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in40lrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160lr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80lr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160lr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80lr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160lr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80lr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:dot11agduphrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:dot11agduplrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb3`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sar5g`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep secret_code`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep odmpid`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep territory_code`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep wifi_psk`");

	system("nvram set asuscfeATEMODE=0");
	system("nvram unset asuscfenospare");

	system("nvram set asuscfecommit=1");

	nvram_set("ATEMODE", "0");
	system("nvram set `cat /dev/mtd0 | grep bl_version`");
	system("nvram set `cat /dev/mtd0 | grep odmpid`");

	nvram_commit();

	system("rm -f /tmp/mtd0");
}

void update_cfe_ac68u_c0_eu()
{
	system("cp /dev/mtd0 /tmp/mtd0");
	system("nvram set `cat /tmp/mtd0 | grep bl_version`");

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("1.3.0.6"))) {
		system("rm -f /tmp/mtd0");
		return;
	}

	system("/rom/cfe/mtd-write /rom/cfe/cfe_rt-ac68u_5636_c0_1.3.0.7.bin boot");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep et0macaddr`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:aa2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:agbg0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:agbg1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:agbg2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:antswitch`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:femctrl`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:gainctrlsph`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:papdcap2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:tworangetssi2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdgain2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:epagain2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:tssiposslope2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgains2gtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:maxp2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:maxp2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:maxp2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:cckbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:cckbw20ul2gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw402gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:dot11agofdmhrbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ofdmlrbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:sb20in40hrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:sb20in40lrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:dot11agduphrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:dot11agduplrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdoffset2g40ma0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdoffset2g40ma1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pdoffset2g40ma2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:sar2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aa5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:aga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:antswitch`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:femctrl`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:subband5gver`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:gainctrlsph`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:papdcap5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:tworangetssi5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdgain5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:epagain5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:tssiposslope5g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghelnagaina0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrelnabypa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrisoa0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghelnagaina1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrelnabypa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrisoa1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5gmtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghelnagaina2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrelnabypa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgains5ghtrisoa2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:maxp5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:maxp5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:maxp5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset40ma0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset40ma1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset40ma2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset80ma0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset80ma1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pdoffset80ma2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw1605glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw1605gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw1605ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcslr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcslr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcslr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in40hrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160hr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80hr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160hr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80hr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160hr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80hr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in40lrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160lr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80lr5glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160lr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80lr5gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb20in80and160lr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sb40and80lr5ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:dot11agduphrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:dot11agduplrpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb3`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:sar5g`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep secret_code`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep odmpid`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep territory_code`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep wifi_psk`");

	system("nvram set asuscfeATEMODE=0");
	system("nvram unset asuscfenospare");

	system("nvram set asuscfecommit=1");

	nvram_set("ATEMODE", "0");
	system("nvram set `cat /dev/mtd0 | grep bl_version`");
	system("nvram set `cat /dev/mtd0 | grep odmpid`");

	nvram_commit();

	system("rm -f /tmp/mtd0");
}

void update_cfe_asus()
{
	int is_ESMT = 0;

	system("cp /dev/mtd0 /tmp/mtd0");
	system("nvram set `cat /tmp/mtd0 | grep bl_version`");

	if (!nvram_match("cpurev", "c0") && (nvram_get_int("PA") == 5003)) {
		if (!(After(get_blver(nvram_safe_get("bl_version")), get_blver("1.0.2.4")) &&
			before(get_blver(nvram_safe_get("bl_version")), get_blver("1.0.2.9")))) {
			system("rm -f /tmp/mtd0");
			return;
		}
	} else if (After(get_blver(nvram_safe_get("bl_version")), get_blver("1.0.1.9"))) {
		check_regrev();
		system("rm -f /tmp/mtd0");
		return;
	}

	if (!nvram_match("cpurev", "c0") && (nvram_get_int("PA") == 5003)) {
		system("/rom/cfe/mtd-write /rom/cfe/cfe_rt-ac68u_v2_5003_1.0.2.9.bin boot");
	} else if (nvram_match("bl_version", "1.0.1.7")) {
		is_ESMT = 1;
		system("/rom/cfe/mtd-write /rom/cfe/cfe_1.0.2.0_esmt.bin boot");
	} else
		system("/rom/cfe/mtd-write /rom/cfe/cfe_1.0.2.0.bin boot");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep et0macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw402gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw205ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw405ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw805ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal5gb3`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep secret_code`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep odmpid`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep wlopmode`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep ctf_fa_cap`");

	if (is_ESMT)
	system("nvram set asuscfeESMT=1");
	system("nvram set asuscfeATEMODE=0");
	system("nvram unset asuscfenospare");

	system("nvram set asuscfecommit=1");

	nvram_set("ATEMODE", "0");
	system("nvram set `cat /dev/mtd0 | grep bl_version`");
	system("nvram set `cat /dev/mtd0 | grep odmpid`");
	if (is_ESMT)
	nvram_set("ESMT", "1");
	nvram_commit();

	system("rm -f /tmp/mtd0");
}

void update_cfe()
{
	if (get_model() != MODEL_RTAC68U)
		return;

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("2.1.2.0")))
		update_cfe_tmo(0);
	else if (is_ac66u_v2_series())
		update_cfe_ac66u_b1();
	else if (nvram_match("cpurev", "c0") && (nvram_get_int("PA") == 5636))
		update_cfe_ac68u_c0_eu();
	else if (nvram_match("cpurev", "c0") && (nvram_get_int("PA") == 5003) &&
		nvram_match("bl_version", "1.1.1.2") && cfe_nvram_match("odmpid", "RT-AC68U")) {
		if (nvram_match("territory_code", "EU/01") &&
			nvram_match("0:ccode", "US") && nvram_match("0:regrev", "0") &&
			nvram_match("1:ccode", "US") && nvram_match("1:regrev", "0")) {
			system("nvram set asuscfeterritory_code=AA/01");
			system("nvram set asuscfecommit=1");
			nvram_commit();
		}
	} else
		update_cfe_asus();
}

/* CRC lookup table */
static unsigned long crcs[256]={ 0x00000000,0x77073096,0xEE0E612C,0x990951BA,
0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,
0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,
0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,
0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,
0xA50AB56B,0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,
0xDCD60DCF,0xABD13D59,0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,
0x56B3C423,0xCFBA9599,0xB8BDA50F,0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,
0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,
0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,
0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,
0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,
0xFBD44C65,0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,
0xA4D1C46D,0xD3D6F4FB,0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,
0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,
0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,
0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,
0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,
0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,
0x6E6B06E7,0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,
0x17B7BE43,0x60B08ED5,0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,
0xA6BC5767,0x3FB506DD,0x48B2364B,0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,
0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,
0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,
0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,
0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,
0x0BDBDF21,0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,
0x6FB077E1,0x18B74777,0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,
0xF862AE69,0x616BFFD3,0x166CCF45,0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,
0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,
0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,
0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,
0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D};

int calc_crc32( const char *fname, unsigned long *crc ) {
    FILE *in;           /* input file */
    unsigned char buf[BUFSIZ]; /* pointer to the input buffer */
    size_t i, j;        /* buffer positions*/
    int k;              /* generic integer */
    unsigned long tmpcrc=0xFFFFFFFF;

    /* open file */
    if((in = fopen(fname, "rb")) == NULL) return -1;

    /* loop through the file and calculate CRC */
    while( (i=fread(buf, 1, BUFSIZ, in)) != 0 ){
        for(j=0; j<i; j++){
            k=(tmpcrc ^ buf[j]) & 0x000000FFL;
            tmpcrc=((tmpcrc >> 8) & 0x00FFFFFFL) ^ crcs[k];
        }
    }
    fclose(in);
    *crc=~tmpcrc; /* postconditioning */
    return 0;
}

int
firmware_enc_crc_main(int argc, char *argv[])
{
	char crc_str[9];
	unsigned long crc;

	if (argc != 2)
                return -1;

	if(calc_crc32(argv[1], &crc) != 0)
	{
		printf("Error reading file %s\n", argv[1]);
		return -1;
	}

	memset(crc_str, 0, sizeof(crc_str));
	sprintf(crc_str, "%08lX", crc);
	dbg("CRC32: %s\n", crc_str);
	nvram_set("fw_enc_crc", crc_str);

	return 0;
}
#endif

#ifdef RTAC3200
void update_cfe_ac3200_128k()
{
	if (get_model() != MODEL_RTAC3200)
		return;

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("2.0.0.3")))
		return;

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("1.0.1.6")) &&
		before(get_blver(nvram_safe_get("bl_version")), get_blver("2.0.0.0")))
		return;

	system("cp /dev/mtd0 /tmp/mtd0");
	system("nvram set `cat /tmp/mtd0 | grep bl_version`");

	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("2.0.0.0")))
		system("/rom/cfe/mtd-write /rom/cfe/cfe_rt-ac3200_2.0.0.4_128k.bin boot");
	else
		system("/rom/cfe/mtd-write /rom/cfe/cfe_rt-ac3200_1.0.1.7_128k.bin boot");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep et0macaddr`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw205ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw205glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw205gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw405ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw405glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw405gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw805ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw805glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:mcsbw805gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:pa5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal5gb0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal5gb1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal5gb2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rpcal5gb3`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgainerr5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgainerr5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 0:rxgainerr5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw202gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:mcsbw402gpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:pa2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rpcal2g`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgainerr2ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgainerr2ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 1:rxgainerr2ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:ccode`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:macaddr`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw205ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw205glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw205gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw405ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw405glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw405gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw805ghpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw805glpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:mcsbw805gmpo`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:pa5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:pa5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:pa5ga2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:regrev`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rpcal5gb0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rpcal5gb1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rpcal5gb2`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rpcal5gb3`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rxgainerr5ga0`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rxgainerr5ga1`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep 2:rxgainerr5ga2`");

	system("nvram set asuscfe`cat /tmp/mtd0 | grep secret_code`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep odmpid`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep territory_code`");
	system("nvram set asuscfe`cat /tmp/mtd0 | grep wifi_psk`");

	system("nvram set asuscfeATEMODE=0");
	system("nvram unset asuscfenospare");

	system("nvram set asuscfecommit=1");

	nvram_set("ATEMODE", "0");
	system("nvram set `cat /dev/mtd0 | grep bl_version`");
	system("nvram set `cat /dev/mtd0 | grep odmpid`");
	nvram_set("nvram_space", "131072");
	nvram_commit();

	system("rm -f /tmp/mtd0");

	reboot(RB_AUTOBOOT);
}
#endif

#ifdef GTAC2900
void update_cfe_ac2900()
{
	if (!pids("envrams")) {
		system("/usr/sbin/envrams &> /dev/null");
		usleep(100000);
	}

	if (!strncmp(cfe_nvram_safe_get_raw("territory_code"), "CN", 2)) {
		if (!strcmp(cfe_nvram_get("ATEMODE"), "1")) {
			eval("envram", "set", "ATEMODE=0");
		        eval("envram", "commit");
			nvram_set("ATEMODE", "0");
			nvram_set("wanduck_down", "0");
			nvram_commit();
			sync(); sync(); sync();
		}
	}
}
#endif

#if defined(RPAX56) || defined(RPAX58)
void chk_cfe_ate()
{
#ifdef RTCONFIG_BCM_MFG
        return;
#endif
        int envs = 0;

        if (nvram_match("force_atemode", "1"))
                return ;

        if (!pids("envrams")) {
                system("/usr/sbin/envrams &> /dev/null");
                usleep(100000);
                envs = 1;
        }

	if (!strcmp(cfe_nvram_get("ATEMODE"), "1")) {
		eval("envram", "set", "ATEMODE=0");
		eval("envram", "commit");
		nvram_set("ATEMODE", "0");
		nvram_commit();

		_dprintf("reset ATE:: fwver: %s_%s_%s (sn:%s /ha:%s )\n", rt_version, rt_serialno, rt_extendno, nvram_safe_get("serial_no"), nvram_safe_get("et0macaddr"));
		syslog(LOG_NOTICE, "reset ATE:: fwver: %s_%s_%s (sn:%s /ha:%s )\n", rt_version, rt_serialno, rt_extendno, nvram_safe_get("serial_no"), nvram_safe_get("et0macaddr"));
		_dprintf("emer reboot.\n");
		reboot(RB_AUTOBOOT);
	}

	if(envs)
		killall_tk("envrams");
}
#endif

#if defined(BCM6750) && !defined(RTAX82_XD6) && !defined(RTAX82_XD6S) && !defined(TUFAX5400)
void update_cfe_nvram()
{
#ifndef RTCONFIG_BCM_MFG
	char str_sw_txchain_mask[] = { '1', ':', 's', 'w', '_', 't', 'x', 'c', 'h', 'a', 'i', 'n', '_', 'm', 'a', 's', 'k', '\0' };
	char str_4t4r[] = { '1', ':', '4', 't', '4', 'r', '\0' };
#if defined(RTAX58U) || defined(TUFAX3000) || defined(GSAX3000)
	char str_wl_txchain[] = { 'w', 'l', '1', '_', 't', 'x', 'c', 'h', 'a', 'i', 'n', '\0' };

	if ( 0 
#ifdef TUFAX3000
		|| (!strncmp(nvram_safe_get("territory_code"), "CN", 2) && nvram_match("location_code", "XX"))
#endif
#ifdef RTCONFIG_PROXYSTA
		|| (psta_exist() || psr_exist())
#endif
	) {
		nvram_set(str_sw_txchain_mask, "0xf");
		nvram_set_int(str_wl_txchain, 15);
	} else
#endif
	if (nvram_get_int(str_4t4r))
		;
	else
#if defined(GSAX3000) || defined(GSAX5400)
	if (!get_gpio2(0xe))
#else
	if (!get_gpio2(0x7))
#endif
		nvram_set(str_sw_txchain_mask, "0x9");
#endif
}

#if defined(RTAX58U) || defined(TUFAX3000) || defined(GSAX3000)
void update_fem_Qorvo()
{
	unsigned int d1, d2, d3, d4;
	if (sscanf(nvram_safe_get("bl_version"), "%d.%d.%d.%d", &d1, &d2, &d3, &d4) == 4) {
		if ((d2 == 1) && !nvram_match("1:swctrlmap4_misc5g_fem3to0", "0x2222")) {
			if (!pids("envrams")) {
				system("/usr/sbin/envrams &> /dev/null");
				usleep(100000);
			}

			ATE_BRCM_SET("1:swctrlmap4_misc5g_fem3to0", "0x2222");
			ATE_BRCM_COMMIT();
		}
	}
}
#endif

void update_cfe_ax58u()
{
	update_cfe_nvram();
#if defined(RTAX58U) || defined(TUFAX3000) || defined(GSAX3000)
	update_fem_Qorvo();
#endif
#if !defined(GSAX3000) && !defined(GSAX5400)
	if (After(get_blver(nvram_safe_get("bl_version")), get_blver("0.0.0.4")))
#endif
		return;

	if (!pids("envrams")) {
		system("/usr/sbin/envrams &> /dev/null");
		usleep(100000);
	}

	ATE_BRCM_SET("0:pdoffsetcck", "0");
	ATE_BRCM_SET("0:pdoffsetcck20m", "0x37b");
	ATE_BRCM_SET("0:pdoffset20in40m2g", "0x339");

	ATE_BRCM_SET("1:pdoffset20in40m5gb0", "0x737b");
	ATE_BRCM_SET("1:pdoffset20in40m5gb1", "0x6f7b");
	ATE_BRCM_SET("1:pdoffset20in40m5gb2", "0x6b9b");
	ATE_BRCM_SET("1:pdoffset20in40m5gb3", "0x6f7b");
	ATE_BRCM_SET("1:pdoffset20in40m5gb4", "0x6f7b");
	ATE_BRCM_SET("1:pdoffset40in80m5gb0", "0x0441");
	ATE_BRCM_SET("1:pdoffset40in80m5gb1", "0x0441");
	ATE_BRCM_SET("1:pdoffset40in80m5gb2", "0x0421");
	ATE_BRCM_SET("1:pdoffset40in80m5gb3", "0x0441");
	ATE_BRCM_SET("1:pdoffset40in80m5gb4", "0x0441");
	ATE_BRCM_SET("1:pdoffset20in80m5gb0", "0x779c");
	ATE_BRCM_SET("1:pdoffset20in80m5gb1", "0x739c");
	ATE_BRCM_SET("1:pdoffset20in80m5gb2", "0x739c");
	ATE_BRCM_SET("1:pdoffset20in80m5gb3", "0x739c");
	ATE_BRCM_SET("1:pdoffset20in80m5gb4", "0x739d");
	ATE_BRCM_SET("1:pdoffset40in80m5gcore3", "0x0821");
	ATE_BRCM_SET("1:pdoffset40in80m5gcore3_1", "0x0021");
	ATE_BRCM_SET("1:pdoffset20in80m5gcore3", "0x77bd");
	ATE_BRCM_SET("1:pdoffset20in80m5gcore3_1", "0x039c");
	ATE_BRCM_SET("1:pdoffset20in40m5gcore3", "0x77bd");
	ATE_BRCM_SET("1:pdoffset20in40m5gcore3_1", "0x037b");
	ATE_BRCM_SET("1:pdoffset20in160m5gc0", "0x677a");
	ATE_BRCM_SET("1:pdoffset20in160m5gc1", "0x677a");
	ATE_BRCM_SET("1:pdoffset20in160m5gc2", "0x6759");
	ATE_BRCM_SET("1:pdoffset20in160m5gc3", "0x6759");
	ATE_BRCM_SET("1:pdoffset40in160m5gc0", "0x21");
	ATE_BRCM_SET("1:pdoffset40in160m5gc1", "0x21");
	ATE_BRCM_SET("1:pdoffset40in160m5gc2", "0x1f");
	ATE_BRCM_SET("1:pdoffset40in160m5gc3", "0x1f");
	ATE_BRCM_SET("1:pdoffset80in160m5gc0", "0x7fff");
	ATE_BRCM_SET("1:pdoffset80in160m5gc1", "0x7fff");
	ATE_BRCM_SET("1:pdoffset80in160m5gc2", "0x7ffd");
	ATE_BRCM_SET("1:pdoffset80in160m5gc3", "0x7ffd");
	ATE_BRCM_SET("1:pdoffset20in160m5gcore3", "0x035a");
	ATE_BRCM_SET("1:pdoffset20in160m5gcore3_1", "0x037b");
	ATE_BRCM_SET("1:pdoffset40in160m5gcore3", "0");
	ATE_BRCM_SET("1:pdoffset40in160m5gcore3_1", "0");
	ATE_BRCM_SET("1:pdoffset80in160m5gcore3", "0x03bd");
	ATE_BRCM_SET("1:pdoffset80in160m5gcore3_1", "0x03ff");

	ATE_BRCM_SET("bl_version", "0.0.0.5");

	ATE_BRCM_COMMIT();
}
#endif

#if defined(RTCONFIG_BCM_MFG) && (defined(RTAX55) || defined(RTAX1800) || defined(TUFAX5400))
void update_cfe_ax55()
{
	if (!strlen(cfe_nvram_safe_get_raw("bl_version"))) {
		dbg("updating misc1...\n");
		system("ubiformat /dev/mtd10");
		system("ubiattach -p /dev/mtd10");
		system("ubimkvol /dev/ubi2 --name=nvram --type=dynamic --maxavsize");
		system("mkdir -p /mnt/nvram");
		system("mount -t ubifs ubi2:nvram /mnt/nvram");
#ifdef TUFAX5400
		system("cp /rom/etc/wlan/nvram/TUF-AX5400.nvm /mnt/nvram/nvram.nvm");
#else
		system("cp /rom/etc/wlan/nvram/RT-AX55.nvm /mnt/nvram/nvram.nvm");
#endif
		system("nvram erase");
		reboot(RB_AUTOBOOT);
	}
}
#endif

#if defined(DSL_AX82U)
#define NVM_FILE      "DSL-AX82U.nvm"
#define MISC1_VOLCNT  "/sys/class/ubi/ubi2/volumes_count"
void update_misc1()
{
	int mtd_num = 10;
	int mtd_size = 0;
	char buf[128] = {0};

	if (mtd_getinfo("misc1", &mtd_num, &mtd_size))
	{
		snprintf(buf, sizeof(buf), "ubiattach -m %d", mtd_num);
		system(buf);
		sleep(1);
		memset(buf, 0, sizeof(buf));
		if (f_read_string(MISC1_VOLCNT, buf, sizeof(buf)) > 0 && atoi(buf) != 0)
		{
			snprintf(buf, sizeof(buf), "ubidetach -m %d", mtd_num);
			system(buf);
			return;
		}
		snprintf(buf, sizeof(buf), "ubidetach -m %d", mtd_num);
		system(buf);

		if (!strlen(cfe_nvram_safe_get_raw("bl_version")))
		{
			_dprintf("\n=====\nupdating misc1...\n=====\n");
			snprintf(buf, sizeof(buf), "ubiformat /dev/mtd%d", mtd_num);
			system(buf);
			snprintf(buf, sizeof(buf), "ubiattach -m %d", mtd_num);
			system(buf);
			system("ubimkvol /dev/ubi2 --name=nvram --type=dynamic --maxavsize");
			snprintf(buf, sizeof(buf), "ubidetach -m %d", mtd_num);
			system(buf);
			system("/rom/etc/init.d/hndnvram.sh mount_ubi");
			system("cp /rom/etc/wlan/nvram/"NVM_FILE" /mnt/nvram/nvram.nvm");
			system("/rom/etc/init.d/hndnvram.sh umount_ubi");
			system("nvram erase");
			reboot(RB_AUTOBOOT);
		}
	}
	else
	{
		_dprintf("%s: %d: cannot get mtd info\n", __FUNCTION__, __LINE__);
	}
}
void update_cfe_ax82u()
{
	char bl_version[16] = {0};

	nvram_safe_get_r("bl_version", bl_version, sizeof(bl_version));

	if (After(get_blver(bl_version), get_blver("0.0.0.4")))
		return;

	if (!pids("envrams")) {
		system("/usr/sbin/envrams &> /dev/null");
		usleep(100000);
	}

	if (strcmp(bl_version, "0.0.0.4") == 0) {
		ATE_BRCM_SET("sb/0/tempthresh", "125");
		ATE_BRCM_SET("0:mcsbw205glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605gx2po", "0x88665444");
		ATE_BRCM_SET("bl_version", "0.0.0.5");
		ATE_BRCM_SET("bl_version_old", "0.0.0.4");
		ATE_BRCM_COMMIT();
		return;
	}
	if (strcmp(bl_version, "0.0.0.3") == 0) {
		ATE_BRCM_SET("sb/0/tempthresh", "125");
		ATE_BRCM_SET("sb/0/mcsbw202gpo", "0x55432211");
		ATE_BRCM_SET("sb/0/pa2ga0", "0x1c3e,0xdd69,0x0000,0x3705");
		ATE_BRCM_SET("sb/0/pa2g20ccka0", "0x1feb,0xd084,0x0000,0x13bf");
		ATE_BRCM_SET("sb/0/pa2g40a0", "0x1e5b,0xd9d0,0x0000,0x499b");
		ATE_BRCM_SET("0:tempthresh", "125");
		ATE_BRCM_SET("0:mcsbw205glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605glpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605gmpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605ghpo", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605gx1po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw205gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw405gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw805gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcsbw1605gx2po", "0x88665444");
		ATE_BRCM_SET("0:mcs1024qam5glpo", "0xcccccccc");
		ATE_BRCM_SET("0:mcs1024qam5gmpo", "0xcccccccc");
		ATE_BRCM_SET("0:mcs1024qam5ghpo", "0xcccccccc");
		ATE_BRCM_SET("0:mcs1024qam5gx1po", "0xcccccccc");
		ATE_BRCM_SET("0:mcs1024qam5gx2po", "0xcccccccc");
		ATE_BRCM_SET("0:pa5ga0", "0x29a9,0xb34c,0xfc00,0x0000,0x273f,0xbfcd,0xf6ae,0x0000,0x237d,0xd6c6,0xeafd,0x0000,0x24ba,0xca1b,0xf206,0x0000,0x27fe,0xb04c,0xfdca,0x0000");
		ATE_BRCM_SET("0:pa5ga1", "0x2768,0xbcea,0xf939,0x0000,0x2644,0xc35d,0xf562,0x0000,0x2336,0xccb1,0xf15c,0x0000,0x256b,0xbabd,0xfb1f,0x0000,0x24f0,0xc106,0xf79e,0x0000");
		ATE_BRCM_SET("0:pa5ga2", "0x27e9,0xbf39,0xf770,0x0000,0x262b,0xc871,0xf359,0x099a,0x266c,0xbc66,0xf89b,0x0000,0x2473,0xc2cf,0xf5c4,0x0000,0x235d,0xcca0,0xf0ea,0x0000");
		ATE_BRCM_SET("0:pa5ga3", "0x2774,0xc78b,0xf308,0x0000,0x289a,0xbaf8,0xf817,0x0000,0x2544,0xcb69,0xf10a,0x0000,0x258e,0xc04f,0xf67b,0x0000,0x24c5,0xc5d8,0xf450,0x0000");
		ATE_BRCM_SET("0:pa5g40a0", "0x268c,0xd1fd,0xeef4,0x0000,0x251f,0xd636,0xed30,0x0000,0x24b4,0xd27e,0xee75,0x0000,0x23ae,0xd648,0xedab,0x0000,0x23e0,0xd72f,0xec05,0x0000");
		ATE_BRCM_SET("0:pa5g40a1", "0x254e,0xd563,0xeebe,0x0000,0x260e,0xca9d,0xf33d,0x0000,0x231a,0xd37c,0xef57,0x0000,0x2224,0xddb8,0xea05,0x0000,0x231d,0xd76d,0xed39,0x0000");
		ATE_BRCM_SET("0:pa5g40a2", "0x2a77,0xb65f,0xfba1,0x0000,0x260c,0xd039,0xf04a,0x0000,0x255c,0xccdc,0xf13f,0x0000,0x21e4,0xde70,0xe8d4,0x0000,0x21ad,0xde38,0xea69,0x0000");
		ATE_BRCM_SET("0:pa5g40a3", "0x290a,0xc2e4,0xf5d4,0x0000,0x263e,0xd1dc,0xeed9,0x0000,0x2736,0xc2e8,0xf5ed,0x0000,0x236a,0xd551,0xee02,0x0000,0x2054,0xedf2,0xe22e,0x0000");
		ATE_BRCM_SET("0:pa5g80a0", "0x29a0,0xb904,0xf987,0x0000,0x2afb,0xaa2a,0x0000,0x0000,0x255e,0xcb20,0xf1db,0x0000,0x2717,0xbc12,0xf8a7,0x0000,0x24d4,0xceae,0xef7a,0x0000");
		ATE_BRCM_SET("0:pa5g80a1", "0x25a9,0xcfd4,0xf090,0x0000,0x25a5,0xcd7a,0xf13b,0x0000,0x2442,0xcb4c,0xf1e7,0x0000,0x2266,0xd965,0xebf8,0x0000,0x24d2,0xc544,0xf610,0x0000");
		ATE_BRCM_SET("0:pa5g80a2", "0x2932,0xbacb,0xf9af,0x0000,0x2961,0xb682,0xfb42,0x0000,0x26e6,0xbde3,0xf809,0x0000,0x23c4,0xcd45,0xf0f4,0x0000,0x2221,0xdc05,0xe9d0,0x0000");
		ATE_BRCM_SET("0:pa5g80a3", "0x29f3,0xb833,0xfa46,0x0000,0x28dc,0xbd4f,0xf7aa,0x0000,0x285a,0xb8f8,0xf984,0x0000,0x2624,0xbf55,0xf762,0x0000,0x2423,0xcf1c,0xf047,0x0000");
		ATE_BRCM_SET("0:pa5g160a0", "0x2eae,0xa73a,0x0000,0x0000,0x2eae,0xa73a,0x0000,0x0000,0x2bdf,0xb518,0xfb86,0x0000,0x2bdf,0xb518,0xfb86,0x0000");
		ATE_BRCM_SET("0:pa5g160a1", "0x2acc,0xba0b,0xf98d,0x0000,0x2acc,0xba0b,0xf98d,0x0000,0x2b23,0xb585,0xfbf7,0x0000,0x2b23,0xb585,0xfbf7,0x0000");
		ATE_BRCM_SET("0:pa5g160a2", "0x2a4a,0xc147,0xf768,0x0000,0x2a4a,0xc147,0xf768,0x0000,0x2d13,0xaa88,0x0000,0x0000,0x2d13,0xaa88,0x0000,0x0000");
		ATE_BRCM_SET("0:pa5g160a3", "0x2e9c,0xaa8e,0x0000,0x0e27,0x2e9c,0xaa8e,0x0000,0x0e27,0x2c38,0xb587,0xfb3b,0x0000,0x2c38,0xb587,0xfb3b,0x0000");
		ATE_BRCM_SET("bl_version", "0.0.0.5");
		ATE_BRCM_SET("bl_version_old", "0.0.0.3");
		ATE_BRCM_COMMIT();
		return;
	}
}

void check_wlfeature()
{
	FILE *fp = NULL;
	char buf[128] = {0};
	char *p;
	unsigned long val = 0;

	if (ATE_BRCM_FACTORY_MODE())
		return;

	fp = popen("nvramUpdate Feature", "r");
	if (fp) {
		fread(buf, sizeof(buf)-1, 1, fp);
		if ((p = strchr(buf, ':'))) {
			val = strtoul(p+1, NULL, 0);
			if (val != 0) {
				system("nvramUpdate Feature 0");
				reboot(RB_AUTOBOOT);
			}
		}
		pclose(fp);
	}
}
#endif
