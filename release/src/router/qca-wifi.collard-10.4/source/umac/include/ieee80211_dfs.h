/*-
 * Copyright (c) 2007-2008 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net80211/ieee80211_dfs.h,v 1.2 2008/12/15 01:26:33 sam Exp $
 */
#ifndef _NET80211_IEEE80211_DFS_H_
#define _NET80211_IEEE80211_DFS_H_

/*
 * 802.11h/DFS definitions.
 */

struct ieee80211_dfs_state {
	int		nol_event[IEEE80211_CHAN_MAX];
	os_timer_t	nol_timer;		/* NOL list processing */
	os_timer_t	cac_timer;		/* CAC timer */
	os_timer_t      cac_valid_timer;         /* Ignore CAC when this timer is running*/
	//struct timeval 	lastevent;		/* time of last radar event */
	int		cureps;			/* current events/second */
	const struct ieee80211_channel *lastchan;/* chan w/ last radar event */
	struct ieee80211_channel *newchan;	/* chan selected next */
	int		cac_timeout_override;	/* overridden cac timeout */
        int8_t     enable:1,
                   cac_timer_running:1,
                   ignore_dfs:1, 
                   ignore_cac:1,
		   cac_valid:1;
	uint32_t cac_valid_time;		/* time for which CAC will be valid and will not be re-done */ 
};

void	ieee80211_dfs_attach(struct ieee80211com *);
void	ieee80211_dfs_detach(struct ieee80211com *);

int	 ieee80211_dfs_override_cac_timeout(struct ieee80211com *ic,
	    int cac_timeout);
int	ieee80211_dfs_get_override_cac_timeout(struct ieee80211com *ic,
	    int *cac_timeout);

void	ieee80211_dfs_reset(struct ieee80211com *);
void 	ieee80211_dfs_cac_valid_reset(struct ieee80211com *ic);

int	ieee80211_dfs_cac_start(struct ieee80211com *);
void	ieee80211_dfs_cac_stop(struct ieee80211vap *, int force);
void ieee80211_update_dfs_next_channel(struct ieee80211com *ic);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
void	ieee80211_dfs_stacac_stop(struct ieee80211vap *);
#endif

void	ieee80211_dfs_cac_clear(struct ieee80211com *,
		const struct ieee80211_channel *);
int	ieee80211_dfs_cac_cancel(struct ieee80211com *);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
int	ieee80211_dfs_stacac_cancel(struct ieee80211com *);
int	ieee80211_get_cac_timeout(struct ieee80211com *ic,
        struct ieee80211_channel *chan);
#endif
int	ieee80211_dfs_is_ap_cac_timer_running(struct ieee80211com * ic);
void	ieee80211_dfs_notify_radar(struct ieee80211com *,
		struct ieee80211_channel *);
void	ieee80211_unmark_radar(struct ieee80211com *,
		struct ieee80211_channel *);
void ieee80211_bringup_ap_vaps(struct ieee80211com *);
struct ieee80211_channel *ieee80211_dfs_pickchannel(struct ieee80211com *);
#endif /* _NET80211_IEEE80211_DFS_H_ */
