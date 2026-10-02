#include <rc.h>
#define MAPD_PATH "/etc/map/mapd_cfg"
#define P1905_PATH "/etc/map/1905d.cfg"
#define WAPP_PATH "etc/wapp_ap.conf"
int gen_1905_config_file(void)
{
	FILE *fp;
        int err = -1;
	unlink(P1905_PATH);
        if ((fp = fopen(P1905_PATH, "w+")) != NULL) {
		//# Controller's ALID
		fprintf(fp,"map_controller_alid=\n");
		//# Has MAP agent on this device
		fprintf(fp,"map_agent=%d\n",0);
		//This device is a MAP root
		fprintf(fp,"map_root=%d\n",1);
		//# Agent's ALID
		fprintf(fp,"map_agent_alid=\n");
		//# Default Backhault Type
		fprintf(fp,"bh_type=%s\n","eth");
		//#Config Band setting of each Radio
		fprintf(fp,"radio_band=%s;%s;%s\n","24G","5G","5G");
		//#bridge interface
		fprintf(fp,"br_inf=%s\n","br0");
		//#lan interface
		fprintf(fp,"map_ver=%s\n","R2");
		//#fixed al_mac of al_inf(only wifi inf) mac
		//#al_inf=ra0
		fprintf(fp,"bss_config_priority=%s;%s;%s;%s\n",get_wififname(0),get_staifname(0),get_wififname(1),get_staifname(1));
		//#ethernet device name used to read the switch table
		//#do not set if not understanding
		//#ethernet_dev_name=
		fprintf(fp,"lan=%s\n","eth0");
		err=0; 
	}
        fclose(fp);
	return err;
}

int gen_mapd_config_file(void)
{
	FILE *fp;
        int err = -1;
	unlink(MAPD_PATH);
        if ((fp = fopen(MAPD_PATH, "w+")) != NULL) {
		fprintf(fp,"lan_interface=%s\n","eth0");
		fprintf(fp,"wan_interface=%s\n","eth1");
		fprintf(fp,"DeviceRole=%d\n",1);
		fprintf(fp,"APSteerRssiTh=%d\n",-100);
		fprintf(fp,"BhPriority2G=%d\n",1);
		fprintf(fp,"BhPriority5GL=%d\n",1);
		fprintf(fp,"BhPriority5GH=%d\n",1);
		fprintf(fp,"ChPlanningIdleByteCount=\n");
		fprintf(fp,"ChPlanningIdleTime=\n");
		fprintf(fp,"ChPlanningUserPreferredChannel5G=\n");
		fprintf(fp,"ChPlanningUserPreferredChannel5GH=\n");
		fprintf(fp,"ChPlanningUserPreferredChannel2G=\n");
		fprintf(fp,"ChPlanningInitTimeout=%d\n",120);
		fprintf(fp,"NtwrkOptBootupWaitTime=%d\n",45);
		fprintf(fp,"NtwrkOptConnectWaitTime=%d\n",45);
		fprintf(fp,"NtwrkOptDisconnectWaitTime=%d\n",45);
		fprintf(fp,"NtwrkOptPeriodicity=%d\n",3600);
		fprintf(fp,"NetworkOptimizationScoreMargin=%d\n",100);
		fprintf(fp,"BandSwitchTime=\n");
		fprintf(fp,"ScanThreshold2g=%d\n",-75);
		fprintf(fp,"ScanThreshold5g=%d\n",-75);
		fprintf(fp,"LowRSSIAPSteerEdge_RE=%d\n",40);
		fprintf(fp,"CUOverloadTh_2G=%d\n",50);
		fprintf(fp,"CUOverloadTh_5G_L=%d\n",80);
		fprintf(fp,"CUOverloadTh_5G_H=%d\n",80);
		fprintf(fp,"BhProfile0Valid=\n");
		fprintf(fp,"BhProfile0Ssid=\n");
		fprintf(fp,"BhProfile0AuthMode=\n");
		fprintf(fp,"BhProfile0EncrypType=\n");
		fprintf(fp,"BhProfile0WpaPsk=\n");
		fprintf(fp,"BhProfile0RaID=\n");
		fprintf(fp,"BhProfile1Ssid=\n");
		fprintf(fp,"BhProfile1AuthMode=\n");
		fprintf(fp,"BhProfile1EncrypType=\n");
		fprintf(fp,"BhProfile1WpaPsk=\n");
		fprintf(fp,"BhProfile1Valid=\n");
		fprintf(fp,"BhProfile1RaID=\n");
		fprintf(fp,"BhProfile2Ssid=\n");
		fprintf(fp,"BhProfile2AuthMode=\n");
		fprintf(fp,"BhProfile2EncrypType=\n");
		fprintf(fp,"BhProfile2WpaPsk=\n");
		fprintf(fp,"BhProfile2Valid=\n");
		fprintf(fp,"BhProfile2RaID=\n");
		fprintf(fp,"ChPlanningEnable=1\n");
		fprintf(fp,"ChPlanningEnableR2=\n");
		fprintf(fp,"SteerEnable=%d\n",1);
		fprintf(fp,"NetworkOptimizationEnabled=%d\n",1);
		fprintf(fp,"AutoBHSwitching=%d\n",1);
		fprintf(fp,"DhcpCtl=%d\n",0);
		fprintf(fp,"ThirdPartyConnection=%d\n",0);
		fprintf(fp,"MAP_QuickChChange=%d\n",1);
		fprintf(fp,"bss_config_priority=%s;%s;%s;%s\n",get_wififname(0),get_staifname(0),get_wififname(1),get_staifname(1));
		fprintf(fp,"DualBH=\n");
		fprintf(fp,"MetricRepIntv=%d\n",60);
		fprintf(fp,"MaxAllowedScan=\n");
		fprintf(fp,"BHSteerTimeout=%d\n",120);
		fprintf(fp,"NtwrkOptPostCACTriggerTime=%d\n",25);
		fprintf(fp,"role_detection_external=%d\n",0);
		fprintf(fp,"NetworkOptPrefer5Gover2G=%d\n",0);
		fprintf(fp,"NetworkOptPrefer5Gover2GRetryCnt=%d\n",0);
		fprintf(fp,"NonMAPAPEnable=%d\n",1);
		fprintf(fp,"CentralizedSteering=%d\n",1);
		fprintf(fp,"ChPlanningEnableR2withBW=\n");
		fprintf(fp,"DivergentChPlanning=%d\n",0);
		fprintf(fp,"LastMapMode=%d\n",2);
		fprintf(fp,"NtwrkOptDataCollectionTime=%d\n",300);
		err=0; 
	}
        fclose(fp);
	return err;
}

int gen_bsd_config_file(void)
{
	FILE *fp;
        int err = -1;
	unlink(BSD_PATH);
        if ((fp = fopen(BSD_PATH, "w+")) != NULL) {
		fprintf(fp,"LowRSSIAPSteerEdge_RE=%d\n",40);
		fprintf(fp,"CUOverloadTh_2G=%d\n",50);
		fprintf(fp,"CUOverloadTh_5G_L=%d\n",80);
		fprintf(fp,"CUOverloadTh_5G_H=%d\n",80);
		fprintf(fp,"MetricPolicyChUtilThres_24G=%d\n",50);
		fprintf(fp,"MetricPolicyChUtilThres_5GL=%d\n",80);
		fprintf(fp,"MetricPolicyChUtilThres_5GH=%d\n",80);
		fprintf(fp,"ChPlanningChUtilThresh_24G=%d\n",50);
		fprintf(fp,"ChPlanningChUtilThresh_5GL=%d\n",80);
		fprintf(fp,"ChPlanningEDCCAThresh_24G=%d\n",200);
		fprintf(fp,"ChPlanningEDCCAThresh_5GL=%d\n",200);
		fprintf(fp,"ChPlanningOBSSThresh_24G=%d\n",200);
		fprintf(fp,"ChPlanningOBSSThresh_5GL=%d\n",200);
		fprintf(fp,"ChPlanningR2MonitorTimeoutSecs=%d\n",100);
		fprintf(fp,"ChPlanningR2MonitorProhibitSecs=%d\n",300);
		fprintf(fp,"ChPlanningR2MetricReportingInterval=%d\n",10);
		fprintf(fp,"ChPlanningR2MinScoreMargin=%d\n",10);
//#extra
#if 0		
		fprintf(fp,"MinRSSIOverload=%d\n",20);
		fprintf(fp,"RSSISteeringEdge_DG=%d\n",20);
		fprintf(fp,"RSSISteeringEdge_UG=%d\n",10);
		fprintf(fp,"MCSCrossingThreshold_DG=%d\n",6000);
		fprintf(fp,"MCSCrossingThreshold_UG=%d\n",50000);
		fprintf(fp,"RSSICrossingThreshold_DG=%d\n",15);
		fprintf(fp,"RSSICrossingThreshold_UG=%d\n",10);
		fprintf(fp,"phy_scal_factx100=%d\n",70);
		fprintf(fp,"RSSIAgeLim=%d\n",5);
		fprintf(fp,"RSSIAgeLim_preAssoc=%d\n",10);
		fprintf(fp,"RSSIMeasureSamples=%d\n",5);
		fprintf(fp,"ForceStrBlockTime=%d\n",600);
		fprintf(fp,"BTMStrBlockTime=%d\n",300);
		fprintf(fp,"ForceStrForbidTime=%d\n",300);
		fprintf(fp,"BTMStrForbidTime=%d\n",30);
		fprintf(fp,"StrForbidTimeJoin=%d\n",10);
		fprintf(fp,"prohibitTime11K=%d\n",30);
		fprintf(fp,"disable_pre_assoc_strng=%d\n",0);
		fprintf(fp,"disable_post_assoc_strng=%d\n",0);
		fprintf(fp,"disable_offloading=%d\n",0);
#endif

		fprintf(fp,"MaxClientOverloaded=%d\n",100);
		fprintf(fp,"ActivityThreshold=%d\n",6000);
		fprintf(fp,"StartInActive=%d\n",1);
		fprintf(fp,"MetricRepIntv=%d\n",10);
		fprintf(fp,"MetricPolicyRcpi_24G=%d\n",100);
		fprintf(fp,"MetricPolicyRcpi_5GL=%d\n",100);
		fprintf(fp,"MetricPolicyRcpi_5GH=%d\n",100);
		err=0; 
	}

        fclose(fp);
 	if(gen_mapd_config_file()!=0 ||  gen_1905_config_file()!=0 || gen_wapp_config_file()!=0 )
	 	err=-1;


	 return err;
}

int gen_wifi_config(int band,char* vap)
{
	FILE *fp;
        int i=0,err = -1;
	int total_band=num_of_wl_if();
	char path[200];
	memset(path,0,sizeof(path));
	snprintf(path,sizeof(path),"/etc/wapp_ap_%s.conf",vap);	
	unlink(path);
        if ((fp = fopen(path, "w+")) != NULL) {
		//##hospot2.0 ap configuration file##
		fprintf(fp,"interface=%s\n",vap);
		fprintf(fp,"interworking=1\n");
		fprintf(fp,"access_network_type=0\n");
		fprintf(fp,"internet=0\n");
		fprintf(fp,"venue_group=0\n");
		fprintf(fp,"venue_type=8\n");
		fprintf(fp,"anqp_query=1\n");
		fprintf(fp,"mih_support=0\n");
		fprintf(fp,"venue_name=eng%{Wi-Fi Alliance 2989 Copper Road Santa Clara, CA 95051, USA}\n");
		fprintf(fp,"hessid=bssid\n");
		fprintf(fp,"roaming_consortium_oi=50-6F-9A,00-1B-C5-04-BD\n");
		fprintf(fp,"advertisement_proto_id=0\n");
		fprintf(fp,"domain_name=wi-fi.org\n");
		fprintf(fp,"network_auth_type=1\n");
		fprintf(fp,"ipv4_type=3\n");
		fprintf(fp,"ipv6_type=0\n");
		if(band==0)
		{	
			fprintf(fp,"anqp_domain_id=1\n");
			fprintf(fp,"venue_url=1,https://venue-server.r2m-testbed.wi-fi.org/floorplans/index.html\n");
			fprintf(fp,"venue_url=1,https://venue-server.r2m-testbed.wi-fi.org/directory/index.html\n");
			fprintf(fp,"icon_metadata=160:76:eng:image/png:icon_red_eng.png\n");
		}	
		fprintf(fp,"nai_realm_data={\nnai_realm=mail.example.com\neap_method=eap-ttls\nauth_param=2:4\nauth_param=5:7}\n");
 		fprintf(fp,"nai_realm_data={\nnai_realm=cisco.com\neap_method=eap-ttls\nauth_param=2:4\nauth_param=5:7}\n");
 		fprintf(fp,"nai_realm_data={\nnai_realm=wi-fi.org\neap_method=eap-ttls\nauth_param=2:4\nauth_param=5:7\neap_method=eap-tls\nauth_param=5:6}\n");
 		fprintf(fp,"nai_realm_data={\nnai_realm=example.com\neap_method=eap-tls\nauth_param=5:6}\n");
		if(band==0)
		{	
			fprintf(fp,"advice_of_charge_data={\nadvice_of_charge_type=0\naoc_realm_encoding=0\naoc_realm=\naoc_language=ENG\naoc_currency_code=USD\naoc_plan_info=\'<?xml version=\"1.0\" encoding\"UTF-8\"?><Plan xmlns=\"http://www.wi-fi.org/specifications/hotspot2dot0/v1.0/aocpi\"><Description>Wi-Fi access for 1 hour, while you wait at the gate, $0.99</Description></Plan>\'\naoc_currency_code=USD}\n");
			fprintf(fp,"t_c_filename=0\n");
			fprintf(fp,"t_c_server_url=https://tandc-server.r2m-testbed.wi-fi.org\n");
			fprintf(fp,"t_c_timestamp=0\n");
			fprintf(fp,"osu_providers_nai_list=21,anonymous@hotspot.net\n");
		}
		fprintf(fp,"op_friendly_name=eng,Wi-Fi Alliance\n");
		fprintf(fp,"proto_port={\nip_protocol=1\nport=0\nstatus=0\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=6\nport=20\nstatus=1\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=6\nport=22\nstatus=0\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=6\nport=80\nstatus=1\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=6\nport=443\nstatus=1\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=6\nport=1723\nstatus=0\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=6\nport=5060\nstatus=0\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=17\nport=500\nstatus=1\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=17\nport=5060\nstatus=0\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=17\nport=4500\nstatus=1\n}\n");
		fprintf(fp,"proto_port={\nip_protocol=50\nport=0\nstatus=1}\n");
		fprintf(fp,"wan_metrics=n/a\n");
		fprintf(fp,"plmn={\nmcc=310\nmnc=026\n}\n");
		fprintf(fp,"plmn={\nmcc=208\nmnc=00\n}\n");
		fprintf(fp,"plmn={\nmcc=208\nmnc=01\n}\n");
		fprintf(fp,"plmn={\nmcc=208\nmnc=02\n}\n");
		fprintf(fp,"plmn={\nmcc=450\nmnc=02\n}\n");
		fprintf(fp,"plmn={\nmcc=450\nmnc=04\n}\n");
		fprintf(fp,"operating_class=81,115\n");
		fprintf(fp,"preferred_candi_list_included=0\n");
		fprintf(fp,"abridged=0\n");
		fprintf(fp,"disassociation_imminent=0\n");
		fprintf(fp,"bss_termination_included=0\n");
		fprintf(fp,"ess_disassociation_imminent=1\n");
		fprintf(fp,"disassociation_timer=100\n");
		fprintf(fp,"validity_interval=200\n");
		fprintf(fp,"bss_termination_duration=n/a\n");
		fprintf(fp,"session_information_url=remediation-server.R2-testbed.wi-fi.org\n");
		fprintf(fp,"bss_transisition_candi_list_preferences=n/a\n");
		fprintf(fp,"timezone=UTC8\n");
		fprintf(fp,"dgaf_disabled=0\n");
		fprintf(fp,"proxy_arp=0\n");
		fprintf(fp,"l2_filter=0\n");
		fprintf(fp,"icmpv4_deny=0\n");
		fprintf(fp,"p2p_cross_connect_permitted=0\n");
		fprintf(fp,"mmpdu_size=1024\n");
		fprintf(fp,"external_anqp_server_test=0\n");
		fprintf(fp,"gas_cb_delay=1\n");
		fprintf(fp,"hs2_openmode_test=0\n");
		fprintf(fp,"icon_path=/etc/\n");
		fprintf(fp,"osu_providers_list={\naosu_friendly_name=eng:SP Red Test Only\nosu_friendly_name=kor:SP 레드 시험 만\nosu_server_uri=https://osu-server.R2-testbed-RKS.wi-fi.org:9443/OnlineSignup/services/\nosu_method=1\nicon=128:61:zxx:image/png:icon_red_zxx.png\nicon=160:76:eng:image/png:icon_red_eng.png\nosu_nai=n/a\nosu_service_desc=eng:Free service for test purpose\nosu_service_desc=kor:테스트 목적으로 무료 서비스\n}\n");
		fprintf(fp,"anonymous_nai=n/a\n");
		if(band)
			fprintf(fp,"osu_interface=rai1\n");
		else
			fprintf(fp,"osu_interface=ra1\n");
		fprintf(fp,"legacy_osu=2\n");
		fprintf(fp,"qosmap=1\n");
		fprintf(fp,"dscp_range=08:15:0:7:255:255:16:31:32:39:255:255:40:47:255:255\n");
		fprintf(fp,"dscp_exception=53:2:22:6\n");
		fprintf(fp,"qload_test=0\n");
		fprintf(fp,"qload_cu=50\n");
		fprintf(fp,"qload_sta_cnt=1\n");
		fprintf(fp,"icon_tag=1\n");
		fprintf(fp,"mbo_ap_cdcp=1\n");
		fprintf(fp,"mbo_ap_assoc_disallow_reason=0\n");
		fprintf(fp,"mbo_ap_assoc_retry_delay=0\n");
		fprintf(fp,"mbo_ap_transition_reason_code=0\n");
		fprintf(fp,"mbo_ap_capability=64\n");
		err=0; 
	}
        fclose(fp);
	return err;
}

int gen_wapp_config_file(void)
{
	FILE *fp;
        int i=0,err = -1;
	int total_band=num_of_wl_if();
	char p1[40],p2[400];
	unlink(WAPP_PATH);
	memset(p2,0,sizeof(p2));
        if ((fp = fopen(WAPP_PATH, "w+")) != NULL) {
		 for(i = 0; i < total_band; i++) 
		 {
                	SKIP_ABSENT_BAND(i);
			memset(p1,0,sizeof(p1));
			snprintf(p1,sizeof(p1),"/etc/wapp_ap_%s.conf;",get_wififname(i));	
			gen_wifi_config(i,get_wififname(i));
			strlcat(p2, p1, sizeof(p2));
		 }
		 if(strlen(p2))
			fprintf(fp,"conf_list=%s\n",p2);
		err=0; 
	}
        fclose(fp);
	return err;
}

/*
int dis_steer(void)
{
        char *nv, *nvp, *b;
        char *reMac, *mac2g, *mac5g, *timestamp;
        nv = nvp = get_cfg_relist(0);
        if (nv) {
                sleep(3); //lbd ready
                while ((b = strsep(&nvp, "<")) != NULL) {
                        if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
                                continue;
                        set_steer(reMac,1);
                        set_steer(mac2g,1);
                        set_steer(mac5g,1);
                }
                free(nv);
        }
        return 0;
}
*/

