TOPDIR ?= ../../../..

COMMON_SRCDIR ?= $(TOPDIR)/src
QUICKSEC_SRCDIR ?= $(COMMON_SRCDIR)/quicksec
CONFIG_INCLUDE_DIR ?= $(TOPDIR)/config/quicksec/include
SCRIPTDIR ?= $(TOPDIR)/scripts
DTDCOMPRESS_DIR := ../../../host/dtd-compress/
DTDCOMPRESS := $(DTDCOMPRESS_DIR)/dtd-compress
PTHREADS ?= 1

override CFLAGS += -MMD -Wall -Werror $(EXTRA_CFLAGS) \
	${EXTERNAL_CFLAGS}

override LDLIBS += -ldl -lrt


INCLUDE_LIST := \
    -I$(TOPDIR)/config/quicksec/include \
    -I$(TOPDIR)/external-src/sshcrc32 \
    -I$(TOPDIR)/external-src/zlib \
    -I$(TOPDIR)/src/base/debug \
    -I$(TOPDIR)/src/base/debugstrbuf \
    -I$(TOPDIR)/src/base/implementationdefs \
    -I$(TOPDIR)/src/base/inaddr \
    -I$(TOPDIR)/src/base/inaddrconvert \
    -I$(TOPDIR)/src/base/publicdefs \
    -I$(TOPDIR)/src/ipsec/dataplane_linux \
    -I$(TOPDIR)/src/ipsec/idtransformer \
    -I$(TOPDIR)/src/ipsec/ipseccontrol \
    -I$(TOPDIR)/src/ipsec/ipselector \
    -I$(TOPDIR)/src/ipsec/ipselectorconvert \
    -I$(TOPDIR)/src/ipsec/ipselectorencode \
    -I$(TOPDIR)/src/ipsec/ipselectormatch \
    -I$(TOPDIR)/src/ipsec/ipselectorparse \
    -I$(TOPDIR)/src/ipsec/keepalive \
    -I$(TOPDIR)/src/ipsec/netlinkxfrm \
    -I$(TOPDIR)/src/ipsec/transformbuffer \
    -I$(TOPDIR)/src/ipsec/transformbufferpool \
    -I$(TOPDIR)/src/quicksec/apps \
    -I$(TOPDIR)/src/quicksec/ipsecutil \
    -I$(TOPDIR)/src/quicksec/policymanager \
    -I$(TOPDIR)/src/toolkit/certutils \
    -I$(TOPDIR)/src/toolkit/sshadt \
    -I$(TOPDIR)/src/toolkit/sshapputil \
    -I$(TOPDIR)/src/toolkit/sshasn1 \
    -I$(TOPDIR)/src/toolkit/sshaudit \
    -I$(TOPDIR)/src/toolkit/sshcert \
    -I$(TOPDIR)/src/toolkit/sshcipher \
    -I$(TOPDIR)/src/toolkit/sshcore \
    -I$(TOPDIR)/src/toolkit/sshcrypto \
    -I$(TOPDIR)/src/toolkit/sshcryptoaux \
    -I$(TOPDIR)/src/toolkit/sshcryptocore \
    -I$(TOPDIR)/src/toolkit/sshdhcp \
    -I$(TOPDIR)/src/toolkit/ssheap \
    -I$(TOPDIR)/src/toolkit/ssheloop \
    -I$(TOPDIR)/src/toolkit/sshenroll \
    -I$(TOPDIR)/src/toolkit/sshexternalkey \
    -I$(TOPDIR)/src/toolkit/sshfsm \
    -I$(TOPDIR)/src/toolkit/sshhash \
    -I$(TOPDIR)/src/toolkit/sshhttp \
    -I$(TOPDIR)/src/toolkit/sshikev2 \
    -I$(TOPDIR)/src/toolkit/sshisakmp \
    -I$(TOPDIR)/src/toolkit/sshl2tp \
    -I$(TOPDIR)/src/toolkit/sshldap \
    -I$(TOPDIR)/src/toolkit/sshmac \
    -I$(TOPDIR)/src/toolkit/sshmath \
    -I$(TOPDIR)/src/toolkit/sshmisc \
    -I$(TOPDIR)/src/toolkit/sshnet \
    -I$(TOPDIR)/src/toolkit/sshpacketstream \
    -I$(TOPDIR)/src/toolkit/sshpk \
    -I$(TOPDIR)/src/toolkit/sshpkcs \
    -I$(TOPDIR)/src/toolkit/sshppp \
    -I$(TOPDIR)/src/toolkit/sshradius \
    -I$(TOPDIR)/src/toolkit/sshrandom \
    -I$(TOPDIR)/src/toolkit/sshsim \
    -I$(TOPDIR)/src/toolkit/sshstream \
    -I$(TOPDIR)/src/toolkit/sshstrutil \
    -I$(TOPDIR)/src/toolkit/sshsysutil \
    -I$(TOPDIR)/src/toolkit/sshtestutil \
    -I$(TOPDIR)/src/toolkit/sshtls \
    -I$(TOPDIR)/src/toolkit/sshutil \
    -I$(TOPDIR)/src/toolkit/sshvalidator \
    -I$(TOPDIR)/src/toolkit/sshxml

override CPPFLAGS += \
    -I$(CONFIG_INCLUDE_DIR)/. \
    $(INCLUDE_LIST) \
    -DSSH_BUILD_IPSEC

ifeq ($(DEBUG), 1)
override CPPFLAGS += \
    -DDEBUG_LIGHT \

override CFLAGS += -ggdb
else
override CFLAGS += \
    -Wno-unused-function \
    -Wno-unused-variable

# The compiler version detection works only for gcc and clang
COMPILER_MAJOR_VERSION := $(shell $(CC) -dumpversion |sed 's/\..*//')
COMPILER_MINOR_VERSION := $(shell $(CC) -dumpversion \
	|sed -r 's/[0-9]{1,}\.([0-9]{1,}).*/\1/')
NO_UNUSED_BUT_SET_VARIABLE_WARNING_SUPPORTED := $(shell \
	[ $(COMPILER_MAJOR_VERSION) -gt 3 -a $(COMPILER_MINOR_VERSION) -gt 5 ] \
	|| [ $(COMPILER_MAJOR_VERSION) -gt 4 ] \
	&& echo true)

ifeq ($(NO_UNUSED_BUT_SET_VARIABLE_WARNING_SUPPORTED),true)
override CFLAGS += -Wno-unused-but-set-variable
endif

endif

ifeq ($(SERVER), 1)
override CPPFLAGS += -DQUICKSEC_DIST_SERVER
endif

ifeq ($(SMALL),1)
override CPPFLAGS += -DSSH_IPSEC_SMALL
endif

ifeq ($(AES),INTEL)
override CPPFLAGS += -DHAVE_AES -DHAVE_AES_INTEL_INSTRUCTION_SET
override CFLAGS += -maes -msse4.1 -mpclmul
endif

QUICKSEC_PROGRAMS := \
    quicksecpm \
    tinypm \
    clientpm \
    make-vendor-id \
    ssh-berdump \
    ssh-certmake \
    ssh-certview \
    ssh-cmpclient \
    ssh-keytool \
    ssh-p12extract \
    ssh-p12make \
    ssh-scepclient \

all: $(QUICKSEC_PROGRAMS)

-include Makefile.inc
-include Makefile.internal


ifeq ($(AES),INTEL)
libcrypto.a: \
    intel-aes.o
else
libcrypto.a: \
    mode-gcm.o \
    rijndael.o
endif

ifeq ($(PTHREADS), 1)
    override CFLAGS += -pthread
    override LDLIBS += -lpthread
endif
             
ifeq ($(PTHREADS),1)
libbase.a: \
    sshmt_pthreads.o \
    sshmt_timeouts.o
endif 

quicksecpm: \
    quicksecpm_audit.o \
    quicksecpm.o \
    quicksecpm_unix.o \
    quicksecpm_xmlconf.o \
    quicksecpm_xmlconf_http.o \
    redirect_filter.o \
    libipsecpm.a \
    libipsec.a \
    libproto.a \
    libcrypto.a \
    libbase.a \
    quicksec_dtd.o

tinypm: \
    tinypm.o \
    libipsecpm.a \
    libipsec.a \
    libproto.a \
    libcrypto.a \
    libbase.a

clientpm: \
    clientpm.o \
    libipsecpm.a \
    libipsec.a \
    libproto.a \
    libcrypto.a \
    libbase.a

quicksec_dtd.c:
	test -s $(DTDCOMPRESS) || $(MAKE) -C $(DTDCOMPRESS_DIR)
	$(DTDCOMPRESS) -b quicksec_dtd \
		-o quicksec_dtd.c $(QUICKSEC_SRCDIR)/apps/quicksec.dtd

make-vendor-id: \
    make-vendor-id.o \
    libcrypto.a \
    libbase.a

ssh-berdump: \
    ssh-berdump.o \
    dump-ber.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-certmake: \
    ssh-certmake.o \
    dump-key.o \
    iprintf.o \
    parse-x509-forms.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-certview: \
    ssh-certview.o \
    dump-ber.o \
    dump-cert.o \
    dump-crl.o \
    dump-key.o \
    dump-other.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-cmpclient: \
    ssh-cmpclient.o \
    au-ek.o \
    dump-ber.o \
    dump-cert.o \
    dump-key.o \
    ec-cmp.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-keytool: \
    ssh-keytool.o \
    dump-key.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-p12extract: \
    ssh-p12extract.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-p12make: \
    ssh-p12make.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-scepclient: \
    ssh-scepclient.o \
    au-ek.o \
    dump-ber.o \
    dump-cert.o \
    dump-key.o \
    ec-cep.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

# This now also contains files from src/base dir
libipsec.a: \
    in_addr.o \
    in_addr_convert.o \
    data_plane.o \
    data_plane_policy.o \
    idtransformer_ikev2_prf.o \
    idtransformer.o \
    idtransformer_ikev2_encr.o \
    idtransformer_ikev2_integ.o \
    idtransformer_ikev2_dh.o \
    idtransformer_strength.o \
    in_addr_convert.o \
    ipsec_control_db.o \
    ipsec_base_policy.o \
    ipsec_control_init.o \
    ipsec_control_sa.o \
    ipsec_control_policy.o \
    ip_selector_convert.o \
    ip_selector_encode.o \
    ip_selector_match.o \
    ip_selector_parse.o \
    ipsec_keepalive.o \
    netlink_xfrm.o \
    transform_buffer.o \
    transform_buffer_pool.o

libipsecpm.a: \
    libipsec.a \
    ip_interfaces.o \
    ras_dhcp_addrpool.o \
    rac_virtual_ip_l2tp_st.o \
    util_ek.o \
    util_ike_id.o \
    pad_ike.o \
    util_algorithms.o \
    spd_rules.o \
    util_ike_cfgmode.o \
    spd_ike_init.o \
    ras.o \
    rac_virtual_ip_utils.o \
    pad_auth_passwd.o \
    rac_virtual_ip.o \
    util_connection.o \
    util_alloc.o \
    sad_ike_common_st.o \
    sad_ike.o \
    sad_ike_i_negotiation_st.o \
    util_dpd.o \
    util_ike_certs.o \
    spd_main_st.o \
    util_compat.o \
    spd_config_st.o \
    util_virtual_adapter.o \
    util_dnsresolver.o \
    util_netconfig.o \
    ras_legacy_auth_server.o \
    util_ike_tsutils.o \
    util_servers.o \
    util_statistics.o \
    util_ike_sautils.o \
    util_ike_confutils.o \
    sad_ike_initiator_st.o \
    spd_rule_lookup.o \
    util_unknown_spis.o \
    util_render.o \
    util_peer.o \
    sad_mobike.o \
    spd_tunnels.o \
    spd_main.o \
    util_l2tp.o \
    spd_ike_blacklist.o \
    spd_shutdown_st.o \
    spd_tunnels_ike.o \
    sad_mobike_st.o \
    util_audit.o \
    sad_ike_spis.o \
    spd_ike.o \
    pad_ike_certs.o \
    spd_batch_st.o \
    util_cm.o \
    netevent_listener.o \
    util_tables.o \
    util_nameserver.o \
    util_linearize.o \
    ras_radius_acct.o \
    rac_virtual_ip_cfgmode_st.o \
    pad_auth_radius.o \
    spd_iface_st.o \
    pad_auth_domain.o \
    sad_sa_handler.o \
    spd_access.o \
    pad_ike_eap.o \
    pad_authorization_local.o \
    rac_virtual_ip_st.o \
    spd_ike_psk.o \
    ras_cfgmode_client_store.o \
    util.o \
    util_ek_st.o \
    util_ike_spis.o \
    ras_addrpool.o \
    util_ipsec.o \
    pad_authorization.o \
    util_l2tp_lns_st.o \
    util_ike_ipsec.o \
    spd_ike_delete.o

libproto.a: \
    sshsnlist.o \
    pem-format.o \
    sshprvkey.o \
    ssh2pubkeyencode.o \
    sshpubkey.o \
    sshkeyblob2.o \
    ssh1encode.o \
    sshcipherlist.o \
    sshkeyblob1.o \
    sshpsystem.o \
    sshasn1.o \
    ssh_berfile.o \
    sshber.o \
    sshasn1create.o \
    sshber-util.o \
    sshasn1print.o \
    x509req_encode.o \
    x509public_encode.o \
    x509ext_encode.o \
    x509private.o \
    dn-util.o \
    dn-der.o \
    x509cert.o \
    x509crl_encode.o \
    x509req_decode.o \
    x509get.o \
    x509crmf_value.o \
    x509crmf_decode.o \
    x509crl_sync.o \
    x509name_decode.o \
    ocsp_http.o \
    x509cert_encode.o \
    ocsp_common.o \
    x509signature.o \
    x509crmf_encode.o \
    x509ext_decode.o \
    eckeys.o \
    ocsp_client.o \
    x509cert_sync.o \
    x509init.o \
    x509public_decode.o \
    x509.o \
    sshglist.o \
    x509crl.o \
    sshpswbmac.o \
    x509name_encode.o \
    x509crl_decode.o \
    x509cert_decode.o \
    x509set.o \
    oid.o \
    dn-ldap.o \
    dhcp_packet.o \
    dhcp_states.o \
    dhcp_options.o \
    dhcpv6_options.o \
    dhcp_util.o \
    dhcp.o \
    dhcpv6_util.o \
    dhcpv6_states.o \
    dhcpv6_packet.o \
    ssheap_aka.o \
    ssheap_common.o \
    ssheap_config.o \
    ssheap_connection.o \
    ssheap_md5.o \
    ssheap_mschap.o \
    ssheap_otp.o \
    ssheap_packet.o \
    ssheap_params.o \
    ssheap_pass_through.o \
    ssheap_protocol.o \
    ssheap_radius.o \
    ssheap_setup.o \
    ssheap_sim.o \
    ssheap_tls.o \
    x509cmp.o \
    enroll-pkix.o \
    crmf-crypto.o \
    x509cmp_decode.o \
    enroll-scep.o \
    x509cmp_util.o \
    enroll.o \
    scep-client.o \
    x509cmp_encode.o \
    scep-common.o \
    dummyacc.o \
    dummyprov.o \
    extkeyprov.o \
    genaccdevice.o \
    genaccprovider.o \
    softacc.o \
    softprovider.o \
    sshexternalkey.o \
    sshsoftkey.o \
    sshhttpserver.o \
    sshhttpclient.o \
    sshhttputils.o \
    ikev2-auth-init-in.o \
    ikev2-recv.o \
    ikev2-ke-error-out.o \
    ikev2-string-protocol.o \
    ikev2-auth2-resp-out.o \
    ikev2-auth2-init-out.o \
    ikev2-fb-policy-qm.o \
    ikev2-state.o \
    ikev2-init-ike-sa.o \
    ikev2-rekey-ike.o \
    ikev2-fb-cfgmode-conv.o \
    ikev2-fb-conv.o \
    ikev2-request-cookie-out.o \
    ikev2-string-auth-method.o \
    ikev2-sa-init-resp-in.o \
    ikev2-shared-key-auth.o \
    ikev2-fb-cfgmode.o \
    ikev2-common-info.o \
    ikev2-auth-resp-in.o \
    ikev2-ike-rekey-init-out.o \
    ikev2-tables.o \
    ikev2-crypto.o \
    ikev2-info-resp-out.o \
    ikev2-auth2-init-in.o \
    ikev2-auth-init-out.o \
    ikev2-packet-debug.o \
    ikev2-state-common.o \
    ikev2-decode.o \
    ikev2-child-init-in.o \
    ikev2-sa-crypto.o \
    ikev2-encode.o \
    ikev2-fb-policy-p2.o \
    ikev2-string-notify.o \
    ikev2-packet-decode.o \
    ikev2-sa-init-init-in.o \
    ikev2-sa-init-resp-out.o \
    ikev2-string-cert-encoding.o \
    ikev2-ike-rekey-init-in.o \
    ikev2-fb-nat-t.o \
    ikev2-nat-t.o \
    ikev2-info-init-in.o \
    ikev2-child-resp-in.o \
    ikev2-child-resp-out.o \
    ikev2-render-ike-spi.o \
    ikev2-sa-init-error.o \
    ikev2-redirect.o \
    ikev2-fb-util.o \
    ikev2-auth2-resp-in.o \
    ikev2-info-resp-in.o \
    ikev2-string-payload.o \
    ikev2-render-payload.o \
    ikev2-groups.o \
    ikev2-fb-ts-conv.o \
    ikev2-auth-resp-out.o \
    ikev2-linearize.o \
    ikev2-multiple-auth.o \
    ikev2-init.o \
    ikev2-fb-policy-p1.o \
    ikev2-fb-xauth.o \
    ikev2-string-transform.o \
    ikev2-ike-rekey-resp-out.o \
    ikev2-debug.o \
    ikev2-fb-init-qm.o \
    ikev2-sa-init-init-out.o \
    ikev2-init-ipsec-sa.o \
    ikev2-fb-sa-conv.o \
    ikev2-tsutil.o \
    ikev2-fb-init-p1.o \
    ikev2-sautil.o \
    ikev2-init-info-sa.o \
    ikev2-confutil.o \
    ikev2-prfplus.o \
    ikev2-ike-rekey-resp-in.o \
    ikev2-send.o \
    ikev2-fb-policy-certs.o \
    ikev2-eap-auth.o \
    ikev2-string-attribute-type.o \
    ikev2-string-id.o \
    ikev2-mobike.o \
    ikev2-child-init-out.o \
    ikev2-fb-init-info.o \
    ikev2-fb-init.o \
    ikev2-fb-id-conv.o \
    ikev2-pk-auth.o \
    ikev2-window.o \
    ikev2-packet-encode.o \
    ikev2-info-init-out.o \
    isakmp_util.o \
    isakmp_init.o \
    isakmp_reply.o \
    isakmp_udp.o \
    isakmp.o \
    isakmp_packet.o \
    isakmp_linearize.o \
    isakmp_state.o \
    isakmp_debug.o \
    isakmp_finalize.o \
    isakmp_attrs.o \
    isakmp_input.o \
    isakmp_sa.o \
    isakmp_da.o \
    isakmp_id.o \
    isakmp_output.o \
    isakmp_tables.o \
    isakmp_misc.o \
    isakmp_groups.o \
    isakmp_string_payload.o \
    isakmp_cookie.o \
    isakmp_packet_debug.o \
    isakmp_crypt.o \
    isakmp_stat.o \
    sshl2tp_message.o \
    sshl2tp_st_lns_oc.o \
    sshl2tp.o \
    sshl2tp_st_lac_oc.o \
    sshl2tp_st_lns_ic.o \
    sshl2tp_st_cc_responder.o \
    sshl2tp_util.o \
    sshl2tp_transport.o \
    sshl2tp_tables.o \
    sshl2tp_st_session.o \
    sshl2tp_st_tunnel.o \
    sshl2tp_st_cc_initiator.o \
    sshl2tp_st_lac_ic.o \
    ldap-strtofilter.o \
    ldap-ext.o \
    ldap-init.o \
    ldap-input.o \
    ldap-modify.o \
    ldap-output.o \
    ldap-conv.o \
    ldap-connect.o \
    ldap-search.o \
    ldap-object.o \
    ldap-filtertostr.o \
    ldap-bind.o \
    pkcs7-create-sync.o \
    pkcs8.o \
    pkcs7-encode.o \
    pkcs7-receive.o \
    pkcs7-receive-sync.o \
    pkcs6.o \
    pkcs7-common.o \
    pkcs6-cert.o \
    pkcs7-decode.o \
    pkcs12-conv.o \
    pkcs7-create.o \
    pkcs12.o \
    pkcs5.o \
    pkcs1-formats.o \
    sshppp_thread.o \
    sshppp_pap_fsm.o \
    sshppp_chap_fsm.o \
    sshppp_lcp.o \
    sshppp_protocol_fsm.o \
    sshppp_ipcp_config.o \
    sshppp_lcp_config.o \
    sshppp_fcs.o \
    sshppp_linkpkt.o \
    sshppp_protocol.o \
    sshppp_flush.o \
    sshppp_timer.o \
    sshppp_auth.o \
    sshppp_setup.o \
    sshppp_chap.o \
    sshppp_eap_fsm.o \
    sshppp_ipcp.o \
    sshppp_io_stream.o \
    sshppp_radius.o \
    sshppp_fsm.o \
    sshppp_config.o \
    sshppp_events.o \
    sshradius_tables.o \
    sshradius.o \
    sshradius_url.o \
    sshsim_sample.o \
    tls_kt_RCertificate.o \
    tls_kt_cont_funcs.o \
    tls_async.o \
    tls_kt_WHelloRequest.o \
    tls_appstream.o \
    tls_kt_RFinished.o \
    tls_kt_WServerHello.o \
    tls_extra.o \
    tls_kextrans.o \
    tls_downstream.o \
    tls_record.o \
    tls_kt_WCertificateRequest.o \
    tls_kt_RChangeCipher.o \
    tls_kt_RServerKeyExchance.o \
    tls_kt_RClientKeyExchange.o \
    tls_util.o \
    tls_kt_WServerKeyExchance.o \
    tls_multihash.o \
    tls_kt_WClientHello.o \
    tls_kt_RCertificateVerify.o \
    tls_main.o \
    tls_kt_WChangeCipher.o \
    tls_kt_RServerHello.o \
    tls_kt_WCertificateVerify.o \
    tls_kt_WFinished.o \
    tls_accel.o \
    tls_kt_RServerHelloDone.o \
    tls_crypto.o \
    tls_kex.o \
    tls_kt_WCertificate.o \
    tls_kt_WClientKeyExchance.o \
    tls_kt_WServerHelloDone.o \
    tls_alert.o \
    tls_suites.o \
    tls_cache.o \
    tls_kt_RCertificateRequest.o \
    tls_tempkey.o \
    tls_kt_RClientHello.o \
    cmi-pcnst.o \
    cmi-trust.o \
    cmi-key.o \
    cert-db.o \
    cmi-map.o \
    cmi.o \
    cmi-edb.o \
    cmi-debug.o \
    cmi-pkcs7.o \
    cmi-ocsp.o \
    cmi-config.o \
    cmi-ldap.o \
    cmi-cert.o \
    cmi-key-pk.o \
    cmi-list.o \
    cmi-crl.o \
    cmi-http.o \
    sshxml_accessors.o \
    sshxml_chain.o \
    sshxml_dom.o \
    sshxml_input_data.o \
    sshxml_input_file.o \
    sshxml_parser.o \
    sshxml_tables.o \
    sshxml_verifier.o \
    sshxml_verifier_dfa.o \
    sshek_providers_toolkit.o

libcrypto.a: \
    nociph.o \
    aes_keywrap.o \
    ansi_x962.o \
    bufhash.o \
    bufzip.o \
    genauxmp.o \
    keyexpand.o \
    md4.o \
    oldimportapi.o \
    pkcs1_pad.o \
    singledes.o \
    sshcipheralias.o \
    sshrandompoll.o \
    crypto_tests.o \
    genaux.o \
    crypto_init.o \
    namelist.o \
    hash-oid.o \
    md5.o \
    sha256.o \
    sha512.o \
    sha.o \
    hmac.o \
    macs.o \
    xcbc-mac.o \
    sshmp-2adic.o \
    sshmp-arithmetic.o \
    sshmp-arithmetic-extra.o \
    sshmp-convabs.o \
    sshmp-ecp.o \
    sshmp-init.o \
    sshmp-integer-core.o \
    sshmp-integer-misc.o \
    sshmp-intmod.o \
    sshmp-kernel.o \
    sshmp-montgomery.o \
    sshmp-naf.o \
    sshmp-powm.o \
    sshmp-tests.o \
    sshmp-xuint.o \
    sshsieve.o \
    sshrgf-mgf1.o \
    sshrgf-pss.o \
    genpkcs_private.o \
    sshproxykey.o \
    sshrgf.o \
    dl-generate.o \
    rsa-operation.o \
    genmp-integer.o \
    ssh-pk-export.o \
    rsa-utility.o \
    dlfix.o \
    ecpfix.o \
    ecpglue.o \
    dl-dh.o \
    rsa-maker.o \
    pkcs1.o \
    dsa-user.o \
    genpkcs_public.o \
    ecp-maker.o \
    ssh-pk-group.o \
    ssh-pk-prv-gen.o \
    dl-stack.o \
    dl-dsa.o \
    sshrgf-oaep.o \
    ecp-user.o \
    dl-utility.o \
    ssh-pk-prv-def.o \
    genpkcs_dh.o \
    rsa-generate.o \
    genpkcs.o \
    dsa-maker.o \
    libmonitor.o \
    genmp-prime.o \
    rsa-user.o \
    genrand.o \
    randompool.o \
    adler32.o \
    compress.o \
    crc32.o \
    deflate.o \
    gzio.o \
    infblock.o \
    infcodes.o \
    inffast.o \
    inflate.o \
    inftrees.o \
    infutil.o \
    trees.o \
    uncompr.o \
    zutil.o \
    des.o \
    genciph.o \
    mode-ccm.o \
    sshcryptoaux.o \
    genhash.o \
    genmac.o \
    nist-health-test.o \
    nist-sp-800-90.o

libbase.a: \
    sshadt_avltree.o \
    sshadt_map.o \
    sshadt_array.o \
    sshadt_conv.o \
    sshadt_priority_heap.o \
    sshadt.o \
    sshadt_assoc.o \
    sshadt_ranges.o \
    sshadt_list.o \
    sshaudit.o \
    sshaudit_file.o \
    sshaudit_syslog.o \
    sshaudit_tables.o \
    sshaudit_util.o \
    sshbprintf.o \
    sshbuffer.o \
    sshcalendar.o \
    sshdebug.o \
    sshdllist.o \
    sshdlqueue.o \
    sshenum.o \
    sshenumcase.o \
    sshfastalloc.o \
    sshfatal.o \
    sshgetopt.o \
    sshglobals.o \
    sshmalloc.o \
    sshmatch.o \
    sshmemcmp.o \
    sshobstack.o \
    sshrand.o \
    sshrecalloc.o \
    sshsimplehashtable.o \
    sshsnprintf.o \
    sshtime.o \
    sshtimemeasure.o \
    sshustr.o \
    sshutil.o \
    sshxbuffer.o \
    sshxmalloc.o \
    sshnothreads.o \
    sshoperation.o \
    sshthreadedtimeout.o \
    sshthreadpool.o \
    sshtimeouts.o \
    sshunixeloop.o \
    sshfsm.o \
    sshbufaux.o \
    sshdecay.o \
    sshgenutils.o \
    sshdnserror.o \
    sshdnsnameserver.o \
    sshdnspacket.o \
    sshdnspacketrender.o \
    sshdnsquery.o \
    sshdnsrender.o \
    sshdnsresolver.o \
    sshdnsrrdataprint.o \
    sshdnsrrsetcache.o \
    sshdnsrrsetrender.o \
    sshdnsrrtype.o \
    sshdnstransport.o \
    sshdnstransporttcp.o \
    sshdnstransportudp.o \
    sshicmp-util.o \
    sshinetbits.o \
    sshinet.o \
    sshinetcalc.o \
    sshinetcompare.o \
    sshinetencode.o \
    sshinetether.o \
    sshinethash.o \
    sshinetmapped.o \
    sshinetmask.o \
    sshinetmerge.o \
    sshinetnetmask.o \
    sshinetparse.o \
    sshinetprint.o \
    sshinetproto.o \
    sshinetrender.o \
    sshinetscope.o \
    sshinetstrtobin.o \
    sshlinuxnetevent.o \
    sshlinuxnetmac.o \
    sshnameserver.o \
    sshnetconfig.o \
    sshpdbg.o \
    sshsocks.o \
    sshtcp.o \
    sshudp-ip.o \
    sshudp-str.o \
    sshunixlocalstream.o \
    sshunixtcp.o \
    sshunixtcplocalstream.o \
    sshunixudp.o \
    sshurl.o \
    sshvrf.o \
    sshpacketwrapper.o \
    sshpacketimpl.o \
    sshpacketstream.o \
    sshstreamconnect.o \
    sshstream.o \
    sshfilterstream.o \
    sshstreampair.o \
    sshdatastream.o \
    sshbase16.o \
    sshbase64.o \
    sshbitvector.o \
    sshencode.o \
    sshencodetypes.o \
    sshfingerprint.o \
    sshmiscstring.o \
    sshregex.o \
    sshregexsyn_egrep.o \
    sshregexsyn_ssh.o \
    sshregexsyn_zsh.o \
    sshstr.o \
    sshutf8.o \
    sshentropy.o \
    sshfilebuffer.o \
    sshfileio.o \
    sshmallocspare.o \
    sshsignals.o \
    sshthreadedmbox.o \
    sshunixdevicestream.o \
    sshunixdirectory.o \
    sshunixfdstream.o \
    sshcrc32.o \
    debug_strf.o \
    debug_ssh.o \
    debug_strbuf_stack.o \
    sshlinuxnetconfig.o


$(QUICKSEC_PROGRAMS):
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.a:
	$(AR) rcs $@ $^

depend:
	cat *.d >Makefile.depend

nodepend:
	rm -f Makefile.depend

clean:
	rm -f *.o *.d *.a $(QUICKSEC_PROGRAMS) Makefile.depend
	rm -f quicksec_dtd.c

vpath %.c \
    $(TOPDIR)/external-src/sshcrc32 \
    $(TOPDIR)/external-src/zlib \
    $(TOPDIR)/src/base/debug \
    $(TOPDIR)/src/base/debug_ssh \
    $(TOPDIR)/src/base/debugstrbuf \
    $(TOPDIR)/src/base/inaddr \
    $(TOPDIR)/src/base/inaddrconvert \
    $(TOPDIR)/src/ipsec/dataplane_linux \
    $(TOPDIR)/src/ipsec/idtransformer \
    $(TOPDIR)/src/ipsec/ipseccontrol \
    $(TOPDIR)/src/ipsec/ipselectorconvert \
    $(TOPDIR)/src/ipsec/ipselectorencode \
    $(TOPDIR)/src/ipsec/ipselectormatch \
    $(TOPDIR)/src/ipsec/ipselectorparse \
    $(TOPDIR)/src/ipsec/keepalive \
    $(TOPDIR)/src/ipsec/netlinkxfrm \
    $(TOPDIR)/src/ipsec/transformbuffer \
    $(TOPDIR)/src/ipsec/transformbufferpool \
    $(TOPDIR)/src/quicksec/apps \
    $(TOPDIR)/src/quicksec/ipsecutil \
    $(TOPDIR)/src/quicksec/policymanager \
    $(TOPDIR)/src/toolkit/certutils \
    $(TOPDIR)/src/toolkit/sshadt \
    $(TOPDIR)/src/toolkit/sshapputil \
    $(TOPDIR)/src/toolkit/sshasn1 \
    $(TOPDIR)/src/toolkit/sshaudit \
    $(TOPDIR)/src/toolkit/sshcert \
    $(TOPDIR)/src/toolkit/sshcipher \
    $(TOPDIR)/src/toolkit/sshcore \
    $(TOPDIR)/src/toolkit/sshcryptoaux \
    $(TOPDIR)/src/toolkit/sshcryptocore \
    $(TOPDIR)/src/toolkit/sshdhcp \
    $(TOPDIR)/src/toolkit/ssheap \
    $(TOPDIR)/src/toolkit/ssheloop \
    $(TOPDIR)/src/toolkit/sshenroll \
    $(TOPDIR)/src/toolkit/sshexternalkey \
    $(TOPDIR)/src/toolkit/sshfsm \
    $(TOPDIR)/src/toolkit/sshhash \
    $(TOPDIR)/src/toolkit/sshhttp \
    $(TOPDIR)/src/toolkit/sshikev2 \
    $(TOPDIR)/src/toolkit/sshisakmp \
    $(TOPDIR)/src/toolkit/sshl2tp \
    $(TOPDIR)/src/toolkit/sshldap \
    $(TOPDIR)/src/toolkit/sshmac \
    $(TOPDIR)/src/toolkit/sshmath \
    $(TOPDIR)/src/toolkit/sshmisc \
    $(TOPDIR)/src/toolkit/sshnet \
    $(TOPDIR)/src/toolkit/sshpacketstream \
    $(TOPDIR)/src/toolkit/sshpk \
    $(TOPDIR)/src/toolkit/sshpkcs \
    $(TOPDIR)/src/toolkit/sshppp \
    $(TOPDIR)/src/toolkit/sshradius \
    $(TOPDIR)/src/toolkit/sshrandom \
    $(TOPDIR)/src/toolkit/sshsim \
    $(TOPDIR)/src/toolkit/sshstream \
    $(TOPDIR)/src/toolkit/sshstrutil \
    $(TOPDIR)/src/toolkit/sshsysutil \
    $(TOPDIR)/src/toolkit/sshtls \
    $(TOPDIR)/src/toolkit/sshvalidator \
    $(TOPDIR)/src/toolkit/sshxml

-include Makefile.depend

