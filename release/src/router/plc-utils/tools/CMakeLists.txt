# ====================================================================
#
# --------------------------------------------------------------------

set(TOOLS_SRC
	assist.c
	b64dump.c
	basespec.c
	binout.c
	bytespec.c
	checkfilename.c
	checksum32.c
	chrout.c
	clr32bitmap.c
	codelist.c
	codename.c
	dataspec.c
	decdecode.c
	decout.c
	decstring.c
	efreopen.c
	emalloc.c
	endian.c
	error.c
	extra.c
	fdchecksum32.c
	getoptv.c
	hexdecode.c
	hexdump.c
	hexencode.c
	hexload.c
	hexoffset.c
	hexout.c
	hexpeek.c
	hexstring.c
	hexview.c
	hexwrite.c
	ipv4spec.c
	ipv6spec.c
	lookup.c
	memdecr.c
	memencode.c
	memincr.c
	memout.c
	memswap.c
	output.c
	putoptv.c
	regview32.c
	reword.c
	set32bitmap.c
	strdecr.c
	strfbits.c
	strincr.c
	synonym.c
	todigit.c
	typelist.c
	typename.c
	uintspec.c
	version.c
	)

if (WIN32)
	set(TOOLS_SRC ${TOOLS_SRC} __bswap.c gettimeofday.c)
endif (WIN32)

# ====================================================================
#
# --------------------------------------------------------------------

add_library(tools ${TOOLS_SRC})

