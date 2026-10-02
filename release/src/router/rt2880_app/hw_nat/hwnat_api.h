#ifndef __HW_NAT_API
#define __HW_NAT_API

int HwNatDumpEntry(unsigned int entry_num);
int HwNatBindEntry(unsigned int entry_num);
int HwNatUnBindEntry(unsigned int entry_num);
int HwNatInvalidEntry(unsigned int entry_num);
int HwNatAddEntry(struct hwnat_tuple *opt);
int HwNatDelEntry(struct hwnat_tuple *opt);
int HwNatGetAllEntries(struct hwnat_args *opt);
int HwNatDebug(unsigned int debug);

#endif
