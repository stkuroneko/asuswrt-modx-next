/* 
   Unix SMB/CIFS implementation.
   test suite for winreg ndr operations

   Copyright (C) Jelmer Vernooij 2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_winreg.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "torture/ndr/proto.h"

static const uint8_t closekey_in_data[] = { 
        0x00, 0x00, 0x00, 0x00, 0x1d, 0xd8, 0xd7, 0xaa, 0x8d, 0x6c, 0x3f, 0x48, 
        0xa7, 0x1e, 0x02, 0x6a, 0x47, 0xf6, 0x7b, 0xae
};

static bool closekey_in_check(struct torture_context *tctx, 
								  struct winreg_CloseKey *ck)
{
	torture_assert(tctx, ck->in.handle != NULL, "handle invalid");
	torture_assert_int_equal(tctx, ck->in.handle->handle_type, 0, "handle type");
	return true;
}

const static uint8_t closekey_out_data[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool closekey_out_check(struct torture_context *tctx, 
							   struct winreg_CloseKey *ck)
{
	torture_assert_int_equal(tctx, ck->out.handle->handle_type, 0, "handle type");
	torture_assert_werr_ok(tctx, ck->out.result, "return code");
	return true;
}

static const uint8_t OpenHKLM_In[] = {
  0x01, 0x00, 0x00, 0x00, 0xe0, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

static bool openhklm_in_check(struct torture_context *tctx, 
								  struct winreg_OpenHKLM *r)
{
	torture_assert(tctx, r->in.system_name != NULL, "system name pointer");
	torture_assert_int_equal(tctx, *r->in.system_name, 34016, "system name");
	torture_assert_int_equal(tctx, r->in.access_mask, 0x02000000, "access mask");
	return true;
}

static const uint8_t openhklm_out_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3, 0x00, 0x00, 0x00, 0x00
};

static bool openhklm_out_check(struct torture_context *tctx, 
								  struct winreg_OpenHKLM *r)
{
	torture_assert(tctx, r->out.handle != NULL, "handle pointer");
	torture_assert_int_equal(tctx, r->out.handle->handle_type, 0, "handle_type");
	torture_assert_werr_ok(tctx, r->out.result, "return code");
	return true;
}

static const uint8_t createkey_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3, 0x16, 0x00, 0x16, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0b, 0x00, 0x00, 0x00, 0x73, 0x00, 0x70, 0x00, 0x6f, 0x00, 0x74, 0x00,
  0x74, 0x00, 0x79, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x74, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static bool createkey_in_check(struct torture_context *tctx, 
								  struct winreg_CreateKey *r)
{
	torture_assert_str_equal(tctx, r->in.name.name, "spottyfoot", "name");
	torture_assert(tctx, r->in.keyclass.name == NULL, "keyclass");
	torture_assert_int_equal(tctx, r->in.options, 0, "option");
	torture_assert_int_equal(tctx, r->in.access_mask, 0x2000000, "access mask");
	torture_assert(tctx, r->in.secdesc == NULL, "secdesc");
	torture_assert(tctx, r->in.action_taken == NULL, "action_taken");

	return true;
}

static const uint8_t createkey_out_data[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x57, 0x00, 0x00, 0x00
};

static bool createkey_out_check(struct torture_context *tctx, 
								  struct winreg_CreateKey *r)
{
	torture_assert(tctx, GUID_all_zero(&r->out.new_handle->uuid), "new_handle");
	torture_assert(tctx, r->out.action_taken == NULL, "action_taken pointer");
	torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_PARAM, 
							  "return code");

	return true;
}

static const uint8_t enumvalue_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xae, 0x1a, 0xbd, 0xbe, 0xbb, 0x94, 0xce, 0x4e,
  0xba, 0xcf, 0x56, 0xeb, 0xe5, 0xb3, 0x6c, 0xa3, 0x05, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0xff, 0xff, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool enumvalue_in_check(struct torture_context *tctx, 
								  struct winreg_EnumValue *r)
{
	torture_assert_int_equal(tctx, r->in.enum_index, 5, "enum index");
	torture_assert(tctx, r->in.type != NULL, "type pointer");
	torture_assert_int_equal(tctx, *r->in.type, 0, "type");
	torture_assert_int_equal(tctx, *r->in.size, 65535, "size");
	torture_assert_int_equal(tctx, *r->in.length, 0, "length");
	torture_assert_int_equal(tctx, r->in.name->size, 512, "name size");
	torture_assert_int_equal(tctx, r->in.name->length, 0, "name length");

	return true;
}

static const uint8_t enumvalue_out_data[] = {
  0x12, 0x00, 0x00, 0x02, 0x28, 0x91, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x48, 0x00, 0x4f, 0x00,
  0x4d, 0x00, 0x45, 0x00, 0x50, 0x00, 0x41, 0x00, 0x54, 0x00, 0x48, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xd8, 0x8c, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xe0, 0x00, 0x0c, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4c, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x63, 0x00,
  0x75, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x73, 0x00,
  0x20, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x20, 0x00, 0x53, 0x00,
  0x65, 0x00, 0x74, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00,
  0x73, 0x00, 0x5c, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00,
  0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00,
  0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x00, 0x00, 0xf0, 0x8c, 0x07, 0x00,
  0x4c, 0x00, 0x00, 0x00, 0xf8, 0x8c, 0x07, 0x00, 0x4c, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static bool enumvalue_out_check(struct torture_context *tctx, 
								  struct winreg_EnumValue *r)
{
	torture_assert_int_equal(tctx, r->out.name->size, 512, "name size");
	torture_assert_int_equal(tctx, r->out.name->length, 18, "name length");
	torture_assert_str_equal(tctx, r->out.name->name, "HOMEPATH", "name");
	torture_assert_int_equal(tctx, *r->out.type, 1, "type");
	torture_assert_int_equal(tctx, *r->out.size, 76, "size");
	torture_assert_int_equal(tctx, *r->out.length, 76, "length");
	torture_assert_werr_ok(tctx, r->out.result, "return code");

	return true;
}

unsigned char enumvalue_in_data2[] = {
  0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xda, 0x45, 0x9c, 0xed, 0xe2, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x02, 0xcc, 0xf9, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xf9, 0x06, 0x00,
  0x39, 0xa6, 0x07, 0x00, 0x00, 0xc4, 0x04, 0x01, 0x00, 0x80, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0xf9, 0x06, 0x00,
  0x00, 0x80, 0x00, 0x00, 0x94, 0xf9, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t queryvalue_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xae, 0x1a, 0xbd, 0xbe, 0xbb, 0x94, 0xce, 0x4e,
  0xba, 0xcf, 0x56, 0xeb, 0xe5, 0xb3, 0x6c, 0xa3, 0x12, 0x00, 0x12, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x09, 0x00, 0x00, 0x00, 0x48, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x45, 0x00,
  0x50, 0x00, 0x41, 0x00, 0x54, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x03, 0x00, 0x00, 0x00, 0xff, 0x0f, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static bool queryvalue_in_check(struct torture_context *tctx, 
								  struct winreg_QueryValue *r)
{
	torture_assert_str_equal(tctx, r->in.value_name->name, "HOMEPATH", "name");
	torture_assert_int_equal(tctx, *r->in.type, 0, "type");
	torture_assert_int_equal(tctx, *r->in.data_size, 4095, "size");
	torture_assert_int_equal(tctx, *r->in.data_length, 0, "length");
	torture_assert(tctx, r->in.data == NULL, "data pointer");

	return true;
}

static const uint8_t queryvalue_out_data[] = {
  0xd8, 0xf5, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xe4, 0xf5, 0x0b, 0x00, 0x4c, 0x00, 0x00, 0x00, 0xec, 0xf5, 0x0b, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool queryvalue_out_check(struct torture_context *tctx, 
								  struct winreg_QueryValue *r)
{
	torture_assert_werr_ok(tctx, r->out.result, "return code");
	torture_assert_int_equal(tctx, *r->out.type, 1, "type");
	torture_assert(tctx, r->out.data == NULL, "data pointer");
	torture_assert_int_equal(tctx, *r->out.data_size, 76, "size");
	torture_assert_int_equal(tctx, *r->out.data_length, 0, "length");

	return true;
}

static const uint8_t querymultiplevalues_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xae, 0x1a, 0xbd, 0xbe, 0xbb, 0x94, 0xce, 0x4e,
  0xba, 0xcf, 0x56, 0xeb, 0xe5, 0xb3, 0x6c, 0xa3, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x12, 0x00, 0x12, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x48, 0x00, 0x4f, 0x00,
  0x4d, 0x00, 0x45, 0x00, 0x50, 0x00, 0x41, 0x00, 0x54, 0x00, 0x48, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00
};

static bool querymultiplevalues_in_check(struct torture_context *tctx, 
					 struct winreg_QueryMultipleValues *r)
{
	torture_assert_int_equal(tctx, r->in.num_values, 1, "num values");
	torture_assert_str_equal(tctx, r->in.values_in[0].ve_valuename->name, "HOMEPATH", "name");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valuename->length, 18, "name len");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valuename->size, 18, "name size");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valuelen, 0, "length");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valueptr, 0, "ve_valueptr");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_type, 0, "type");
	torture_assert_int_equal(tctx, *r->in.buffer_size, 32, "buffer size");

	return true;
}

static const uint8_t querymultiplevalues_out_data[] = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xd8, 0x8c, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x12, 0x00, 0x38, 0x87, 0x07, 0x00,
  0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
  0x48, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x45, 0x00, 0x50, 0x00, 0x41, 0x00,
  0x54, 0x00, 0x48, 0x00, 0xc8, 0x95, 0x08, 0x00, 0x4c, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x4c, 0x4d, 0x45, 0x4d, 0xc8, 0x95, 0x08, 0x00,
  0x50, 0x87, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00,
  0x00, 0x01, 0x0c, 0x00, 0x50, 0x95, 0x08, 0x00, 0x48, 0x96, 0x08, 0x00,
  0xdc, 0x00, 0x00, 0x00, 0xc0, 0x83, 0x00, 0x01, 0x0d, 0xf0, 0xff, 0xff,
  0x4c, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00
};

static bool querymultiplevalues_out_check(struct torture_context *tctx, 
					  struct winreg_QueryMultipleValues *r)
{
	torture_assert_str_equal(tctx, r->out.values_out[0].ve_valuename->name, "HOMEPATH", "name");
	torture_assert_int_equal(tctx, r->out.values_out[0].ve_type, 0, "type");
	torture_assert_int_equal(tctx, r->out.values_out[0].ve_valuelen, 0, "length");
	/* FIXME: r->out.buffer */
	torture_assert_int_equal(tctx, *r->out.buffer_size, 76, "buffer size");
	torture_assert_werr_equal(tctx, r->out.result, WERR_MORE_DATA, "return code");

	return true;
}

const uint8_t querymultiplevalues2_in_data[] = {
	0x00, 0x00, 0x00, 0x00, 0x98, 0xe4, 0xdf, 0x3c, 0x70, 0xde, 0x69, 0x4a,
	0x90, 0xb4, 0x85, 0x36, 0x33, 0x79, 0x89, 0x32, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0a, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x54, 0x00, 0x45, 0x00,
	0x4d, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool querymultiplevalues2_in_check(struct torture_context *tctx,
					  struct winreg_QueryMultipleValues2 *r)
{
	torture_assert_int_equal(tctx, r->in.num_values, 1, "num values");
	torture_assert_str_equal(tctx, r->in.values_in[0].ve_valuename->name, "TEMP", "name");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valuename->length, 10, "name len");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valuename->size, 10, "name size");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valuelen, 0, "length");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_valueptr, 0,  "ve_valueptr");
	torture_assert_int_equal(tctx, r->in.values_in[0].ve_type, 0, "type");
	torture_assert_int_equal(tctx, *r->in.offered, 0, "buffer size");

	return true;
}

const uint8_t querymultiplevalues2_out_data[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x54, 0x00, 0x45, 0x00, 0x4d, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x42, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00
};

static bool querymultiplevalues2_out_check(struct torture_context *tctx,
					   struct winreg_QueryMultipleValues2 *r)
{
	return true;
}

static const uint8_t flushkey_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3
};

static bool flushkey_in_check(struct torture_context *tctx, 
							   struct winreg_FlushKey *r)
{
	torture_assert_int_equal(tctx, r->in.handle->handle_type, 0, "handle type");
	return true;
}

static const uint8_t flushkey_out_data[] = {
  0x00, 0x00, 0x00, 0x00
};

static bool flushkey_out_check(struct torture_context *tctx, 
							   struct winreg_FlushKey *r)
{
	torture_assert_werr_ok(tctx, r->out.result, "return code");
	return true;
}


static const uint8_t openkey_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3, 0x16, 0x00, 0x16, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0b, 0x00, 0x00, 0x00, 0x73, 0x00, 0x70, 0x00, 0x6f, 0x00, 0x74, 0x00,
  0x74, 0x00, 0x79, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x74, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

static bool openkey_in_check(struct torture_context *tctx, struct winreg_OpenKey *r)
{
	torture_assert_int_equal(tctx, r->in.options, 0, "unknown");
	torture_assert_int_equal(tctx, r->in.access_mask, 0x02000000, "access mask");
	torture_assert_str_equal(tctx, r->in.keyname.name, "spottyfoot", "keyname");
	/* FIXME: parent handle */
	return true;
}

static const uint8_t openkey_out_data[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};

static bool openkey_out_check(struct torture_context *tctx, struct winreg_OpenKey *r)
{
	torture_assert(tctx, GUID_all_zero(&r->out.handle->uuid), "handle");
	torture_assert_werr_equal(tctx, r->out.result, WERR_BADFILE, "return code");
	return true;
}

static const uint8_t deletekey_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3, 0x16, 0x00, 0x16, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0b, 0x00, 0x00, 0x00, 0x73, 0x00, 0x70, 0x00, 0x6f, 0x00, 0x74, 0x00,
  0x74, 0x00, 0x79, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x74, 0x00,
  0x00, 0x00
};

static bool deletekey_in_check(struct torture_context *tctx, struct winreg_DeleteKey *r)
{
	/* FIXME: Handle */
	torture_assert_str_equal(tctx, r->in.key.name, "spottyfoot", "key name");
	return true;
}

static const uint8_t deletekey_out_data[] = {
  0x02, 0x00, 0x00, 0x00
};

static bool deletekey_out_check(struct torture_context *tctx, struct winreg_DeleteKey *r)
{
	torture_assert_werr_equal(tctx, r->out.result, WERR_BADFILE, "return code");
	return true;
}

static const uint8_t getversion_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3
};

static bool getversion_in_check(struct torture_context *tctx, struct winreg_GetVersion *r)
{
	/* FIXME: Handle */
	return true;
}

static const uint8_t getversion_out_data[] = {
  0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool getversion_out_check(struct torture_context *tctx, struct winreg_GetVersion *r)
{
	torture_assert_int_equal(tctx, *r->out.version, 5, "version");
	torture_assert_werr_ok(tctx, r->out.result, "return code");
	return true;
}

static const uint8_t queryinfokey_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static bool queryinfokey_in_check(struct torture_context *tctx, struct winreg_QueryInfoKey *r)
{
	/* FIXME: Handle */
	torture_assert(tctx, r->in.classname->name == NULL, "class in");
	return true;
}

static const uint8_t queryinfokey_out_data[] = {
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
  0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00,
  0x10, 0x48, 0x02, 0x3a, 0xcf, 0xfd, 0xc4, 0x01, 0x00, 0x00, 0x00, 0x00
};

static bool queryinfokey_out_check(struct torture_context *tctx, struct winreg_QueryInfoKey *r)
{
	torture_assert(tctx, r->out.classname != NULL, "class out");
	torture_assert(tctx, r->out.classname->name != NULL, "class out name");
	torture_assert_str_equal(tctx, r->out.classname->name, "", "class out name");
	torture_assert_int_equal(tctx, *r->out.num_subkeys, 0, "num subkeys");
	torture_assert_int_equal(tctx, *r->out.max_subkeylen, 0, "subkey length");
	torture_assert_int_equal(tctx, *r->out.max_classlen, 140, "subkey size");
	torture_assert_werr_ok(tctx, r->out.result, "return code");
	return true;
}

static const uint8_t notifychangekeyvalue_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xb2, 0x64, 0xbc, 0xb3, 0x7f, 0x90, 0x29, 0x4a,
  0xb4, 0xb3, 0x91, 0xe7, 0xe4, 0x4a, 0x58, 0xe3, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static bool notifychangekeyvalue_in_check(struct torture_context *tctx, struct winreg_NotifyChangeKeyValue *r)
{
	torture_assert_int_equal(tctx, r->in.watch_subtree, 1, "watch subtree");
	torture_assert_int_equal(tctx, r->in.notify_filter, 0, "notify filter");
	torture_assert_int_equal(tctx, r->in.unknown, 0, "unknown");
	torture_assert(tctx, r->in.string1.name == NULL, "string1");
	torture_assert(tctx, r->in.string2.name == NULL, "string2");
	torture_assert_int_equal(tctx, r->in.unknown2, 0, "unknown2");
	return true;
}

static const uint8_t notifychangekeyvalue_out_data[] = {
  0x57, 0x00, 0x00, 0x00
};

static bool notifychangekeyvalue_out_check(struct torture_context *tctx, struct winreg_NotifyChangeKeyValue *r)
{
	torture_assert_werr_equal(tctx, r->out.result, WERR_INVALID_PARAM, "notify change key value");
	return true;
}

static const uint8_t getkeysecurity_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0xbd, 0xaa, 0xf6, 0x59, 0xc1, 0x82, 0x1f, 0x4d,
  0x84, 0xa9, 0xdd, 0xae, 0x60, 0x77, 0x1e, 0x45, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool getkeysecurity_in_check(struct torture_context *tctx, 
				    struct winreg_GetKeySecurity *r)
{
	/* FIXME: Handle */
	torture_assert_int_equal(tctx, r->in.sec_info, 2, "sec info");
	torture_assert_int_equal(tctx, r->in.sd->size, 65536, "sd size");
	torture_assert_int_equal(tctx, r->in.sd->len, 0, "sd len");
	torture_assert(tctx, r->in.sd->data == NULL, "sd data");
	return true;
}

static const uint8_t getkeysecurity_out_data[] = {
  0x08, 0x91, 0x08, 0x00, 0x14, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
  0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool getkeysecurity_out_check(struct torture_context *tctx, 
				     struct winreg_GetKeySecurity *r)
{
	torture_assert_int_equal(tctx, r->in.sd->size, 20, "sd size");
	torture_assert_int_equal(tctx, r->in.sd->len, 20, "sd len");
	torture_assert_werr_ok(tctx, r->out.result, "return code");
	return true;
}

static const uint8_t enumkey_in_data[] = {
  0x00, 0x00, 0x00, 0x00, 0x85, 0xb8, 0x41, 0xb0, 0x17, 0xe4, 0x28, 0x45,
  0x8a, 0x69, 0xbf, 0x40, 0x79, 0x82, 0x8b, 0xcb, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x14, 0x04, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0x7f
};

static bool enumkey_in_check(struct torture_context *tctx, struct winreg_EnumKey *r)
{
	torture_assert_int_equal(tctx, r->in.enum_index, 0, "enum index");
	torture_assert_int_equal(tctx, r->in.name->size, 1044, "name size");
	torture_assert_int_equal(tctx, r->in.name->length, 0, "name len");
	torture_assert(tctx, r->in.keyclass != NULL, "keyclass pointer");
	torture_assert(tctx, r->in.keyclass->name == NULL, "keyclass");
	torture_assert(tctx, r->in.last_changed_time != NULL, "last_changed_time != NULL");
	return true;
}

static const uint8_t enumkey_out_data[] = {
  0x08, 0x00, 0x14, 0x04, 0x18, 0xe8, 0x07, 0x00, 0x0a, 0x02, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x53, 0x00, 0x41, 0x00,
  0x4d, 0x00, 0x00, 0x00, 0xd0, 0x62, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xdc, 0x62, 0x07, 0x00, 0x50, 0x67, 0xd0, 0x8b,
  0x16, 0x06, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x00
};

static bool enumkey_out_check(struct torture_context *tctx, struct winreg_EnumKey *r)
{
	torture_assert_int_equal(tctx, r->out.name->size, 1044, "name size");
	torture_assert_int_equal(tctx, r->out.name->length, 8, "name len");
	torture_assert(tctx, r->out.keyclass != NULL, "keyclass pointer");
	torture_assert(tctx, r->out.keyclass->name == NULL, "keyclass");
	torture_assert(tctx, r->out.last_changed_time != NULL, "last_changed_time pointer");
	/* FIXME: *last_changed_time */
	return true;
}

struct torture_suite *ndr_winreg_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "winreg");

	torture_suite_add_ndr_pull_fn_test(suite, winreg_CloseKey, closekey_in_data, NDR_IN, closekey_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_CloseKey, closekey_out_data, NDR_OUT, closekey_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_OpenHKLM, OpenHKLM_In, NDR_IN, openhklm_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_OpenHKLM, openhklm_out_data, NDR_OUT, openhklm_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_CreateKey, createkey_in_data, NDR_IN, createkey_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_CreateKey, createkey_out_data, NDR_OUT, createkey_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_EnumValue, enumvalue_in_data, NDR_IN, enumvalue_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_EnumValue, enumvalue_out_data, NDR_OUT, enumvalue_out_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_EnumValue, enumvalue_in_data2, NDR_IN, NULL);

	torture_suite_add_ndr_pull_fn_test(suite, winreg_QueryValue, queryvalue_in_data, NDR_IN, queryvalue_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_QueryValue, queryvalue_out_data, NDR_OUT, queryvalue_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_QueryMultipleValues, querymultiplevalues_in_data, NDR_IN, querymultiplevalues_in_check );
	torture_suite_add_ndr_pull_io_test(suite, winreg_QueryMultipleValues, querymultiplevalues_in_data, querymultiplevalues_out_data, querymultiplevalues_out_check);

	torture_suite_add_ndr_pull_fn_test(suite, winreg_QueryMultipleValues2, querymultiplevalues2_in_data, NDR_IN, querymultiplevalues2_in_check );
	torture_suite_add_ndr_pull_io_test(suite, winreg_QueryMultipleValues2, querymultiplevalues2_in_data, querymultiplevalues2_out_data, querymultiplevalues2_out_check);

	torture_suite_add_ndr_pull_fn_test(suite, winreg_FlushKey, flushkey_in_data, NDR_IN, flushkey_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_FlushKey, flushkey_out_data, NDR_OUT, flushkey_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_OpenKey, openkey_in_data, NDR_IN, openkey_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_OpenKey, openkey_out_data, NDR_OUT, openkey_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_DeleteKey, deletekey_in_data, NDR_IN, deletekey_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_DeleteKey, deletekey_out_data, NDR_OUT, deletekey_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_GetVersion, getversion_in_data, NDR_IN, getversion_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_GetVersion, getversion_out_data, NDR_OUT, getversion_out_check );

	torture_suite_add_ndr_pull_fn_test(suite, winreg_QueryInfoKey, queryinfokey_in_data, NDR_IN, queryinfokey_in_check );
	/*torture_suite_add_ndr_pull_fn_test(suite, winreg_QueryInfoKey, queryinfokey_out_data, NDR_OUT, queryinfokey_out_check );*/

	torture_suite_add_ndr_pull_fn_test(suite, winreg_NotifyChangeKeyValue, notifychangekeyvalue_in_data, NDR_IN, notifychangekeyvalue_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_NotifyChangeKeyValue, notifychangekeyvalue_out_data, NDR_OUT, notifychangekeyvalue_out_check );

	/*torture_suite_add_ndr_pull_fn_test(suite, winreg_GetKeySecurity, getkeysecurity_in_data, NDR_IN, getkeysecurity_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_GetKeySecurity, getkeysecurity_out_data, NDR_OUT, getkeysecurity_out_check );*/

	torture_suite_add_ndr_pull_fn_test(suite, winreg_EnumKey, enumkey_in_data, NDR_IN, enumkey_in_check );
	torture_suite_add_ndr_pull_fn_test(suite, winreg_EnumKey, enumkey_out_data, NDR_OUT, enumkey_out_check );

	return suite;
}
