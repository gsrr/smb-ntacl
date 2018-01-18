#include "ndr.h"

#define XATTR_DOSATTRIB_NAME	( "user.DosAttrib" )
#define XATTR_DOSATTRIB_ESTIMATED_SIZE	( 64 )
#define XATTR_DOSEAS_NAME	( "user.DosEAs" )
#define XATTR_DOSSTREAMS_NAME	( "user.DosStreams" )
#define XATTR_STREAM_FLAG_INTERNAL	( 0x00000001 )
#define XATTR_DOSSTREAM_PREFIX	( "user.DosStream." )
#define XATTR_MAX_STREAM_SIZE	( 0x4000 )
#define XATTR_MAX_STREAM_SIZE_TDB	( 0x100000 )
#define XATTR_NTACL_NAME	( "security.NTACL" )
#define XATTR_SD_HASH_SIZE	( 64 )
#define XATTR_SD_HASH_TYPE_NONE	( 0x0 )
#define XATTR_SD_HASH_TYPE_SHA256	( 0x1 )

struct security_descriptor_hash_v2 {
	struct security_descriptor *sd;/* [unique] */
	uint8_t hash[16];
}/* [public] */;

struct security_descriptor_hash_v3 {
	struct security_descriptor *sd;/* [unique] */
	uint16_t hash_type;
	uint8_t hash[64];
}/* [public] */;

struct security_descriptor_hash_v4 {
	struct security_descriptor *sd;/* [unique] */
	uint16_t hash_type;
	uint8_t hash[64];
	const char * description;/* [flag(LIBNDR_FLAG_STR_UTF8|LIBNDR_FLAG_STR_NULLTERM)] */
	NTTIME time;
	uint8_t sys_acl_hash[64];
}/* [public] */;

union xattr_NTACL_Info {
	struct security_descriptor *sd;/* [case,unique] */
	struct security_descriptor_hash_v2 *sd_hs2;/* [case(2),unique] */
	struct security_descriptor_hash_v3 *sd_hs3;/* [case(3),unique] */
	struct security_descriptor_hash_v4 *sd_hs4;/* [case(4),unique] */
}/* [switch_type(uint16)] */;

struct xattr_NTACL {
	uint16_t version;
	union xattr_NTACL_Info info;/* [switch_is(version)] */
}/* [public] */;

