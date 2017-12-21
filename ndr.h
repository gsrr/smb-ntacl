typedef void TALLOC_CTX;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned long long int uint64_t;
typedef uint64_t NTTIME;

#define NDR_SCALARS    0x100
#define NDR_BUFFERS    0x200

#define LIBNDR_FLAG_BIGENDIAN  (1<<0)
#define LIBNDR_FLAG_NOALIGN    (1<<1)
#define LIBNDR_FLAG_STR_ASCII       (1<<2)
#define LIBNDR_FLAG_STR_LEN4        (1<<3)
#define LIBNDR_FLAG_STR_SIZE4       (1<<4)
#define LIBNDR_FLAG_STR_NOTERM      (1<<5)
#define LIBNDR_FLAG_STR_NULLTERM    (1<<6)
#define LIBNDR_FLAG_STR_SIZE2       (1<<7)
#define LIBNDR_FLAG_STR_BYTESIZE    (1<<8)
#define LIBNDR_FLAG_STR_CONFORMANT  (1<<10)
#define LIBNDR_FLAG_STR_CHARLEN     (1<<11)
#define LIBNDR_FLAG_STR_UTF8        (1<<12)
#define LIBNDR_FLAG_STR_RAW8        (1<<13)
#define LIBNDR_FLAG_INCOMPLETE_BUFFER (1<<16)
#define LIBNDR_FLAG_NO_RELATIVE_REVERSE (1<<18)
#define LIBNDR_FLAG_RELATIVE_REVERSE    (1<<19)
#define LIBNDR_FLAG_REF_ALLOC    (1<<20)
#define LIBNDR_FLAG_REMAINING    (1<<21)
#define LIBNDR_FLAG_ALIGN2       (1<<22)
#define LIBNDR_FLAG_ALIGN4       (1<<23)
#define LIBNDR_FLAG_ALIGN8       (1<<24)
#define LIBNDR_FLAG_LITTLE_ENDIAN (1<<27)
#define LIBNDR_FLAG_PAD_CHECK     (1<<28)
#define LIBNDR_FLAG_NDR64         (1<<29)
#define LIBNDR_STRING_FLAGS     (0x7FFC)



#define LIBNDR_ALIGN_FLAGS ( 0        | \
        LIBNDR_FLAG_NOALIGN   | \
        LIBNDR_FLAG_REMAINING | \
        LIBNDR_FLAG_ALIGN2    | \
        LIBNDR_FLAG_ALIGN4    | \
        LIBNDR_FLAG_ALIGN8    | \
        0)


struct ndr_token_list {
	struct ndr_token_list *next, *prev;
	const void *key;
	uint32_t value;
};

/* this is the base structure passed to routines that 
   parse MSRPC formatted data 

   note that in Samba4 we use separate routines and structures for
   MSRPC marshalling and unmarshalling. Also note that these routines
   are being kept deliberately very simple, and are not tied to a
   particular transport
*/
struct ndr_pull {
	uint32_t flags; /* LIBNDR_FLAG_* */
	uint8_t *data;
	uint32_t data_size;
	uint32_t offset;

	uint32_t relative_highest_offset;
	uint32_t relative_base_offset;
	uint32_t relative_rap_convert;
	struct ndr_token_list *relative_base_list;

	struct ndr_token_list *relative_list;
	struct ndr_token_list *array_size_list;
	struct ndr_token_list *array_length_list;
	struct ndr_token_list *switch_list;

	TALLOC_CTX *current_mem_ctx;

	/* this is used to ensure we generate unique reference IDs
	   between request and reply */
	uint32_t ptr_count;
};

/* structure passed to functions that generate NDR formatted data */
struct ndr_push {
	uint32_t flags; /* LIBNDR_FLAG_* */
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;

	uint32_t relative_base_offset;
	uint32_t relative_end_offset;
	struct ndr_token_list *relative_base_list;

	struct ndr_token_list *switch_list;
	struct ndr_token_list *relative_list;
	struct ndr_token_list *relative_begin_list;
	struct ndr_token_list *nbt_string_list;
	struct ndr_token_list *dns_string_list;
	struct ndr_token_list *full_ptr_list;

	/* this is used to ensure we generate unique reference IDs */
	uint32_t ptr_count;
};


enum ndr_err_code {
	NDR_ERR_SUCCESS = 0,
	NDR_ERR_ARRAY_SIZE,
	NDR_ERR_BAD_SWITCH,
	NDR_ERR_OFFSET,
	NDR_ERR_RELATIVE,
	NDR_ERR_CHARCNV,
	NDR_ERR_LENGTH,
	NDR_ERR_SUBCONTEXT,
	NDR_ERR_COMPRESSION,
	NDR_ERR_STRING,
	NDR_ERR_VALIDATE,
	NDR_ERR_BUFSIZE,
	NDR_ERR_ALLOC,
	NDR_ERR_RANGE,
	NDR_ERR_TOKEN,
	NDR_ERR_IPV4ADDRESS,
	NDR_ERR_IPV6ADDRESS,
	NDR_ERR_INVALID_POINTER,
	NDR_ERR_UNREAD_BYTES,
	NDR_ERR_NDR64,
	NDR_ERR_FLAGS,
	NDR_ERR_INCOMPLETE_BUFFER
};
enum ndr_compression_alg {
	NDR_COMPRESSION_MSZIP	= 2,
	NDR_COMPRESSION_XPRESS	= 3
};

