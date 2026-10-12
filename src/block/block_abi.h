#ifndef BLOCK_ABI_H
#define BLOCK_ABI_H

#include "types.h"

#define BLOCK_SECTOR_SIZE 512
#define BLOCK_SECTOR_MAX 4096
#define BLOCK_IO_SECTORS_MAX 1

#define BLOCK_OP_READ 1
#define BLOCK_OP_WRITE 2

#define BLOCK_FLAG_READ_ONLY 1u
#define BLOCK_FLAG_DEFER 2u

struct block_info {
    u32 sector_size;
    u32 sector_count;
    u32 flags;
    u32 generation;
};

struct block_io_request {
    u32 device_handle;
    u32 op;
    u32 lba;
    u32 sectors;
    u64 request_id;
    i32 status;
    u32 transferred;
    u8 data[BLOCK_SECTOR_SIZE];
};

#endif
