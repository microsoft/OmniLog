#ifndef __OMNILOG_H__
#define __OMNILOG_H__

// SMC Function ID (FID)s 
#define OMNILOG_CONFIG   0xC2000010
#define OMNILOG_LOG      0xC2000011
#define OMNILOG_STORE    0xC2000012
#define OMNILOG_READ     0xC2000013
#define OMNILOG_DELETE   0xC2000014

// x1: the base address of a log buffer
// x2: the size of the buffer
int omnilog_config_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// x1: the address of a log entry
// x2: the size of the log entry
int omnilog_log_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// store a log-entry buffer in storage
// x1: buffer index
int omnilog_store_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// x1: block index
// x2: the address of a buffer
// x3: the size of the buffer
int omnilog_read_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// delete storage
// TODO: authentication?
// TODO: specify the block rage to delete?
int omnilog_delete_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

void omnilog_finalize();

#endif /* __OMNILOG_H__ */
