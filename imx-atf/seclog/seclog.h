#ifndef __SECLOG_H__
#define __SECLOG_H__

// SMC Function ID (FID)s 
#define SECLOG_CONFIG   0xC2000010
#define SECLOG_LOG      0xC2000011
#define SECLOG_STORE    0xC2000012
#define SECLOG_READ     0xC2000013
#define SECLOG_DELETE   0xC2000014

// x1: the base address of a log buffer
// x2: the size of the buffer
int seclog_config_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// x1: the address of a log entry
// x2: the size of the log entry
int seclog_log_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// store a log-entry buffer in storage
// x1: buffer index
int seclog_store_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// x1: block index
// x2: the address of a buffer
// x3: the size of the buffer
int seclog_read_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

// delete storage
// TODO: authentication?
// TODO: specify the block rage to delete?
int seclog_delete_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3);

void seclog_finalize();

#endif /* __SECLOG_H__ */
