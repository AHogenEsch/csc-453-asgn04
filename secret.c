#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/const.h>
#include <sys/ioc_secret.h>
#include <sys/ucred.h>
#include <minix/syslib.h>
#include <sys/types.h>
#include <fcntl.h> /* For O_APPEND */

#include "secret.h" /* For SECRET_SIZE */

/* Memory segment for safe copy operations. 0 is the data segment. */
#define SAFEPK_D 0
/* DS label for storing driver state for Live Update */
#define DS_SECRET_STATE_LABEL "secret_keeper_state"
/* Driver name string */
#define SECRET_KEEPER_NAME "secret"
/* Name string for announcements */
#define SECRET_ANNOUNCE_NAME "The Secret Safe"

/* Global state structure for /dev/Secret. */
struct secret_state {
	/* UID of the current secret owner (INVAL_UID if empty) */
	uid_t owner_uid;
	/* Actual size of the secret data stored (0 if empty) */ 	
	size_t secret_len;
	/* Number of currently open file descriptors */ 	
	unsigned int open_count; 
	/* Flag: 1 if a file descriptor has been opened for reading */
	int read_opened;
	/* The secret data buffer */
	char data[SECRET_SIZE]; 	
};

/* The single global instance of our state */
static struct secret_state secret_global_state;

/* Function prototypes for driver callbacks */
static int secret_open(message *m_ptr);
static int secret_close(message *m_ptr);
static struct device *secret_prepare(dev_t device);
static int secret_transfer(endpoint_t endpt, int opcode, u64_t position,
	iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt);
static int secret_ioctl(message *m_ptr);

/* Function prototypes for SEF callbacks */
static int secret_init_fresh(int type, sef_init_info_t *info);
static int secret_save_state(int state);

/* Forward declaration of the character driver struct */
static struct chardriver secret_driver = {
	.cdr_open 	 = secret_open,
	.cdr_close 	 = secret_close,
	.cdr_ioctl 	 = secret_ioctl,
	.cdr_prepare 	= secret_prepare,
	.cdr_transfer 	= secret_transfer,
	.cdr_cleanup 	= NULL,
	.cdr_alarm 	 = NULL,
	.cdr_cancel 	= NULL,
	.cdr_select 	= NULL,
	.cdr_other 	 = NULL,
};

/* Resets the global state. */
static void secret_init_state(void)
{
	secret_global_state.owner_uid = INVAL_UID;
	secret_global_state.secret_len = 0;
	secret_global_state.open_count = 0;
	secret_global_state.read_opened = 0;
}

/* SEF Callback for fresh init or LU/restart. */
static int secret_init_fresh(int type, sef_init_info_t *info)
{
	size_t len = sizeof(secret_global_state);
	int r;

	if (type == SEF_INIT_FRESH) {
		secret_init_state();
		printf("%s ready for work.\n", SECRET_ANNOUNCE_NAME);
	} else { /* SEF_INIT_LU or SEF_INIT_RESTART */
		r = ds_retrieve_mem(DS_SECRET_STATE_LABEL, 
			(char *)&secret_global_state, &len);
		if (r == OK) {
			if (type == SEF_INIT_LU) {
				printf("%s: I'm a new version!\n",
					SECRET_ANNOUNCE_NAME);
			} else { /* SEF_INIT_RESTART */
				printf("%s: I've just been restarted!\n",
					SECRET_ANNOUNCE_NAME);
			}
			secret_global_state.open_count = 0;
		} else {
			printf("%s: DS retrieval failed (%d). Starting fresh.\n", 
				SECRET_KEEPER_NAME, r);
			secret_init_state();
		}
		ds_delete_mem(DS_SECRET_STATE_LABEL);
	}

	chardriver_announce();
	return(OK);
}

/* SEF Callback for saving state before a live update. */
static int secret_save_state(int state)
{
	int r;
	
	r = ds_publish_mem(DS_SECRET_STATE_LABEL, &secret_global_state, 
						sizeof(secret_global_state), 
						DSF_OVERWRITE);
	
	if (r != OK) {
		printf("%s: ds_publish_mem failed: %d\n", SECRET_KEEPER_NAME, r);
	} else {
		printf("%s: State published to DS.\n", SECRET_KEEPER_NAME);
	}
	
	return(r);
}

/* Open callback. */
static int secret_open(message *m_ptr)
{
	struct ucred ucred;
	endpoint_t caller_endpt = m_ptr->m_source;
	int flags = m_ptr->COUNT; 
	int r;

	r = getnucred(caller_endpt, &ucred);
	if (r != OK) {
		return EGENERIC;
	}

	/* 1. Cannot open for R/W access (EACCES) */
	if ((flags & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
		return EACCES;
	}
	
	/* 2. Cannot open with O_APPEND or O_TRUNC (EACCES) */
	if (flags & (O_APPEND | O_TRUNC)) {
		return EACCES;
	}

	if (secret_global_state.owner_uid == INVAL_UID) {
		/* Secret is EMPTY (Owned by nobody) */
		if (flags & (R_BIT | W_BIT)) {
			/* Owner becomes opener. */
			secret_global_state.owner_uid = ucred.uid;
		}
	} else {
		/* Secret is FULL (Owned by somebody) */

		/* 3. Open a full secret for writing results in ENOSPC */
		if (flags & W_BIT) {
			return ENOSPC;
		}

		/* 4. Check for read access (R_BIT) */
		if (flags & R_BIT) {
			if (ucred.uid != secret_global_state.owner_uid) {
				/* Non-owner attempts to read result in EACCES */
				return EACCES;
			} else {
				secret_global_state.read_opened = 1;
			}
		}
	}
	
	/* Final success path increment count and return OK */
	secret_global_state.open_count++;
	return OK;
}

/* Close callback. Resets the secret state if conditions are met. */
static int secret_close(message *m_ptr)
{
	if (secret_global_state.open_count > 0) {
		secret_global_state.open_count--;
	}

	/* Reset secret if last FD closed and a read was ever attempted. */
	if (secret_global_state.open_count == 0 && 
		secret_global_state.read_opened == 1) {
		secret_init_state();
	}

	return OK;
}

/* Prepare callback. Reports device geometry (always SECRET_SIZE). */
static struct device *secret_prepare(dev_t device)
{
	static struct device dev;
	/* UNUSED(device); */

	dev.dv_base = make64(0, 0);
	dev.dv_size = make64(0, SECRET_SIZE);

	return &dev;
}

/* Transfer callback. Handles safe copy in (write) and out (read). */
static int secret_transfer(endpoint_t endpt, int opcode, u64_t position,
	iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt)
{
	size_t bytes_left, bytes_to_transfer;
	int r;
	
	/* The VFS has already checked permissions via secret_open */
	if (nr_req != 1) return EGENERIC; 

	
	if (opcode == DEV_SCATTER_S) { /* Write (user to driver) */
		bytes_left = SECRET_SIZE - secret_global_state.secret_len;
		bytes_to_transfer = MIN(iov[0].iov_size, bytes_left);

		if (bytes_to_transfer == 0) {
			return ENOSPC;
		}

		/* iov[0].iov_addr holds the grant ID */
		r = sys_safecopyfrom(user_endpt, 
			(cp_grant_id_t)iov[0].iov_addr, 0, 
			(vir_bytes)(secret_global_state.data + 
				secret_global_state.secret_len), 
			bytes_to_transfer, SAFEPK_D);

		if (r != OK) {
			return r;
		}
		
		secret_global_state.secret_len += bytes_to_transfer;
		return bytes_to_transfer;

	} else if (opcode == DEV_GATHER_S) { /* Read (driver to user) */
		/* Position is ignored as /dev/Secret is not seekable */
		size_t pos_offset = 0; 
		
		if (pos_offset >= secret_global_state.secret_len) {
			return 0; /* EOF */
		}
		
		bytes_left = secret_global_state.secret_len - pos_offset;
		bytes_to_transfer = MIN(iov[0].iov_size, bytes_left);

		/* iov[0].iov_addr holds the grant ID */
		r = sys_safecopyto(user_endpt, 
			(cp_grant_id_t)iov[0].iov_addr, 0,
			(vir_bytes)(secret_global_state.data + pos_offset), 
			bytes_to_transfer, SAFEPK_D);

		if (r != OK) {
			return r;
		}

		return bytes_to_transfer;

	} else {
		return EGENERIC; /* Unknown opcode */
	}
}

/* Ioctl callback. Handles SSGRANT. */
static int secret_ioctl(message *m_ptr)
{
	endpoint_t caller_endpt = m_ptr->m_source;
	int request = m_ptr->REQUEST;
	cp_grant_id_t grant_id = (cp_grant_id_t)m_ptr->IO_GRANT;
	struct ucred ucred;
	uid_t grantee_uid;
	int r;
	
	r = getnucred(caller_endpt, &ucred);
	if (r != OK) {
		return r;
	}

	if (request == SSGRANT) {
		/* Check if the caller is the current owner */
		if (ucred.uid != secret_global_state.owner_uid) {
			return EACCES;
		}
		
		/* Copy the uid_t argument from the user's address space */
		r = sys_safecopyfrom(caller_endpt, grant_id, 0, 
			(vir_bytes)&grantee_uid, sizeof(grantee_uid),
			SAFEPK_D);

		if (r != OK) {
			printf("%s: sys_safecopyfrom failed for SSGRANT: %d\n",
				SECRET_KEEPER_NAME, r);
			return EFAULT;
		}

		/* Change ownership */
		secret_global_state.owner_uid = grantee_uid;
		return OK;

	} else {
		/* Non-SSGRANT ioctl requests get ENOTTY */
		return ENOTTY;
	}
}


int main(void)
{
	/* Set SEF callbacks for init and Live Update state saving. */
	sef_setcb_init_fresh(secret_init_fresh);
	sef_setcb_init_lu(secret_init_fresh); 
	sef_setcb_init_restart(secret_init_fresh);
	sef_setcb_lu_state_save(secret_save_state);

	sef_startup();

	/* Start the main character driver task loop */
	chardriver_task(&secret_driver, CHARDRIVER_SYNC);

	return(OK);
}