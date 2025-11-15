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

#include "secret.h" /* For SECRET_SIZE */


/*
 * Memory segment for safe copy operations. 0 is the data segment.
 */
#define SAFEPK_D 0

/* DS label for storing driver state for Live Update */
#define DS_SECRET_STATE_LABEL "secret_keeper_state"

/* Driver name string */
#define SECRET_KEEPER_NAME "secret"

/*
 * Global state structure for /dev/Secret.
 * This structure holds all the information necessary for the driver's logic
 * and must be saved/restored during Live Update.
 */
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
	.cdr_cleanup 	= NULL, /* Not needed */
	.cdr_alarm 	 = NULL, /* Not needed */
	.cdr_cancel 	= NULL, /* Not needed */
	.cdr_select 	= NULL, /* Not needed */
	.cdr_other 	 = NULL, /* Not needed */
};

/*
 * Resets the global state to an "empty" secret.
 */
static void secret_init_state(void)
{
	/* Mark the secret as not owned */
	secret_global_state.owner_uid = INVAL_UID;
	/* Secret has no content */
	secret_global_state.secret_len = 0;
	/* No file descriptors are open */
	secret_global_state.open_count = 0;
	/* No read has occurred since the last write/reset */
	secret_global_state.read_opened = 0;
	/* Data buffer contents are not strictly necessary to clear, but safe */
	/* memset(secret_global_state.data, 0, SECRET_SIZE); */
}

/*
 * SEF Callback for fresh initialization or after live update/restart.
 */
static int secret_init_fresh(int type, sef_init_info_t *info)
{
	size_t len = sizeof(secret_global_state);
	int r;

	if (type == SEF_INIT_FRESH) {
		/* Initialize the state structure for a fresh start */
		secret_init_state();
	} else { /* SEF_INIT_LU or SEF_INIT_RESTART */
		/* Retrieve the state from the Data Store (DS) */
		r = ds_retrieve_mem(DS_SECRET_STATE_LABEL, 
			(char *)&secret_global_state, &len);
		if (r == OK) {
			/* State successfully restored */
			printf("%s: State restored from DS.\n", SECRET_KEEPER_NAME);
			/* open_count must be zero after LU/restart */
			secret_global_state.open_count = 0;
		} else {
			/* If retrieval fails, start fresh */
			printf("%s: DS retrieval failed (%d). Starting fresh.\n", 
				SECRET_KEEPER_NAME, r);
			secret_init_state();
		}
		/* Delete the state from DS after retrieval */
		ds_delete_mem(DS_SECRET_STATE_LABEL);
	}

	/* Announce we are ready */
	chardriver_announce();
	return(OK);
}

/*
 * SEF Callback for saving state before a live update.
 */
static int secret_save_state(int state)
{
	int r;
	
	/* Save the entire global state structure to the Data Store (DS) */
	r = ds_publish_mem(DS_SECRET_STATE_LABEL, &secret_global_state, 
						sizeof(secret_global_state), DSF_OVERWRITE);
	
	if (r != OK) {
		printf("%s: ds_publish_mem failed: %d\n", SECRET_KEEPER_NAME, r);
	} else {
		printf("%s: State published to DS.\n", SECRET_KEEPER_NAME);
	}
	
	return(r);
}

/*
 * Open callback. Handles permission and ownership logic.
 */
static int secret_open(message *m_ptr)
{
	struct ucred ucred;
	endpoint_t caller_endpt = m_ptr->m_source;
	/* Open flags re-mapped to R_BIT/W_BIT are in m_ptr->COUNT */
	int flags = m_ptr->COUNT; 
	int r;

	/* Get the credentials of the calling process */
	r = getnucred(caller_endpt, &ucred);
	if (r != OK) {
		printf("%s: Failed to get credentials for endpoint %d: %d\n", 
				SECRET_KEEPER_NAME, caller_endpt, r);
		return EGENERIC;
	}

	/* 1. /dev/Secret may not be opened for read-write access (EACCES) */
	if ((flags & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
		return EACCES;
	}

	/* State check */
	if (secret_global_state.owner_uid == INVAL_UID) {
		/* Secret is EMPTY (Owned by nobody) */
		if (flags & (R_BIT | W_BIT)) {
			/* Any process may open for R or W. Owner becomes the opener. */
			secret_global_state.owner_uid = ucred.uid;
			secret_global_state.open_count++;
			return OK;
		}
	} else {
		/* Secret is FULL (Owned by somebody) */

		/* 2. Attempts to open a full secret for writing result in ENOSPC */
		if (flags & W_BIT) {
			return ENOSPC;
		}

		/* 3. Check for read access (R_BIT) */
		if (flags & R_BIT) {
			if (ucred.uid == secret_global_state.owner_uid) {
				/* Owner match, allow read */
				secret_global_state.read_opened = 1;
				secret_global_state.open_count++;
				return OK;
			} else {
	/* Attempts to read a secret belonging to another user result in EACCES */
				return EACCES;
			}
		}
	}
	
/* Catch-all for non R/W opens (O_NONBLOCK only, or just using open/close) */
	secret_global_state.open_count++;
	return OK;
}

/*
 * Close callback. Resets the secret state if conditions are met.
 */
static int secret_close(message *m_ptr)
{
	/* UNUSED(m_ptr); is now removed as it's handled by chardriver.h logic */

	if (secret_global_state.open_count > 0) {
		secret_global_state.open_count--;
	}

	/*
	 * When the last file descriptor is closed after any read file descriptor
	 * has been opened, /dev/Secret reverts to being empty.
	 */
	if (secret_global_state.open_count == 0 && \
		secret_global_state.read_opened == 1) {
		secret_init_state();
	}

	return OK;
}

/*
 * Prepare callback. Reports device geometry 
 * (always SECRET_SIZE for this device).
 */
static struct device *secret_prepare(dev_t device)
{
	static struct device dev;
	/* UNUSED(device); is now removed as it's handled by chardriver.h logic */

	/* For a single device, the size is the max secret size. */
	dev.dv_base = make64(0, 0);
	dev.dv_size = make64(0, SECRET_SIZE);

	/* Internal position state is no longer used for character device I/O. */

	return &dev;
}

/*
 * Transfer callback. Handles safe copy in (write) and out (read).
 */
static int secret_transfer(endpoint_t endpt, int opcode, u64_t position,
	iovec_t *iov, unsigned int nr_req, endpoint_t user_endpt)
{
	size_t bytes_left, bytes_to_transfer;
	int r;
	struct ucred ucred;
	
	/* UNUSED(endpt); removed */
	
	/* We expect a single request vector for character device */
	if (nr_req != 1) return EGENERIC; 

	/* Get the credentials of the I/O initiating process */
	r = getnucred(user_endpt, &ucred);
	if (r != OK || ucred.uid != secret_global_state.owner_uid) {
		/* The owner check should have happened in open, but be safe */
		return EACCES; 
	}
	
	/* The position argument is now used for reads (lseek support) */
	
	if (opcode == DEV_SCATTER_S) { /* Write (data from user to driver) */
		bytes_left = SECRET_SIZE - secret_global_state.secret_len;
		bytes_to_transfer = MIN(iov[0].iov_size, bytes_left);

		if (bytes_to_transfer == 0) {
			return ENOSPC; /* No space left in the secret buffer */
		}

/* Use iov[0].iov_addr (a pointer) to carry the grant ID (an integer) */
		r = sys_safecopyfrom(user_endpt, (cp_grant_id_t)iov[0].iov_addr, 0,
			(vir_bytes)(secret_global_state.data +\
				secret_global_state.secret_len), bytes_to_transfer, SAFEPK_D);

		if (r != OK) {
			return r;
		}
		
/* Update state: write is always appending to secret_len */
		secret_global_state.secret_len += bytes_to_transfer;

		return bytes_to_transfer;

	} else if (opcode == DEV_GATHER_S) { /* Read (data from driver to user) */
		size_t pos_offset = (size_t)position;
		
		if (pos_offset >= secret_global_state.secret_len) {
			return 0; /* EOF */
		}
		
		bytes_left = secret_global_state.secret_len - pos_offset;
		bytes_to_transfer = MIN(iov[0].iov_size, bytes_left);

	/* Use iov[0].iov_addr (a pointer) to carry the grant ID (an integer) */
		r = sys_safecopyto(user_endpt, (cp_grant_id_t)iov[0].iov_addr, 0,
			(vir_bytes)(secret_global_state.data + pos_offset),\
			bytes_to_transfer, SAFEPK_D);

		if (r != OK) {
			return r;
		}

		/* VFS handles position update, no need to update driver state */

		return bytes_to_transfer;

	} else {
		return EGENERIC; /* Unknown opcode */
	}
}

/*
 * Ioctl callback. Handles SSGRANT to change ownership.
 */
static int secret_ioctl(message *m_ptr)
{
	endpoint_t caller_endpt = m_ptr->m_source;
	int request = m_ptr->REQUEST;
	/* Cast IO_GRANT to cp_grant_id_t to avoid pointer-to-integer warning */
	cp_grant_id_t grant_id = (cp_grant_id_t)m_ptr->IO_GRANT;
	struct ucred ucred;
	uid_t grantee_uid;
	int r;
	
	/* Get the credentials of the calling process */
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
		r = sys_safecopyfrom(caller_endpt, grant_id, 0, \
			(vir_bytes)&grantee_uid, sizeof(grantee_uid), SAFEPK_D);

		if (r != OK) {
			printf("%s: sys_safecopyfrom failed for SSGRANT: %d\n",\
				SECRET_KEEPER_NAME, r);
			return EFAULT;
		}

		/* Change ownership */
		secret_global_state.owner_uid = grantee_uid;
		return OK;

	} else {
		/* Any ioctl(2) requests other than SSGRANT get a ENOTTY response */
		return ENOTTY;
	}
}


int main(void)
{
	/*
	 * SEF initialization must be done first.
	 * We set callbacks for both initialization and state saving/restoring
	 * for Live Update (LU).
	 */
	sef_setcb_init_fresh(secret_init_fresh);
	sef_setcb_init_lu(secret_init_fresh); /* Use same init for LU restore */
	sef_setcb_init_restart(secret_init_fresh);
	sef_setcb_lu_state_save(secret_save_state);

	/* Standard SEF startup */
	sef_startup();

	/* Start the main character driver task loop */
	chardriver_task(&secret_driver, CHARDRIVER_SYNC);

	return(OK);
}