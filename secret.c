#include <minix/drivers.h>
#include <minix/chardriver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <minix/const.h> // R_BIT and W_BIT
#include <sys/ioc_secret.h> // SSGRANT definition
#include <sys/ucred.h> // struct ucred
#include <minix/syslib.h> // sys_getnucred
#include <sys/types.h>
#include "secret.h"

#define MAX_SECRET_SIZE 8192

/* IOCTL commands for /dev/Secret */
/* Note: _IOW and _IO require <sys/ioctl.h> */
#define SSGRANT _IOW('S', 1, int) 
#define SSREVOKE _IO('S', 2)

/* Storage for the secret */
static char secret_data[MAX_SECRET_SIZE];
static size_t secret_len = 0;

/* Endpoint of the process currently owning the secret.
 * NONE is defined in <minix/endpoint.h>
 */
static endpoint_t secret_owner = NONE;

/*
 * Function Prototypes for the chardriver interface.
 * These must exactly match the required signatures.
 */
static int secret_open(dev_t minor, int access);
static int secret_close(dev_t minor);
static int secret_ioctl(dev_t minor, unsigned long request, cp_grant_id_t grant, int flags, endpoint_t endpt);
static int secret_transfer(dev_t minor, int operation, endpoint_t endpt, cp_grant_id_t grant, size_t pos, size_t chunk, int flags, struct device *dev);

/* The prepare function must match the type defined in the header. */
static struct device *nop_prepare(int device);
static int nop_prepare_end(struct device *dev);

/* Device table definition */
static struct chardriver secret_tab = {
    .cdr_prepare = nop_prepare,
    .cdr_end = nop_prepare_end,
    .cdr_open = secret_open,
    .cdr_close = secret_close,
    .cdr_ioctl = secret_ioctl,
    .cdr_transfer = secret_transfer,
    .cdr_cleanup = NULL,
};

/* --- General Helper Functions (from chardriver examples) --- */
static struct device *nop_prepare(int device)
{
    UNUSED(device);
    return NULL; /* No specific device state to prepare */
}

static int nop_prepare_end(struct device *dev)
{
    UNUSED(dev);
    return OK;
}

/* --- Driver Functions --- */

/* secret_open: Called when /dev/Secret is opened. */
static int secret_open(dev_t minor, int access)
{
    endpoint_t user_endpt;
    uid_t user_uid;

    UNUSED(minor);

    /* Get the endpoint and UID of the process calling open() */
    user_endpt = chardriver_get_caller_endpt();
    
    /* Get credentials (UID) of the caller */
    if (getnucred(user_endpt, &user_uid, NULL, NULL) != OK) {
        return EPERM;
    }

    /* Case 1: The secret is currently UNOWNED (empty) */
    if (secret_owner == NONE) {
        /* If opening for R/W access, deny it. */
        if ((access & (W_BIT | R_BIT)) == (W_BIT | R_BIT)) {
            return EACCES;
        }
        
        /* If opening for writing, the caller becomes the new owner. */
        if (access & W_BIT) {
            secret_owner = user_endpt;
            secret_len = 0; /* Clear previous data, prepare for new write */
            return OK;
        }
        
        /* If opening for reading, the caller also becomes the owner. */
        if (access & R_BIT) {
            secret_owner = user_endpt;
            return OK;
        }
    } 
    /* Case 2: The secret is OWNED */
    else {
        /* If the caller is the owner, allow R or W access (but not R/W) */
        if (user_endpt == secret_owner) {
            if ((access & (W_BIT | R_BIT)) == (W_BIT | R_BIT)) {
                return EACCES;
            }
            return OK;
        }
        /* If the caller is NOT the owner, check for grant access */
        else {
            /* If the caller is the ROOT user, they can read the secret. */
            if (user_uid == 0 && (access & R_BIT)) {
                /* Root can read, but does not become the owner. */
                return OK;
            }
            
            /* Otherwise, deny access. */
            return EACCES;
        }
    }
    
    return EACCES; /* Default deny */
}

/* secret_close: Called when /dev/Secret is closed. */
static int secret_close(dev_t minor)
{
    endpoint_t user_endpt = chardriver_get_caller_endpt();
    
    UNUSED(minor);

    /* Only the owner closing the device should release the secret.
     * Non-owners (like root readers) closing should not affect ownership.
     */
    if (user_endpt == secret_owner) {
        secret_owner = NONE;
        secret_len = 0;
    }

    return OK;
}

/* secret_transfer: Handles read and write operations. */
static int secret_transfer(dev_t minor, int operation, endpoint_t endpt, cp_grant_id_t grant, size_t pos, size_t chunk, int flags, struct device *dev)
{
    endpoint_t user_endpt = chardriver_get_caller_endpt();
    int r = EPERM; /* Default return: Permission denied */

    UNUSED(minor);
    UNUSED(flags);
    UNUSED(dev);

    /* The transfer must be performed by the owner (or root for reading) */
    if (user_endpt != secret_owner) {
        /* Check if caller is root (UID 0) and is reading */
        if (operation == DEV_READ) {
            uid_t user_uid;
            if (getnucred(user_endpt, &user_uid, NULL, NULL) == OK && user_uid == 0) {
                /* Root is allowed to read. Continue below. */
            } else {
                return EACCES;
            }
        } else {
            /* Non-owner (non-root) cannot write. */
            return EACCES;
        }
    }
    
    /* Ensure the operation is within the bounds of the secret buffer */
    if (pos >= MAX_SECRET_SIZE) {
        return 0; /* EOF */
    }
    
    if (pos + chunk > MAX_SECRET_SIZE) {
        chunk = MAX_SECRET_SIZE - pos;
    }

    if (operation == DEV_READ) {
        /* Only read up to the currently written secret length */
        if (pos + chunk > secret_len) {
            chunk = secret_len - pos;
        }
        
        if (chunk == 0) return 0; /* EOF if nothing to read */

        /* Copy data FROM driver TO user process */
        /* IMPORTANT: sys_safecopyto now takes 6 arguments (including flags=0) */
        r = sys_safecopyto(endpt, grant, 0, (vir_bytes) (secret_data + pos), chunk, 0);
        
        if (r != OK) {
            printf("SECRET: sys_safecopyto failed: %d\n", r);
            return r;
        }
        
        return chunk;

    } else if (operation == DEV_WRITE) {
        /* Only write up to the MAX_SECRET_SIZE (truncation/error handling) */
        if (pos + chunk > MAX_SECRET_SIZE) {
            /* The assignment suggests "No space left on device" (ENOSPC) */
            return ENOSPC;
        }

        /* Copy data FROM user process TO driver */
        /* IMPORTANT: sys_safecopyfrom now takes 6 arguments (including flags=0) */
        r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) (secret_data + pos), chunk, 0);

        if (r != OK) {
            printf("SECRET: sys_safecopyfrom failed: %d\n", r);
            return r;
        }

        /* Update the length of the secret if we're writing past the old end */
        if (pos + chunk > secret_len) {
            secret_len = pos + chunk;
        }
        
        return chunk;
    }

    return EIO; /* Invalid operation */
}

/* secret_ioctl: Handles SSGRANT and SSREVOKE commands. */
static int secret_ioctl(dev_t minor, unsigned long request, cp_grant_id_t grant, int flags, endpoint_t endpt)
{
    endpoint_t user_endpt = chardriver_get_caller_endpt();
    int target_uid;
    endpoint_t target_endpt;
    int r;

    UNUSED(minor);
    UNUSED(grant);
    UNUSED(flags);

    /* Only the owner is allowed to call ioctl */
    if (user_endpt != secret_owner) {
        return EPERM;
    }

    switch (request) {
        case SSGRANT: {
            /* SSGRANT: _IOW('S', 1, int) - Expects a UID from the user */
            
            /* Read the target UID from user space via the grant */
            /* The user must have created a grant for an integer (UID) */
            /* IMPORTANT: sys_safecopyfrom now takes 6 arguments (including flags=0) */
            r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes)&target_uid, sizeof(int), 0);
            
            if (r != OK) {
                printf("SECRET: sys_safecopyfrom failed in SSGRANT: %d\n", r);
                return EFAULT;
            }

            /* The driver is now responsible for setting the new owner.
             * Since the assignment says "grant access to another user (via UID)", 
             * we need to find the endpoint associated with that UID.
             * The new owner is simply the target_uid's process endpoint.
             */
            r = get_endpoint_by_uid(target_uid, &target_endpt);

            if (r != OK) {
                /* Target user is not running or invalid UID */
                return EINVAL;
            }
            
            /* The *target* user now becomes the owner. */
            secret_owner = target_endpt;
            
            return OK;
        }

        case SSREVOKE: {
            /* SSREVOKE: _IO('S', 2) - No arguments, revoke ownership */
            
            /* Revoking ownership means setting the owner back to NONE. */
            secret_owner = NONE;
            secret_len = 0; /* Clear the secret upon revocation */

            return OK;
        }

        default:
            return EINVAL;
    }
}

/* --- SEF Callbacks --- */

static int sef_cb_lu_state_save(int state, int flags)
{
    /* The chardriver framework passes different arguments here, 
     * but we use the standard SEF signature and UNUSED macros 
     * for forward compatibility and to avoid compiler warnings.
     */
    UNUSED(state);
    UNUSED(flags);

    /* Save the current secret_owner and secret_len to persist across upgrades */
    ds_publish_u32("secret_owner", secret_owner);
    ds_publish_u32("secret_len", (u32_t)secret_len);
    
    /* We don't save the secret_data itself, as it's typically ephemeral. 
     * If the secret needs to persist, it should be saved here.
     * For this assignment, we'll assume it's lost on upgrade/restart.
     */
    
    return OK;
}

static int sef_cb_init(int type, sef_init_info_t *info)
{
    UNUSED(info);
    
    /* On initialization (startup or restore after update) */
    if (type == SEF_INIT_FRESH) {
        /* Fresh start */
        secret_owner = NONE;
        secret_len = 0;
        printf("SECRET: Initialized as a new secret device.\n");
    } else if (type == SEF_INIT_LU) {
        /* Live Update: Restore state */
        u32_t owner_u32, len_u32;
        
        if (ds_retrieve_u32("secret_owner", &owner_u32) == OK && 
            ds_retrieve_u32("secret_len", &len_u32) == OK) {
            secret_owner = (endpoint_t)owner_u32;
            secret_len = (size_t)len_u32;
            printf("SECRET: State restored from live update. Owner: %d, Length: %zu\n", 
                secret_owner, secret_len);
        } else {
            /* Failed to restore, start fresh */
            secret_owner = NONE;
            secret_len = 0;
            printf("SECRET: Failed to restore state, starting fresh.\n");
        }
    }

    /* Announce we are up! */
    chardriver_announce();
    
    return OK;
}

static void sef_local_startup(void)
{
    /* Register for live update state saving */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);
    
    /* Register for signal handling */
    sef_setcb_signal_handler(sef_cb_signal_handler);
    
    /* Announce the device name */
    sef_dev_set_name("secret");
    
    /* Initialize the whole system */
    sef_init(sef_cb_init);
}

static int sef_cb_signal_handler(int signo)
{
    /* Only handle SIGTERM (shutdown) */
    if (signo != SIGTERM) return 0;
    
    /* Clean shutdown procedure */
    chardriver_terminate();
    
    return 1;
}

int test453main(void)
{
    /*
     * This is the entry point for the driver.
     * The chardriver_task function enters the main message loop.
     * CD_TASK is defined in <minix/chardriver.h>.
     */
    sef_local_startup();
    
    /* Run the main driver loop, listening for requests */
    chardriver_task(&secret_tab, CD_TASK);

    return OK;
}