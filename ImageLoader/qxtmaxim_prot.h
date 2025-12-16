/*
 * =====================================================================================
 *
 *       Filename:  qxtmaxim_prot.h
 *
 *    Description:  Maxim protection structures
 *
 *        Version:  1.0
 *        Created:  9/17/2021 5:43:34 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Marco Barbini (MB), marco.barbini@quixant.com
 *   Organization:  QIT
 *
 * =====================================================================================
 * This software is owned and published by:
 * Quixant Italia srl, Contrada Case Bruciate, 1, Torrita Tiberina, RM, Italy
 *
 * BY DOWNLOADING, INSTALLING OR USING THIS SOFTWARE, YOU AGREE TO BE BOUND
 * BY ALL THE TERMS AND CONDITIONS OF THIS AGREEMENT.
 *
 * This software consists of code for use in programming Quixant gaming
 * platforms. This software is licensed by Quixant to be adapted only for
 * use with Quixant series of gaming platforms. Quixant is not responsible
 * for misuse of illegal use of the software for platforms not supported herein.
 * Quixant is providing this source code "AS IS" and will not be responsible for
 * issues arising from incorrect user implementation of the source code herein.
 *
 * QUIXANT MAKES NO WARRANTY, EXPRESS OR IMPLIED, ARISING BY LAW OR OTHERWISE,
 * REGARDING THE SOFTWARE, ITS PERFORMANCE OR SUITABILITY FOR YOUR INTENDED USE
 * INCLUDING, WITHOUT LIMITATION, NO IMPLIED WARRANTY OF MERCHANTABILITY FITNESS
 * FOR A PARTICULAR PURPOSE OR USE, OR NON-INFRINGEMENT. QUIXANT WILL HAVE NO
 * LIABILITY (WHETHER IN CONTRACT, WARRANTY, TORT, NEGLIGENCE OR INCLUDING,
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, OR
 * CONSEQUENTIAL DAMAGES OF LOSS OF DATA, SAVINGS OR PROFITS, EVEN IF QUIXANT
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * =====================================================================================
 */
#pragma once
#include "qxteeprom.h"

/** \addtogroup API
@{*/
/*
 * =====================================================================================
 *       Macros:  Maxim protection macros
 * =====================================================================================
 */

/*-----------------------------------------------------------------------------
 * Maxim commands in qxt_eeprom-protect_t (see qxt_eeprom_protect_t::cmd)
 *-----------------------------------------------------------------------------*/
#define PROT_PAGE_STORE     0x0001  ///< Stores the page protection on chip
#define PROT_PAGE_LOAD      0x0002  ///< Loads the page protection
#define PROT_SECRET_STORE   0x0003  ///< Stores the secret on chip
#define PROT_SECRET_SET     0x0004  ///< Sets a editable secret
#define PROT_SECRET_NEXT    0x0005  ///< Updates the secret stored on chip [NOT SUPPORTED]
#define PROT_SECRET_FINAL   0x0006  ///< Protects permanently the secret stored on chip [NOT SUPPORTED]

/*-----------------------------------------------------------------------------
 * Protection attribute for memory pages (see qxt_prot_page_t::prot)
 *-----------------------------------------------------------------------------*/
#define PROT_NONE           0x0000  ///< No protection
#define PROT_READ           0x0001  ///< Read protection
#define PROT_WRITE          0x0002  ///< Write protection
#define PROT_EM             0x0004  ///< EEPROM emulation protection
#define PROT_APH            0x0008  ///< Write protection with HMAC
#define PROT_EPH            0x0010  ///< Write protection with encryption and HMAC [NOT SUPPORTED]

/***************************************************************************************
 * \brief   Used as the parameter of qxtEepromProtect(), this function is related to the
 *          page protection attribute of the selected memory page.
 **************************************************************************************/
typedef struct qxt_prot_page_s
{
    qxt_eeprom_protect_t base;      ///< Base protection struct
    uint16_t prot;                  ///< Protection attribute
    int page;                       ///< Number of page
} qxt_prot_page_t;

/***************************************************************************************
 * \brief   Used as the parameter of qxtEepromProtect(), this function is used to set or store
 *          the secret to be used during the protected memory accesses for reading or writing
 **************************************************************************************/
typedef struct qxt_prot_secret_s
{
    qxt_eeprom_protect_t base;      ///< Base protection struct
    uint8_t secret[2048];           ///< User defined secret
} qxt_prot_secret_t;

/**
 *
 *  Please note that not all commands or protection attributes are supported yet. When documented with [NOT SUPPORTED]
 *  it means that no chip/devices offer that feature in the current version
 *
PROT_PAGE_STORE

Synopsis

qxt_prot_page_t prot_page =
{
    .base = {.cmd = PROT_PAGE_STORE, .size = sizeof(prot_page) },
    .prot = <protection attribute code>,
    .page = <page number>
};
qxtEepromProtect(<memory chip handle>, (qxt_eeprom_protect_t *)&prot_page);

Description

Set persistently the page protection attribute of the selected page on the chip memory

PROT_PAGE_LOAD

Synopsis

qxt_prot_page_t prot_page =
{
    .base = {.cmd = PROT_PAGE_LOAD, .size = sizeof(prot_page) },
    .prot = <protection attribute code>,
    .page = <page number>
};
qxtEepromProtect(<memory chip handle>, (qxt_eeprom_protect_t *)&prot_page);

Description

Load the page protection attribute of the selected page on the chip memory in the 'prot' field


PROT_SECRET_STORE

Synopsis

qxt_prot_secret_t prot_secret =
{
    .base = { .cmd = PROT_SECRET_STORE, .size = <size of the secret> },
    .secret = { <secret byte sequence> }
};
qxtEepromProtect(<memory chip handle>, (qxt_eeprom_protect_t *)&prot_secret);

Description

Set permanently the user defined secret on the chip memory. Devices differ for the size of the secret:
 - DS28CN01 requires a secret of 8 bytes
 - DS28C50/36 requires a secret in range [8-32] bytes

NOTE:   In case of DS28C50 devices, user must ensure that PAGE 0 is in a readable/writable state during the PROT_SECRET_STORE
        command and exclusive access to it. After that, the user can use the page as he sees fit.


PROT_SECRET_SET

Synopsis

qxt_prot_secret_t prot_secret =
{
    .base = { .cmd = PROT_SECRET_SET, .size = <size of the secret> },
    .secret = { <secret byte sequence> }
};
qxtEepromProtect(<memory chip handle>, (qxt_eeprom_protect_t *)&prot_secret);

Description

Set an editable user defined secret on the chip memory. Devices differ for the size of the secret:
 - DS28CN01 requires a secret of 8 bytes
 - DS28C50/36 requires a secret in range [8-32] bytes

PROT_SECRET_NEXT [NOT SUPPORTED]

Synopsis

qxt_prot_secret_t prot_secret =
{
    .base = { .cmd = PROT_SECRET_NEXT, .size = <size of the new partial secret> },
    .secret = { <new partial secret byte sequence> }
};
qxtEepromProtect(<memory chip handle>, (qxt_eeprom_protect_t *)&prot_secret);

Description

Update the persistent secret stored on the chip using the new partial secret.
After the call, the field secret is filled with the new calculated secret.


PROT_SECRET_FINAL [NOT SUPPORTED]

Synopsis

qxt_prot_secret_t prot_secret =
{
    .base = { .cmd = PROT_SECRET_FINAL, .size = <size of the new partial secret> },
    .secret = { <new partial secret byte sequence> }
};
qxtEepromProtect(<memory chip handle>, (qxt_eeprom_protect_t *)&prot_secret);

Description

Update the persistent secret stored on the chip using the new partial secret.
After the call, the new calculated secret is returned to the secret field of the structure and the secret cannot be modified anymore.
*/
///@}