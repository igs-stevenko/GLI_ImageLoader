/*
 * =====================================================================================
 *
 *       Filename:  qxteeprom.h
 *
 *    Description:  Pure C interface of QxtEEPROM
 *
 *        Version:  1.0
 *        Created:  2020/8/16
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  s.rivieccio (sr), salvatore.rivieccio@quixant.com
 *   Organization:  Quixant plc
 *
 * =====================================================================================
 * This software is owned and published by:
 * Quixant Italia srl, Contrada Case Bruciate, 1, Torrita Tiberina, Roma
 *
 * BY DOWNLOADING, INSTALLING OR USING THIS SOFTWARE, YOU AGREE TO BE BOUND
 * BY ALL THE TERMS AND CONDITIONS OF THIS AGREEMENT.
 *
 * This software constitutes of code for use in programming Quixant gaming
 * platforms. This software is licensed by Quixant to be adapted only for 
 * use with Quixant's series of gaming platforms. Quixant is not responsible
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
#include <stdint.h>
#include <stddef.h>

#ifdef _WINDLL
#ifdef __cplusplus
#define QXTEEPROM_API extern "C" __declspec(dllexport)
#else
#define QXTEEPROM_API __declspec(dllexport)
#endif
#else
#ifdef __cplusplus
#define QXTEEPROM_API extern "C"
#else
#define QXTEEPROM_API
#endif
#endif

#ifndef _WIN32
#ifndef HANDLE
#define HANDLE void *
#endif
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#endif
#else
#include <Windows.h>
#endif

#define QXTEEPROM_LIB_VERSION_1		2
#define QXTEEPROM_LIB_VERSION_2		3
#define QXTEEPROM_LIB_VERSION_3		3
#define QXTEEPROM_LIB_VERSION_4		0

/** \addtogroup API
 * The library QxtEeprom unifies the management of the EEPROM or FLASH memory chips on the Quixant boards.
 * It exhibits a simple, uniform and platform independent interface that permits the final users to list and access for
 * reading and writing any EEPROM/FLASH chip present on the board, independent from any needs to explicitly address the
 * underlying bus (I2C, SMBUS, SPI, etc.).
@{*/
#ifndef QRESULT
#define QRESULT unsigned int    ///< Library return value definition
#endif

#ifndef Q_SUCCESS
#define Q_SUCCESS 0     ///< Library success value definition
#endif

/*
 * =====================================================================================
 *       Macros:  Error Codes
 *  Description:  QRESULT errors from the C API
 * =====================================================================================
 */
#define Q_NOEXIST               0x80000001  ///< No exist error code
#define Q_EXIST                 0x80000002  ///< Exist error code
#define Q_DUPLICATE             0x80000003  ///< Duplicate error code
#define Q_MALFORMED             0x80000004  ///< Malformed error code
#define Q_UNSUPPORTED           0x80000005  ///< Unsupported action error code
#define Q_UNDEFINED             0x80000006  ///< Object Undefined error code
#define Q_NOMEM                 0x80000007  ///< No memory available error code
#define Q_MEM_OUT_OF_RANGE      0x80000008  ///< Out of bound memory error code
#define Q_INVALID               0x80000009  ///< Invalid action error code
#define Q_END                   0x8000000A  ///< End error code
#define Q_NOT_IMPLEMENTED       0x8000000B  ///< Command not implemented error code
#define Q_INVALID_PARAMETER     0x8000000C  ///< Invalid parameter error code
#define Q_GENERIC_WRITE_ERROR   0x8000000D  ///< Write error error code
#define Q_GENERIC_READ_ERROR    0x8000000E  ///< Read error error code
#define Q_GENERIC_PROT_ERROR    0x8000000F  ///< Protection error code
#define Q_AUTH_WRITE_ERROR      0x80000010  ///< Authentication write error code
#define Q_WRONG_SECRET          0x80000011  ///< Wrong secret error code
#define Q_DESTINATION_PROTECTED 0x80000012  ///< Destination protected error code
/*
 * =====================================================================================
 *       Macros:  Handles/Descriptors initializer
 *  Description:  define for handles and descriptors initial state
 * =====================================================================================
 */
 #define EEPROM_HANDLE_INIT 	0       	        		    		    ///< Library handle initializer
 #define MEMORY_HANDLE_INIT	    0       			    				    ///< Memory handle initializer
 #define EEPROM_DESC_NULL       {(e_bus_type)0, 0, 0, 0, {0}, {0}, 0, 0}    ///< Dev descriptor initializer
 
/*
 * =====================================================================================
 *  Description:  Enums used by the library
 * =====================================================================================
 */
/***************************************************************************************
 * \brief Enum used to specify bus type
 **************************************************************************************/
 typedef enum e_bus_type
 {
     null = 0x00,    ///< Bus null
     i2c,            ///< i2c bus
     smbus,          ///< smbus bus
     unknown = 0xFF  ///< Unknown bus, not supported
 } e_bus_type;

/*
 * =====================================================================================
 *  Description:  Structs used by the library
 * =====================================================================================
 */
/***************************************************************************************
 * \brief Opaque struct for library handle
 **************************************************************************************/
typedef struct qxt_eeprom_t* qxt_eeprom_handle_t;

/***************************************************************************************
 * \brief A struct containing device information
 **************************************************************************************/
typedef struct qxt_eeprom_desc_t
{
	e_bus_type 	device_type;        ///< Dev type: i2c, smbus, spi and so on...
	uint8_t     device_channel;     ///< Dev channel, if there are more than one bus of the same type
	size_t 		memory_size;        ///< Dev total available memory
	uint64_t 	device_addr;        ///< The address on the specified bus
	char 		device_model[256];  ///< String containing chip model
	uint8_t 	device_serial[64];  ///< Unique serial number
	size_t      serial_length;      ///< Length of the serial number
	uint8_t     prot_available;     ///< This flag indicates whether the chip is protectable
} qxt_eeprom_desc_t;
/***************************************************************************************
 * \brief Opaque struct for memory handle
 **************************************************************************************/
typedef struct qxt_memory_t* qxt_memory_handle_t;

/***************************************************************************************
* \brief  protection structure passed by the user contains
*         the needed data (keys, certificates, etc.) to obtain the access rights,
*         depending on the chip security features.
**************************************************************************************/
typedef struct qxt_eeprom_protect_t
{
    uint16_t	cmd;    ///< The command that is wanted to use, it depends from the selected chip
    uint16_t	size;   ///< This field contains the size of the 'child' struct (it will have chip-specific fields)
} qxt_eeprom_protect_t;

/*
 * =====================================================================================
 *  Description: Exported function declaration
 * =====================================================================================
 */
/***************************************************************************************
 * \brief	    Initializes the access to the EEPROM chips on the board. The function
 *		        initializes a handle to be used by the following calls: qxtEepromScan(),
 *		        qxtEepromSelect(), qxtEepromClose().
 *
 * \return	    An integer contains the status of the call. In case of success this
 *              function will fill the handle with a proper value.
 *
 * \retval	    Q_SUCCESS	The function is successful
 * \retval	    Q_INVALID	The handle is invalid, or the library could not be opened
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromOpen
(
	qxt_eeprom_handle_t * handle 	///< [out] The handle for the eeprom library
);

/***************************************************************************************
 * \brief       Scans the EEPROM chips on the board and returns the first item if called
 * 		        with desc = qxt_eeprom_desc_null; the function sets the passed descriptor
 * 		        such that any subsequent call to qxtEepromScan() returns the next
 * 		        chip's descriptor.
 *
 * \return      An integer contains the status of the call.In case of success this
 *              function will fill the device descriptor with the proper values.
 *
 * \retval      Q_SUCCESS                   The function is successful
 * \retval      Q_INVALID                   The library is not initialized
 * \retval      Q_NOEXIST                   No device found
 * \retval      Q_END                       No more devices to be scanned
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromScan
(
	qxt_eeprom_handle_t handle, 	///< [in] The library handle
	qxt_eeprom_desc_t *desc 	    ///< [out] The device/chip descriptor
);

/***************************************************************************************
 * \brief       Selects the chip identified by its descriptor, returned by any previous
 * 		        call to qxtEepromScan(). The function takes the exclusive ownership of
 * 		        the chip, blocking any further access from other processes and sets the
 * 		        qxt_memory_handle provided by the caller.
 * 		        The qxt_memory_handle must be used for any access to the chip memory.
 *
 * \return      An integer contains the status of the call. In case of success this
 *              function will fill the memory handle with a proper value.
 *
 * \retval      Q_SUCCESS                   The function is successful
 * \retval      Q_INVALID                   The library is not initialized
 * \retval      Q_INVALID_PARAMETER         The chosen device is not selectable
 * \retval      Q_DUPLICATE                 Device already taken
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromSelect
(
 	qxt_eeprom_handle_t handle, 		///< [in] The library handle
	qxt_eeprom_desc_t *desc, 			///< [in] The device/chip descriptor
	qxt_memory_handle_t * mem_handle 	///< [out] The memory handle for the selected chip
);

/***************************************************************************************
 * \brief       Transfers a data block from the selected EEPROM memory source to the CPU
 * 		        memory destination.
 *
 * \return      An integer contains the status of the call.
 *
 * \retval      Q_SUCCESS                   The function is successful
 * \retval      Q_INVALID                   The library is not initialized
 * \retval      Q_NOEXIST                   Memory handle do not exist
 * \retval      Q_MEM_OUT_OF_RANGE          Memory out of bound error
 * \retval      Q_GENERIC_READ_ERROR        Error while reading device
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromRead
(
 	qxt_memory_handle_t handle, 	///< [in] The memory handle for the selected chip
	uint64_t src_addr, 		        ///< [in] The starting memory address that is wanted to be read
	void * dst, 			        ///< [out] The user memory block where to place the read data
	size_t size 			        ///< [in] The number of data that wants to be read
);

/***************************************************************************************
 * \brief       Transfers a data block from the CPU memory source to the selected 
 * 		        EEPROM memory destination.
 *
 * \return      An integer contains the status of the call.
 *
 * \retval      Q_SUCCESS                   The function is successful
 * \retval      Q_INVALID                   The library is not initialized
 * \retval      Q_NOEXIST                   Memory handle do not exist
 * \retval      Q_MEM_OUT_OF_RANGE          Memory out of bound error
 * \retval      Q_GENERIC_WRITE_ERROR       Error while writing device
 * \retval      Q_AUTH_WRITE_ERROR          Error while writing authenticated memory
 * \retval      Q_DESTINATION_PROTECTED     Chip/device memory slot protected
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromWrite
(
	qxt_memory_handle_t handle,     ///< [in] The memory handle for the selected chip
	uint64_t dst_addr,              ///< [in] The starting memory address that is wanted to be wrote
	void * src,                     ///< [out] The user memory block where to take the write data
	size_t size                     ///< [in] The number of data that wants to be read
);

/***************************************************************************************
 * \brief       Allows or inhibits the access to the EEPROM chip, if it supports any 
 * 		        security mechanism. The protection structure passed by the user contains
 * 		        the needed data (keys, certificates, etc.) to obtain the access rights,
 * 		        depending on the chip security features.
 *
 * \return      An integer contains the status of the call.
 *
 * \retval      Q_SUCCESS                   The function is successful
 * \retval      Q_INVALID                   The library is not initialized
 * \retval      Q_NOEXIST                   Memory handle do not exist
 * \retval      Q_INVALID_PARAMETER         'prot' parameter is invalid
 * \retval      Q_GENERIC_PROT_ERROR        Generic protection error
 * \retval      Q_NOT_IMPLEMENTED           Command not implemented
 * \retval      Q_UNSUPPORTED               Command not supported
 * \retval      Q_GENERIC_WRITE_ERROR       Generic write error
 * \retval      Q_DESTINATION_PROTECTED     The selected chip is already protected
 * \retval      Q_AUTH_WRITE_ERROR          Authenticated write error, ex: secret not set or wrong
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromProtect
(
 	qxt_memory_handle_t handle,     ///< [in] The memory handle for the selected chip
	qxt_eeprom_protect_t *prot      ///< [in|out] The protection struct is used in either way as input/output parameter
);

/***************************************************************************************
 * \brief       Releases the chip ownership, identified by its handle, previously 
 * 		        obtained by qxtEepromSelect().
 *
 * \return      An integer contains the status of the call.
 *
 * \retval      Q_SUCCESS     The function is successful
 * \retval      Q_INVALID     The handle is invalid
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromRelease
(
 	qxt_memory_handle_t handle     ///< [in] The memory handle for the selected chip
);

/***************************************************************************************
 * \brief       Terminates the EEPROM library session. Any previously taken memory handle
 * 		        yet owned by the caller is implicitly released and the corresponding
 * 		        memory no more accessible.
 *
 * \return      An integer contains the status of the call.
 *
 * \retval      Q_SUCCESS     The function is successful
 * \retval      Q_INVALID     The handle is invalid
 *
 **************************************************************************************/
QXTEEPROM_API QRESULT qxtEepromClose
(
 	qxt_eeprom_handle_t handle      ///< [in] The library handle
);
///@}
