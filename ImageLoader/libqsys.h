/*
 * =====================================================================================
 *
 *       Filename:  libqsys.h
 *
 *    Description:  Pure C interface of QSys
 *
 *        Version:  1.0
 *        Created:  2020/7/21 8:39:03 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  m.barbini (mb), marco.barbini@quixant.com
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
 * FOR A PARTICULAR PURPOSE OR USE, OR NONINFRINGEMENT. QUIXANT WILL HAVE NO 
 * LIABILITY (WHETHER IN CONTRACT, WARRANTY, TORT, NEGLIGENCE OR INCLUDING, 
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, OR 
 * CONSEQUENTIAL DAMAGES OF LOSS OF DATA, SAVINGS OR PROFITS, EVEN IF QUIXANT
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * =====================================================================================
 */

#ifndef _LIBQSYS_H_
#define _LIBQSYS_H_


/* #####   EXPORTED MACROS   ######################################################## */

/*
 *  QSys product id and version
 */
#if defined (_WIN32)
/*-----------------------------------------------------------------------------
 *  Windows
 *-----------------------------------------------------------------------------*/
#if defined (_M_AMD64)  
// 64bit
#if defined (_WINDLL)   
// dynamic
#define QSYS_PROD_ID "R_LIB_QSYS_WIN_D64"
#else                   
// static
#define QSYS_PROD_ID "R_LIB_QSYS_WIN_S64"
#endif
#else                   
// 32bit
#if defined (_WINDLL)   
// dynamic
#define QSYS_PROD_ID "R_LIB_QSYS_WIN_D32"
#else                   
// static
#define QSYS_PROD_ID "R_LIB_QSYS_WIN_S32"
#endif
#endif
#else
/*-----------------------------------------------------------------------------
 *  Linux
 *-----------------------------------------------------------------------------*/
#if defined(_SHARED)
// Shared
#if __x86_64__ || __ppc64__
// 64bit
#define QSYS_PROD_ID "R_LIB_QSYS_LIN_D64"
#else
// 32 bit
#define QSYS_PROD_ID "R_LIB_QSYS_LIN_D32"
#endif 
#else
// Static
#if __x86_64__ || __ppc64__
// 64bit
#define QSYS_PROD_ID "R_LIB_QSYS_LIN_S64"
#else
// 32bit
#define QSYS_PROD_ID "R_LIB_QSYS_LIN_S32"
#endif
#endif
#endif

/*
 * Tools for library versioning information
 */
#define QSYS_LIBVER_STR(a,b,c,d) QSYS_LIBVER_STRX(a,b,c,d)
#define QSYS_LIBVER_STRX(a,b,c,d) #a "." #b "." #c "." #d

#define QSYS_LIBRARY_VERSION_1		2  	
#define QSYS_LIBRARY_VERSION_2		11 	
#define QSYS_LIBRARY_VERSION_3		0 	
#define QSYS_LIBRARY_VERSION_4		0

#ifdef _WINDLL
#ifdef __cplusplus
#define LIBCQSYS_API extern "C" __declspec(dllexport)
#else
#define LIBCQSYS_API __declspec(dllexport)
#endif
#else
#ifdef __cplusplus
#define LIBCQSYS_API extern "C"
#else
#define LIBCQSYS_API
#endif
#endif

#ifndef _WIN32
#ifndef HANDLE
#define HANDLE void *
#endif
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (HANDLE)-1
#endif
#else
#include <Windows.h>
#endif

#ifndef QRESULT
#define QRESULT unsigned int
#endif

/*
 * =====================================================================================
 *       Macros:  Error Codes
 *  Description:  QRESULT errors from the C API
 * =====================================================================================
 */
#define Q_NOEXIST       0x80000001
#define Q_EXIST         0x80000002
#define Q_DUPLICATE     0x80000003
#define Q_MALFORMED     0x80000004
#define Q_UNSUPPORTED   0x80000005
#define Q_UNDEFINED     0x80000006
#define Q_NOMEM         0x80000007
#define Q_INVALID       0x80000008
#define Q_END           0x80000009


/* #####   EXPORTED FUNCTION DECLARATIONS   ######################################### */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysOpen
 *  Description:  Open a new session of the QSys subsystem, setting the passed handle.
 *                The handle, if valid, can be used in any subsequent QSys function.
 *                In case of error, the handle value is INVALID_HANDLE_VALUE.
 *  Error Codes:  Q_NOMEM: not enough memory to allocate the new QSys subsystem
 *                Q_INVALID: invalid handle address
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysOpen(HANDLE * handle);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysClose
 *  Description:  Terminate an open session of the QSys subsystem using a valid session
 *                handle.
 *  Error Codes:  Q_INVALID: the handle does not refers to any valid open session
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysClose(HANDLE);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysGetLastError
 *  Description:  Return the last error caused by any unsuccesfull QSys operation.
 *         Note:  If the user provided handle is invalid, the return code is Q_INVALID,
 *                independently from the actual error of the QSys subsystem
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysGetLastError(HANDLE);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysMakeQuery
 *  Description:  Make a query in the current QSys subsystem, using a regular expression
 *                applied to any key stored inside the QSys tree and setting a handle 
 *                usable in qsysBeginEntry(), qsysNextEntry() and qsysDestroyQuery(). 
 *                The returned handle has the value INVALID_HANDLE_VALUE in case of
 *                error.
 *  Error codes:  Q_INVALID: invalid handle or handle pointer
 *                Q_MALFORMED: the query is malformed
 *                Q_NOMEM: not enough memory to create the query
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysMakeQuery(HANDLE qsys_handle, const char* reg_exp, HANDLE* query_handle);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysQueryDirectory
 *  Description:  Make a query in the current QSys subsystem, selecting the directory
 *                that contains the user passed key and filling the query_handle that
 *                can be used in qsysBeginEntry(), qsysNextEntry() and
 *                qsysDestroyQuery().
 *                The returned handle has the value INVALID_HANDLE_VALUE in case of
 *                error.
 *  Error codes:  Q_INVALID: invalid handle or handle pointer
 *                Q_MALFORMED: the query is malformed
 *                Q_NOMEM: not enough memory to create the query
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysQueryDirectory(HANDLE qsys_handle, const char* key, HANDLE* query_handle);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysFirstEntry
 *  Description:  Given the handle returned by qsysMakeQuery() or qsysQueryDirectory(),
 *                get the first item that matches the query. The result is stored inside
 *                the key,value pair.
 *                This function must be called first before any qsysNextEntry().
 *  Error codes:  Q_INVALID: invalid argument
 *                Q_END: no result for the the current query
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysFirstEntry(HANDLE query_handle, char* key, size_t key_size, char* value, size_t value_size);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysNextEntry
 *  Description:  Given the handle returned by qsysMakeQuery() or qsysQueryDirectory(),
 *                get the next item that matches the query. The result is stored inside
 *                the key,value pair.
 *                This function must be called only after qsysFirstEntry();
 *  Error codes:  Q_INVALID: invalid argument
 *                Q_END: no result for the the current query
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysNextEntry(HANDLE query_handle, char* key, size_t key_size, char* value, size_t value_size);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  qsysDestroyQuery
 *  Description:  Given the handle returned by qsysMakeQuery() or qsysQueryDirectory(),
 *                the function releases any resource previously allocated. After the
 *                call the query handle is invalid.
 *  Error codes:  Q_INVALID: invalid argument
 * =====================================================================================
 */
LIBCQSYS_API QRESULT qsysDestroyQuery(HANDLE query_handle);

#endif
