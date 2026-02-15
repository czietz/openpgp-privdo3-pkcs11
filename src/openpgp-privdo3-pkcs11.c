/*
 *  Copyright 2026 Christian Zietz <czietz@gmx.net>
 *
 *  Copyright 2011-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 *
 *  Modified for OpenPGP-PrivDO3-PKCS11 by:
 *  Christian Zietz <czietz@gmx.net>
 */


#include "openpgp-privdo3-pkcs11.h"

#define no_init_all deprecated

#ifdef _WIN32
#include <windows.h>
#include <winscard.h>
#else
#include <winscard.h>
#include <wintypes.h>
#define SCardListReadersA SCardListReaders
#define SCardConnectA SCardConnect
#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#endif

SCARDCONTEXT g_hContext = (SCARDCONTEXT)0;

#define MAX_SLOTS 8u
 // direct 1-to-1 mapping between slots and sessions
#define MAX_SESSIONS MAX_SLOTS

typedef struct {
	int available;
	char name[64];
	SCARDHANDLE hcard;
	DWORD protocol;
} SLOT;

typedef struct {
	int active;
	int objects;
	CK_SESSION_INFO session_info;
} SESSION;

unsigned int g_slotcnt = 0;

// info about slots
SLOT g_slots[MAX_SLOTS];
// info about sessions
SESSION g_sessions[MAX_SESSIONS];

// we only support private data object #3 with a 'magic' ID
#define OBJECT_NAME "PrivDO3"
#define MAGIC_OBJECT_NUM 42u

#define VALID_PTR_CHECK(ptr) do { if (NULL == ptr) return CKR_ARGUMENTS_BAD; } while (0)
#define VALID_SLOT_CHECK(slotID) do { if ((slotID >= MAX_SLOTS) || (slotID >= g_slotcnt) || !g_slots[slotID].available) return CKR_SLOT_ID_INVALID; } while (0)
#define VALID_SESSION_CHECK(hSession) do { if ((hSession >= MAX_SESSIONS) || !g_sessions[hSession].active) return CKR_SESSION_HANDLE_INVALID; } while (0)
#define VALID_OBJECT_CHECK(hObject) do { if (hObject != MAGIC_OBJECT_NUM) return CKR_OBJECT_HANDLE_INVALID; } while (0)

#ifdef _WIN32
#define SECURE_WIPE(ptr,len) SecureZeroMemory(ptr, len)
#else
#define SECURE_WIPE(ptr,len) memset(ptr, 0, len)
#endif

// OpenPGP smartcard functions

static LONG openpgp_command(unsigned int slotID, const BYTE* sendBuffer, DWORD sendLength, BYTE* recvBuffer, DWORD* recvLength)
{
	SCARD_IO_REQUEST pioSendPci;
	LONG rv;

	if (g_slots[slotID].protocol == SCARD_PROTOCOL_T0) {
		pioSendPci = *SCARD_PCI_T0;
	} else {
		pioSendPci = *SCARD_PCI_T1;
	}

	rv = SCardTransmit(g_slots[slotID].hcard,
		&pioSendPci,
		sendBuffer,
		sendLength,
		NULL,
		recvBuffer,
		recvLength);

	return rv;
}

static int select_app(unsigned int slotID)
{
	BYTE cmd_select[] = { 0x00, 0xa4, 0x04, 0x00, 0x06, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01 };
	BYTE status[2] = { 0,0 };
	DWORD retlen = sizeof(status);
	LONG rv;

	rv = openpgp_command(slotID, cmd_select, sizeof(cmd_select), status, &retlen);
	// TODO map errors to PKCS#11 return codes
	return (rv == SCARD_S_SUCCESS) && (retlen >= 2) && (status[retlen - 2] == 0x90) && (status[retlen - 1] == 0);
}

// TODO what is max
#define MAX_PIN_LEN 32

static int verify_pin82(unsigned int slotID, BYTE pinlen, BYTE* pin)
{
	BYTE cmd_verify[5+MAX_PIN_LEN] = { 0x00, 0x20, 0x00, 0x82 };
	BYTE status[2] = { 0,0 };
	DWORD retlen = sizeof(status);
	LONG rv;

	if (pinlen > MAX_PIN_LEN) {
		pinlen = MAX_PIN_LEN;
	}
	cmd_verify[4] = pinlen;
	memcpy(&cmd_verify[5], pin, pinlen);
	rv = openpgp_command(slotID, cmd_verify, 5 + pinlen, status, &retlen);
	// TODO map errors to PKCS#11 return codes
	return (rv == SCARD_S_SUCCESS) && (retlen >= 2) && (status[retlen-2] == 0x90) && (status[retlen-1] == 0);
}

static int unverify_pin82(unsigned int slotID)
{
	BYTE cmd_verify[] = { 0x00, 0x20, 0xff, 0x82 };
	BYTE status[2] = { 0,0 };
	DWORD retlen = sizeof(status);
	LONG rv;

	rv = openpgp_command(slotID, cmd_verify, sizeof(cmd_verify), status, &retlen);
	// TODO map errors to PKCS#11 return codes
	return (rv == SCARD_S_SUCCESS) && (retlen >= 2) && (status[retlen - 2] == 0x90) && (status[retlen - 1] == 0);
}

#define TAG_PRIVDO3 0x0103
// TODO: dynamically determine maximum DO size from 'extended capabilities'
// Nitrokey announces 0x1000 = 4096 bytes, Yubikey 255 bytes
#define MAX_DO_SIZE 1024 

static int get_privdo3(unsigned int slotID, BYTE* buffer, ULONG buflen)
{
	BYTE cmd_getdata[] = { 0x00, 0xca, TAG_PRIVDO3>>8, TAG_PRIVDO3 & 0xff, 0x00, MAX_DO_SIZE>>8, MAX_DO_SIZE & 0xff };
	BYTE status[MAX_DO_SIZE+2] = { 0 };
	DWORD retlen = sizeof(status);
	LONG rv;
	int filelen = -1; // error

	rv = openpgp_command(slotID, cmd_getdata, sizeof(cmd_getdata), status, &retlen);

	if ((rv == SCARD_S_SUCCESS) && (retlen >= 2) && (status[retlen - 2] == 0x90) && (status[retlen - 1] == 0)) {
		int bytes_to_copy;

		filelen = retlen - 2;
		bytes_to_copy = min(retlen - 2, buflen);
		if (buffer != NULL) {
			memcpy(buffer, status, bytes_to_copy);
		}
	}

	SECURE_WIPE(status, sizeof(status));

	// TODO map errors to PKCS#11 return codes
	return filelen;
}

static int put_privdo3(unsigned int slotID, BYTE* buffer, ULONG buflen)
{
	BYTE cmd_putdata[MAX_DO_SIZE+7] = { 0x00, 0xda, TAG_PRIVDO3 >> 8, TAG_PRIVDO3 & 0xff, 0x00 };
	BYTE status[2] = { 0, 0 };
	DWORD retlen = sizeof(status);
	LONG rv = SCARD_E_WRITE_TOO_MANY;

	if (buflen <= MAX_DO_SIZE) {
		cmd_putdata[5] = (BYTE)(buflen >> 8);
		cmd_putdata[6] = (BYTE)(buflen & 0xff);
		if (buffer != NULL) {
			memcpy(&cmd_putdata[7], buffer, buflen);
		}
		rv = openpgp_command(slotID, cmd_putdata, 7 + buflen, status, &retlen);
	}

	SECURE_WIPE(cmd_putdata, sizeof(cmd_putdata));

	// TODO map errors to PKCS#11 return codes
	return (rv == SCARD_S_SUCCESS) && (retlen >= 2) && (status[retlen - 2] == 0x90) && (status[retlen - 1] == 0);
}

CK_FUNCTION_LIST openpgp_pkcs11_2_40_functions =
{
	{0x02, 0x28},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};


CK_INTERFACE openpgp_pkcs11_2_40_interface =
{
	(CK_CHAR*)"PKCS 11",
	&openpgp_pkcs11_2_40_functions,
	0
};


CK_FUNCTION_LIST_3_0  openpgp_pkcs11_3_0_functions =
{
	{0x03, 0x00},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
	&C_GetInterfaceList,
	&C_GetInterface,
	&C_LoginUser,
	&C_SessionCancel,
	&C_MessageEncryptInit,
	&C_EncryptMessage,
	&C_EncryptMessageBegin,
	&C_EncryptMessageNext,
	&C_MessageEncryptFinal,
	&C_MessageDecryptInit,
	&C_DecryptMessage,
	&C_DecryptMessageBegin,
	&C_DecryptMessageNext,
	&C_MessageDecryptFinal,
	&C_MessageSignInit,
	&C_SignMessage,
	&C_SignMessageBegin,
	&C_SignMessageNext,
	&C_MessageSignFinal,
	&C_MessageVerifyInit,
	&C_VerifyMessage,
	&C_VerifyMessageBegin,
	&C_VerifyMessageNext,
	&C_MessageVerifyFinal
};


CK_INTERFACE openpgp_pkcs11_3_0_interface =
{
	(CK_CHAR*)"PKCS 11",
	&openpgp_pkcs11_3_0_functions,
	0
};

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	UNUSED(pInitArgs);
	LONG rv;
	char *mszReaders = NULL;
	char *mszReaders_orig = NULL;
	DWORD dwReaders = SCARD_AUTOALLOCATE;

	g_slotcnt = 0;
	memset(g_slots, 0, sizeof(g_slots));
	memset(g_sessions, 0, sizeof(g_sessions));

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_hContext);
	if (rv == SCARD_S_SUCCESS) {
		rv = SCardListReadersA(g_hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
		if (rv == SCARD_S_SUCCESS) {
			mszReaders_orig = mszReaders;
			// mszReaders is a double-NULL-terminated array of NULL-terminated strings
			while (strlen(mszReaders) > 0) {

				rv = SCardConnectA(g_hContext, mszReaders, SCARD_SHARE_SHARED,
					SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
					&g_slots[g_slotcnt].hcard, &g_slots[g_slotcnt].protocol);

				if (rv == SCARD_S_SUCCESS) {
					if (select_app(g_slotcnt)) {
						g_slots[g_slotcnt].available = 1;
						strncpy(g_slots[g_slotcnt].name, mszReaders, sizeof(g_slots[g_slotcnt].name));
						g_slotcnt++;
					}
				}

				mszReaders += strlen(mszReaders) + 1;

			}

			SCardFreeMemory(g_hContext, mszReaders_orig);

		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	UNUSED(pReserved);

	for (unsigned int k = 0; k < MAX_SESSIONS; k++)
	{
		if (g_sessions[k].active) {
			C_Logout(k);
		}
	}

	memset(g_slots, 0, sizeof(g_slots));
	memset(g_sessions, 0, sizeof(g_sessions));
	g_slotcnt = 0;

	// TODO: check if SCardReleaseContext disconnects from all cards

	if (g_hContext) {
		SCardReleaseContext(g_hContext);
		g_hContext = (SCARDCONTEXT)0;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &openpgp_pkcs11_2_40_functions;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	UNUSED(tokenPresent);

	CK_RV retval = CKR_OK;

	VALID_PTR_CHECK(pulCount);

	if (NULL != pSlotList) {
		if (*pulCount >= g_slotcnt) {
			for (CK_ULONG k=0; k < g_slotcnt; k++) {
				pSlotList[k] = (CK_SLOT_ID)k;
			}
		} else {
			retval = CKR_BUFFER_TOO_SMALL;
		}
	}

	*pulCount = g_slotcnt;
	return retval;
}



CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	VALID_PTR_CHECK(pInfo);

	VALID_SLOT_CHECK(slotID);

	// strings need to be padded with spaces and must not be NULL terminated
	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->slotDescription, g_slots[slotID].name, strlen(g_slots[slotID].name));

	pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
	pInfo->hardwareVersion.major = 1;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	VALID_PTR_CHECK(pInfo);

	VALID_SLOT_CHECK(slotID);

	memset(pInfo, ' ', sizeof(CK_TOKEN_INFO));
	memcpy(pInfo->label, g_slots[slotID].name, strlen(g_slots[slotID].name));

	pInfo->flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	pInfo->hardwareVersion.major = 1;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;
	pInfo->ulMaxSessionCount = 1;
	pInfo->ulMaxRwSessionCount = 1;
	pInfo->ulSessionCount = 0;
	pInfo->ulRwSessionCount = 0;

	if (g_sessions[slotID].active) {
		pInfo->ulSessionCount = 1;
		if (g_sessions[slotID].session_info.flags & CKF_RW_SESSION) {
			pInfo->ulRwSessionCount = 1;
		}
	}

	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	pInfo->ulMinPinLen = 6;
	pInfo->ulMaxPinLen = MAX_PIN_LEN;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	UNUSED(slotID);
	UNUSED(pMechanismList);
	UNUSED(pulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	UNUSED(slotID);
	UNUSED(type);
	UNUSED(pInfo);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	UNUSED(slotID);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pLabel);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(pPin);
	UNUSED(ulPinLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	UNUSED(hSession);
	UNUSED(pOldPin);
	UNUSED(ulOldLen);
	UNUSED(pNewPin);
	UNUSED(ulNewLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	UNUSED(pApplication);

	VALID_PTR_CHECK(phSession);

	if (NULL != Notify) {
		// no callbacks supported
		return CKR_ARGUMENTS_BAD;
	}

	if (!(flags & CKF_SERIAL_SESSION)) {
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	}

	VALID_SLOT_CHECK(slotID);

	g_sessions[slotID].active = 1;
	g_sessions[slotID].objects = 0;

	g_sessions[slotID].session_info.slotID = slotID;
	g_sessions[slotID].session_info.flags = flags;
	g_sessions[slotID].session_info.state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	g_sessions[slotID].session_info.ulDeviceError = 0;

	*phSession = (CK_SESSION_HANDLE)slotID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	VALID_SESSION_CHECK(hSession);

	C_Logout(hSession);
	memset(&g_sessions[hSession], 0, sizeof(g_sessions[hSession]));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	UNUSED(slotID);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	VALID_PTR_CHECK(pInfo);

	VALID_SESSION_CHECK(hSession);

	memcpy(pInfo, &g_sessions[hSession].session_info, sizeof(CK_SESSION_INFO));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(pulOperationStateLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(ulOperationStateLen);
	UNUSED(hEncryptionKey);
	UNUSED(hAuthenticationKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV retval;
	int validated;

	VALID_SESSION_CHECK(hSession);

	if (userType != CKU_USER) {
		// only user PIN supported
		return CKR_USER_TYPE_INVALID;
	}

	if (ulPinLen > MAX_PIN_LEN) {
		return CKR_ARGUMENTS_BAD;
	}

	validated = verify_pin82(g_sessions[hSession].session_info.slotID, (BYTE)ulPinLen, pPin);

	if (validated) {
		g_sessions[hSession].session_info.state |= (CK_STATE)1; // PUBLIC -> USER
		retval = CKR_OK;
	} else {
		retval = CKR_PIN_INCORRECT;
	}

	return retval;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	VALID_SESSION_CHECK(hSession);

	unverify_pin82(g_sessions[hSession].session_info.slotID);

	g_sessions[hSession].session_info.state &= ~((CK_STATE)1); // USER -> PUBLIC

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV retval = CKR_ATTRIBUTE_VALUE_INVALID;

	CK_OBJECT_CLASS cls = CKO_VENDOR_DEFINED;
	CK_BBOOL token = CK_FALSE;
	CK_BBOOL priv = CK_FALSE;
	void *contents = NULL;
	CK_ULONG length = 0;

	VALID_SESSION_CHECK(hSession);

	VALID_PTR_CHECK(pTemplate);
	VALID_PTR_CHECK(phObject);

	// check if PrivDO3 already exists and fail (to prevent accidental overwrite)
	if (get_privdo3(g_sessions[hSession].session_info.slotID, NULL, 0) > 0) {
		return CKR_DEVICE_MEMORY;
	}

	// parse template
	for (CK_ULONG k = 0; k < ulCount; k++) {
		if (NULL == pTemplate[k].pValue) {
			continue;
		}
		switch (pTemplate[k].type) {
		case CKA_CLASS:
			cls = *((CK_OBJECT_CLASS*)pTemplate[k].pValue);
			break;
		case CKA_TOKEN:
			token = *((CK_BBOOL*)pTemplate[k].pValue);
			break;
		case CKA_PRIVATE:
			priv = *((CK_BBOOL*)pTemplate[k].pValue);
			break;
		case CKA_VALUE:
			contents = pTemplate[k].pValue;
			length = pTemplate[k].ulValueLen;
			break;
		}
	}

	if ((CKO_DATA == cls) && token && priv) {
		if (put_privdo3(g_sessions[hSession].session_info.slotID, contents, length)) {
			*phObject = MAGIC_OBJECT_NUM;
			retval = CKR_OK;
		} else {
			retval = CKR_FUNCTION_FAILED;
		}
	}

	return retval;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phNewObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV retval = CKR_DEVICE_ERROR;

	VALID_SESSION_CHECK(hSession);
	VALID_OBJECT_CHECK(hObject);

	// delete by writing a 0-length DO
	if (put_privdo3(g_sessions[hSession].session_info.slotID, NULL, 0)) {
		retval = CKR_OK;
	}

	return retval;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pulSize);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

static void internal_copy_attr(CK_ATTRIBUTE_PTR pAttr, const void* value, const CK_ULONG len)
{
	if (NULL == pAttr->pValue) {
		pAttr->ulValueLen = len;
	} else if (pAttr->ulValueLen >= len) {
		memcpy(pAttr->pValue, value, len);
		pAttr->ulValueLen = len;
	} else {
		pAttr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
	}
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV retval = CKR_OK;
	BYTE privdo3_contents[MAX_DO_SIZE];
	int privdo3_len;

	VALID_PTR_CHECK(pTemplate);

	VALID_SESSION_CHECK(hSession);
	VALID_OBJECT_CHECK(hObject);

	for (CK_ULONG k = 0; k < ulCount; k++) {

		const CK_BBOOL private = CK_TRUE;
		const char label[] = OBJECT_NAME;

		switch (pTemplate[k].type) {
		case CKA_PRIVATE:
			internal_copy_attr(&pTemplate[k], &private, sizeof(CK_BBOOL));
			break;
		case CKA_LABEL:
			internal_copy_attr(&pTemplate[k], label, strlen(label) + 1);
			break;
		case CKA_VALUE:
			privdo3_len = get_privdo3(g_sessions[hSession].session_info.slotID, privdo3_contents, sizeof(privdo3_contents));
			if (privdo3_len >= 0) {
				internal_copy_attr(&pTemplate[k], privdo3_contents, privdo3_len);
			} else {
				retval = CKR_DEVICE_ERROR;
			}
			break;
		default:
			pTemplate[k].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			break;
		}
	}

	SECURE_WIPE(privdo3_contents, sizeof(privdo3_contents));

	return retval;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_OBJECT_CLASS cls = CKO_DATA;

	int priv_do3_len;

	VALID_SESSION_CHECK(hSession);

	if (pTemplate != NULL) {
		for (ULONG k = 0; k < ulCount; k++) {
			switch (pTemplate[k].type) {
			case CKA_CLASS:
				cls = *((CK_OBJECT_CLASS*)pTemplate[k].pValue);
				break;
			}
		}
	}

	priv_do3_len = get_privdo3(g_sessions[hSession].session_info.slotID, NULL, 0);
	// only return PrivDO3 if it exists (with a size > 0)
	g_sessions[hSession].objects = ((cls == CKO_DATA) && (priv_do3_len > 0)) ? 1 : 0;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	VALID_SESSION_CHECK(hSession);

	VALID_PTR_CHECK(phObject);
	VALID_PTR_CHECK(pulObjectCount);

	if ((ulMaxObjectCount > 0) && (g_sessions[hSession].objects > 0)) {
		phObject[0] = MAGIC_OBJECT_NUM;
		*pulObjectCount = 1;
		g_sessions[hSession].objects--;
	} else {
		*pulObjectCount = 0;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	VALID_SESSION_CHECK(hSession);

	g_sessions[hSession].objects = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pEncryptedData);
	UNUSED(pulEncryptedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastEncryptedPart);
	UNUSED(pulLastEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedData);
	UNUSED(ulEncryptedDataLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastPart);
	UNUSED(pulLastPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	UNUSED(hSession);
	UNUSED(pMechanism);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pPublicKeyTemplate);
	UNUSED(ulPublicKeyAttributeCount);
	UNUSED(pPrivateKeyTemplate);
	UNUSED(ulPrivateKeyAttributeCount);
	UNUSED(phPublicKey);
	UNUSED(phPrivateKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hWrappingKey);
	UNUSED(hKey);
	UNUSED(pWrappedKey);
	UNUSED(pulWrappedKeyLen);
	
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hUnwrappingKey);
	UNUSED(pWrappedKey);
	UNUSED(ulWrappedKeyLen);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hBaseKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	UNUSED(hSession);
	UNUSED(pSeed);
	UNUSED(ulSeedLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	UNUSED(hSession);
	UNUSED(RandomData);
	UNUSED(ulRandomLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	UNUSED(flags);
	UNUSED(pSlot);
	UNUSED(pReserved);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pInterfacesList)
	{
		*pulCount = 2;
	}
	else
	{
		if (*pulCount < 2)
			return CKR_BUFFER_TOO_SMALL;

		pInterfacesList[0].pInterfaceName = openpgp_pkcs11_2_40_interface.pInterfaceName;
		pInterfacesList[0].pFunctionList = openpgp_pkcs11_2_40_interface.pFunctionList;
		pInterfacesList[0].flags = openpgp_pkcs11_2_40_interface.flags;

		pInterfacesList[1].pInterfaceName = openpgp_pkcs11_3_0_interface.pInterfaceName;
		pInterfacesList[1].pFunctionList = openpgp_pkcs11_3_0_interface.pFunctionList;
		pInterfacesList[1].flags = openpgp_pkcs11_3_0_interface.flags;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	if (NULL == ppInterface)
		return CKR_ARGUMENTS_BAD;

	if (flags != 0)
	{
		*ppInterface = NULL;
		return CKR_OK;
	}

	if (NULL != pInterfaceName)
	{
		const char* requested_interface_name = (const char*)pInterfaceName;
		const char* supported_interface_name = "PKCS 11";

		if (strlen(requested_interface_name) != strlen(supported_interface_name) || 0 != strcmp(requested_interface_name, supported_interface_name))
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	if (NULL != pVersion)
	{
		if (pVersion->major == openpgp_pkcs11_2_40_functions.version.major && pVersion->minor == openpgp_pkcs11_2_40_functions.version.minor)
		{
			*ppInterface = &openpgp_pkcs11_2_40_interface;
			return CKR_OK;
		}
		else if (pVersion->major == openpgp_pkcs11_3_0_functions.version.major && pVersion->minor == openpgp_pkcs11_3_0_functions.version.minor)
		{
			*ppInterface = &openpgp_pkcs11_3_0_interface;
			return CKR_OK;
		}
		else
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	*ppInterface = &openpgp_pkcs11_3_0_interface;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pUsername);
	UNUSED(ulUsernameLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pPlaintext);
	UNUSED(ulPlaintextLen);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pPlaintextPart);
	UNUSED(ulPlaintextPartLen);
	UNUSED(pCiphertextPart);
	UNUSED(pulCiphertextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(pPlaintext);
	UNUSED(pulPlaintextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pCiphertextPart);
	UNUSED(ulCiphertextPartLen);
	UNUSED(pPlaintextPart);
	UNUSED(pulPlaintextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}
