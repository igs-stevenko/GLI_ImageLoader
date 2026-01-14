// GLIProtectTest.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>
#include <windows.h>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <tbs.h>
#include <ncrypt.h>
#include <commctrl.h>
#include <thread>
#include "hasp_api.h"
#include "qxteeprom.h"
#include "libqsys.h"

#define TPM_CC_CREATE        0x00000153
#define TPM_CC_LOAD          0x00000157
#define TPM_CC_UNSEAL        0x0000015E

#define CARDKEYNAME "IGSCardKey"

#define UPDATE_PERCENT (WM_APP + 1)

#pragma warning(disable:4996)
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int MountPartition(unsigned char* key) {

	int rtn = 0;
	char cmd[512];
	sprintf(cmd,
		"\"C:\\VeraCrypt\\VeraCrypt-x64.exe\" "
		"/v C:\\KO\\igs.img "
		"/l X "
		"/p %s "
		"/q /s /m rm",
		key   // 密碼直接塞進來
	);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	// 用 CreateProcess 執行
	BOOL ok = CreateProcessA(
		NULL,
		cmd,            // 你的指令
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (!ok) {
		printf("CreateProcess failed, error=%d\n", GetLastError());
		return 1;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeProcess(pi.hProcess, &exitCode);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	printf("VeraCrypt exit code = %lu\n", exitCode);

	return 0;
}



int WriteToEEProm(unsigned char* DataBuf, int DataLen) {

	int rtn = 0;

	qxt_eeprom_handle_t my_handle = EEPROM_HANDLE_INIT;
	qxt_memory_handle_t my_mem = MEMORY_HANDLE_INIT;
	qxt_eeprom_desc_t scanning_desc = EEPROM_DESC_NULL;

	// Passing the initialized handle to Open function in order to get a
	// valid handle if no error occurs
	if (qxtEepromOpen(&my_handle))
	{
		puts("Error opening protected eeprom library");
		return -1;
	}

	qxt_eeprom_desc_t selected_desc = EEPROM_DESC_NULL;
	uint32_t addr, channel;
	addr = 0x56;
	channel = 0;
	char found = 0;

	while (qxtEepromScan(my_handle, &selected_desc) == 0)
	{
		if (selected_desc.device_addr == addr && selected_desc.device_channel == channel)
		{
			found = 1;
			break;
		}
	}

	if (!found)
	{
		puts("Device not found");
		return -2;
	}

	// Get exclusive access to device
	if (qxtEepromSelect(my_handle, &selected_desc, &my_mem))
	{
		puts("Error on selecting device");
		return -3;
	}

	for (int i = 0; i < DataLen; i++) {
		int addr_of_interest = i;
		int value = DataBuf[i];
		if (qxtEepromWrite(my_mem, addr_of_interest, &value, 1))
		{
			puts("Error while writing on device");
			rtn = -4;
			break;
		}
	}


	// Close the handle
	if (qxtEepromClose(my_handle))
	{
		puts("Error on libI2cClose");
		//rtn = -5;
	}

	return rtn;
}

int ReadFromEEProm(unsigned char* DataBuf, int DataLen) {

	int rtn = 0;

	qxt_eeprom_handle_t my_handle = EEPROM_HANDLE_INIT;
	qxt_memory_handle_t my_mem = MEMORY_HANDLE_INIT;

	// Passing the initialized handle to Open function in order to get a
	// valid handle if no error occurs
	if (qxtEepromOpen(&my_handle))
	{
		puts("Error opening protected eeprom library");
		return -1;
	}

	qxt_eeprom_desc_t selected_desc = EEPROM_DESC_NULL;
	uint32_t addr, channel;


	addr = 0x56;
	channel = 0;

	char found = 0;
	while (qxtEepromScan(my_handle, &selected_desc) == 0)
	{
		if (selected_desc.device_addr == addr && selected_desc.device_channel == channel)
		{
			found = 1;
			break;
		}
	}

	if (!found)
	{
		puts("Device not found");
		return -2;
	}

	// Get exclusive access to device
	if (qxtEepromSelect(my_handle, &selected_desc, &my_mem))
	{
		puts("Error on selecting device");
		return -3;
	}

	uint8_t read_value = 0;


	for (int i = 0; i < DataLen; i++) {
		if (qxtEepromRead(my_mem, i, &read_value, 1))
		{
			printf("Error while reading the device memory at address %#02x\n", i);
			rtn = -4;
			break;
		}

		DataBuf[i] = read_value;
	}


	// Close the handle
	if (qxtEepromClose(my_handle))
	{
		puts("Error on libI2cClose");
		//rtn = -5;
	}

	return rtn;
}


#define CHUNK 4096  // 每次處理4KB，可自由調整

int aes_encrypt_file(const char* in_file, const char* out_file,
	const unsigned char key[16], const unsigned char iv[16])
{
	FILE* fin = fopen(in_file, "rb");
	if (!fin) return 0;

	FILE* fout = fopen(out_file, "wb");
	if (!fout) {
		fclose(fin);
		return 0;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return 0;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		return 0;

	unsigned char in_buf[CHUNK];
	unsigned char out_buf[CHUNK + 16];   // CBC 會多出最大1個block

	int in_len = 0, out_len = 0;

	while ((in_len = fread(in_buf, 1, CHUNK, fin)) > 0)
	{
		if (!EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len))
			return 0;

		fwrite(out_buf, 1, out_len, fout);
	}

	// Final block (padding)
	if (!EVP_EncryptFinal_ex(ctx, out_buf, &out_len))
		return 0;

	fwrite(out_buf, 1, out_len, fout);

	EVP_CIPHER_CTX_free(ctx);
	fclose(fin);
	fclose(fout);

	return 1;
}

int aes_decrypt_file(const char* in_file, const char* out_file,
	const unsigned char key[16], const unsigned char iv[16])
{
	FILE* fin = fopen(in_file, "rb");
	if (!fin) return 0;

	/*
	FILE* fout = fopen(out_file, "wb");
	if (!fout) {
		fclose(fin);
		return 0;
	}
	*/

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return 0;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		return 0;

	unsigned char in_buf[CHUNK];
	unsigned char out_buf[CHUNK + 16];

	int in_len = 0, out_len = 0;

	while ((in_len = fread(in_buf, 1, CHUNK, fin)) > 0)
	{
		if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len))
			return 0;

		//fwrite(out_buf, 1, out_len, fout);
	}

	// Final block (remove padding)
	if (!EVP_DecryptFinal_ex(ctx, out_buf, &out_len))
		return 0;

	//fwrite(out_buf, 1, out_len, fout);

	EVP_CIPHER_CTX_free(ctx);
	fclose(fin);
	//fclose(fout);

	return 1;
}

void Aes128Encrypt_Test(void) {

	unsigned char key[16] =
	{
		0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
		0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00
	};

	unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };


	printf("Encrypting file...\n");
	if (!aes_encrypt_file("input.bin", "encrypted.bin", key, iv))
		printf("Encrypt failed\n");
	else
		printf("Encrypt OK\n");

}

void Aes128Decrypt_Test(void) {

	unsigned char key[16] =
	{
		0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
		0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00
	};

	unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };

	printf("Decrypting file...\n");
	if (!aes_decrypt_file("encrypted.bin", "decrypted.bin", key, iv))
		printf("Decrypt failed\n");
	else
		printf("Decrypt OK\n");
}

int aes256_encrypt_file(const char* in_file, const char* out_file,
	const unsigned char key[32], const unsigned char iv[16])
{
	FILE* fin = fopen(in_file, "rb");
	if (!fin) return 0;

	FILE* fout = fopen(out_file, "wb");
	if (!fout) {
		fclose(fin);
		return 0;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return 0;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return 0;

	unsigned char in_buf[CHUNK];
	unsigned char out_buf[CHUNK + 16]; // CBC padding 最多多 1 block
	int in_len = 0, out_len = 0;

	while ((in_len = fread(in_buf, 1, CHUNK, fin)) > 0)
	{
		if (!EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len))
			return 0;

		fwrite(out_buf, 1, out_len, fout);
	}

	if (!EVP_EncryptFinal_ex(ctx, out_buf, &out_len))
		return 0;

	fwrite(out_buf, 1, out_len, fout);

	EVP_CIPHER_CTX_free(ctx);
	fclose(fin);
	fclose(fout);

	return 1;
}

// AES-256-CBC 解密檔案
int aes256_decrypt_file(const char* in_file,
	const unsigned char key[32], const unsigned char iv[16])
{
	FILE* fin = fopen(in_file, "rb");
	if (!fin) return -1;


	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -2;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return -3;

	unsigned char in_buf[CHUNK];
	unsigned char out_buf[CHUNK + 16];
	int in_len = 0, out_len = 0;

	while ((in_len = fread(in_buf, 1, CHUNK, fin)) > 0)
	{
		if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len))
			return -4;
	}

	if (!EVP_DecryptFinal_ex(ctx, out_buf, &out_len))
		return -5;

	EVP_CIPHER_CTX_free(ctx);
	fclose(fin);

	return 0;
}

int aes256_decrypt_file_and_write(const char* in_file, const char* out_file,
	const unsigned char key[32], const unsigned char iv[16])
{
	FILE* fin = fopen(in_file, "rb");
	if (!fin) return 0;


	FILE* fout = fopen(out_file, "wb");
	if (!fout) {
		fclose(fin);
		return 0;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return 0;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return 0;

	unsigned char in_buf[CHUNK];
	unsigned char out_buf[CHUNK + 16];
	int in_len = 0, out_len = 0;

	while ((in_len = fread(in_buf, 1, CHUNK, fin)) > 0)
	{
		if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len))
			return 0;

		fwrite(out_buf, 1, out_len, fout);
	}

	if (!EVP_DecryptFinal_ex(ctx, out_buf, &out_len))
		return 0;

	fwrite(out_buf, 1, out_len, fout);

	EVP_CIPHER_CTX_free(ctx);
	fclose(fin);
	fclose(fout);

	return 0;
}

int Aes256Encrypt_Test(void) {

	unsigned char key[32] =
	{
		0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
		0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x12
	};

	unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };


	printf("Encrypting...\n");
	if (!aes256_encrypt_file("input.bin", "encrypt_aes256.bin", key, iv)) {
		return -1;
	}
	else {
		return 0;
	}

}

int Aes256Decrypt_Test(void) {

	int rtn = 0;

	unsigned char key[32] =
	{
		0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
		0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x12
	};

	unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	printf("Decrypting...\n");
	rtn = aes256_decrypt_file_and_write("encrypt_aes256.bin","dec.bin", key, iv);
	if (rtn != 0) {
		printf("Decrypt failed, rtn = %d\n", rtn);
		return -1;
	}
	else {
		printf("Decrypt OK\n");
		return 0;
	}
}

TBS_HCONTEXT hContext;

BOOL TpmInit()
{
	TBS_CONTEXT_PARAMS2 params = { };
	params.version = TBS_CONTEXT_VERSION_TWO;
	params.includeTpm20 = 1;

	return Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&params, &hContext) == TBS_SUCCESS;
}

void TpmClose()
{
	if (hContext)
		Tbsip_Context_Close(hContext);
}

// ========================================================
// Step 1: TPM2_CreatePrimary
// ========================================================
DWORD CreatePrimary(UINT32* primaryHandle, BYTE* outPub, UINT16* outPubLen)
{
	BYTE cmd[1024], rsp[1024];
	UINT32 cmdLen = 0, rspLen = sizeof(rsp);

	BYTE header[] = {
		0x80,0x02,
		0x00,0x00,0x00,0x00,
		0x00,0x00,0x01,0x31,      // TPM_CC_CreatePrimary
		0x40,0x00,0x00,0x0B       // TPM_RH_OWNER
	};
	memcpy(cmd, header, sizeof(header));
	cmdLen = sizeof(header);

	// Auth Area: no auth
	cmd[cmdLen++] = 0x00; cmd[cmdLen++] = 0x00;

	// SensitiveCreate empty
	BYTE sens[] = {
		0x00,0x04,    // size
		0x00,0x00,    // userAuth.size
		0x00,0x00     // data.size
	};
	memcpy(&cmd[cmdLen], sens, sizeof(sens));
	cmdLen += sizeof(sens);

	// Public Area: RSA 2048, no authPolicy
	BYTE publicTemplate[] = {
		0x00,0x3A,          // size = 58
		0x00,0x01,          // type = RSA
		0x00,0x0B,          // nameAlg = SHA256
		0x00,0x00,0x00,0x10,// objectAttributes = decrypt
		0x00,0x00,          // authPolicy size=0

		// RSA params
		0x00,0x10,          // scheme = NULL
		0x00,0x00,          // hashAlg unused
		0x08,0x00,          // keyBits 2048
		0x00,0x00,0x00,0x00,// exponent

		// unique
		0x00,0x00
	};
	memcpy(&cmd[cmdLen], publicTemplate, sizeof(publicTemplate));
	cmdLen += sizeof(publicTemplate);

	// OutsideInfo empty
	cmd[cmdLen++] = 0x00; cmd[cmdLen++] = 0x00;

	// PCR selection empty
	BYTE pcrSel[] = { 0x00,0x00,0x00 };
	memcpy(&cmd[cmdLen], pcrSel, sizeof(pcrSel));
	cmdLen += sizeof(pcrSel);

	// fill commandSize
	cmd[2] = cmdLen >> 24;
	cmd[3] = cmdLen >> 16;
	cmd[4] = cmdLen >> 8;
	cmd[5] = cmdLen;

	DWORD r = Tbsip_Submit_Command(
		hContext, TBS_COMMAND_LOCALITY_ZERO,
		TBS_COMMAND_PRIORITY_NORMAL,
		cmd, cmdLen,
		rsp, &rspLen
	);

	printf("===== CreatePrimary Response (%u bytes) =====\n", rspLen);
	for (UINT32 i = 0; i < rspLen; i++) {
		printf("%02X ", rsp[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n=============================================\n");

	if (rspLen < 14) return 0xFFFFFFFF;

	// responseCode @ 6..9
	UINT32 rc =
		(rsp[6] << 24) | (rsp[7] << 16) | (rsp[8] << 8) | rsp[9];

	if (rc != 0) {
		printf("TPM_RC = %08X\n", rc);
		return rc;
	}

	UINT32 pos = 10;

	*primaryHandle =
		(rsp[pos] << 24) | (rsp[pos + 1] << 16) | (rsp[pos + 2] << 8) | rsp[pos + 3];
	pos += 4;

	UINT16 nameSize = (rsp[pos] << 8) | rsp[pos + 1];
	pos += 2 + nameSize;

	UINT16 pubSize = (rsp[pos] << 8) | rsp[pos + 1];
	pos += 2;

	memcpy(outPub, &rsp[pos], pubSize);
	*outPubLen = pubSize;

	printf("PrimaryHandle = %08X\n", *primaryHandle);
	printf("PublicArea size = %u bytes\n", *outPubLen);

	return 0;
}


// 混合 Key 和 UUID 產生 SessionKey (SHA-256)
void Derive_Session_Key(const unsigned char* RawKey, int KeyLen,
	const char* UUID,
	unsigned char* OutSessionKey) {

	// 1. 準備 Buffer: RawKey + UUID
	std::vector<unsigned char> mixBuffer;

	// 放入 RawKey
	mixBuffer.insert(mixBuffer.end(), RawKey, RawKey + KeyLen);

	// 放入 UUID
	if (UUID) {
		int uuidLen = strlen(UUID);
		mixBuffer.insert(mixBuffer.end(), UUID, UUID + uuidLen);
	}

	// 2. 計算 SHA-256
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, mixBuffer.data(), mixBuffer.size());
	SHA256_Final(OutSessionKey, &sha256);
}

// 記憶體對記憶體 ChaCha20 解密
int ChaCha20_Decrypt_Buffer(unsigned char* ciphertext, int len, unsigned char* plaintext, 
                            const unsigned char key[32], const unsigned char nonce[12]) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (!EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce)) {
		EVP_CIPHER_CTX_free(ctx);
		return -2;
	}

	int outLen = 0;
	if (!EVP_DecryptUpdate(ctx, plaintext, &outLen, ciphertext, len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -3;
	}

	// ChaCha20 is a stream cipher, so Final usually doesn't output anything, but good practice to call
	int finalLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, plaintext + outLen, &finalLen)) {
		EVP_CIPHER_CTX_free(ctx);
		return -4;
	}

	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int ChaCha20_enc() {

	int rtn = 0;

	static unsigned char KEY[32] = {
	0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
	0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x01,
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
	0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x02
	};

	unsigned char nonce[12] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	};


	const char* inputFile = "input.bin";
	const char* outputFile = "encrypt_chacha.bin";

	//--- Step 1: 讀取整個檔案 ---
	std::ifstream fin(inputFile, std::ios::binary);
	if (!fin) {
		std::cout << "無法開啟來源檔案 input.bin\n";
		return -1;
	}

	std::ofstream fout(outputFile, std::ios::binary);
	if (!fout) {
		std::cout << "無法建立 encrypt_chacha.bin\n";
		return -1;
	}
	// ==== 初始化 ChaCha20 ====
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, KEY, nonce);

	const size_t BUF_SIZE = 64 * 1024; // 64KB buffer
	unsigned char inBuf[BUF_SIZE];
	unsigned char outBuf[BUF_SIZE + 16];

	while (true) {
		fin.read((char*)inBuf, BUF_SIZE);
		std::streamsize bytesRead = fin.gcount();
		if (bytesRead <= 0)
			break;

		int outLen = 0;
		EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, (int)bytesRead);
		fout.write((char*)outBuf, outLen);
	}

	EVP_CIPHER_CTX_free(ctx);

	fin.close();
	fout.close();

	std::cout << "串流加密完成！輸出檔案：encrypt.bin\n";

	return rtn;
}


int ChaCha20_dec() {

	int rtn = 0;
	static unsigned char KEY[32] = {
	0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
	0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x01,
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
	0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x02
	};

	unsigned char nonce[12] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	};

	const char* inputFile = "encrypt_chacha.bin";
	const char* outputFile = "decrypt.bin";

	std::ifstream fin(inputFile, std::ios::binary);
	if (!fin) {
		std::cout << "無法開啟 encrypt_chacha.bin\n";
		return -1;
	}


	// === 初始化 ChaCha20 解密（ChaCha20 解密與加密相同 API）===
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, KEY, nonce);

	const size_t BUF_SIZE = 64 * 1024; // 64KB buffer
	unsigned char inBuf[BUF_SIZE];
	unsigned char outBuf[BUF_SIZE + 16];

	while (true) {
		fin.read((char*)inBuf, BUF_SIZE);
		std::streamsize bytesRead = fin.gcount();
		if (bytesRead <= 0)
			break;

		int outLen = 0;
		EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, (int)bytesRead);
	}

	EVP_CIPHER_CTX_free(ctx);

	fin.close();

	return rtn;
}



int ChaCha20_dec_and_write() {

	int rtn = 0;
	static unsigned char KEY[32] = {
	0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
	0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x01,
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
	0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x02
	};

	unsigned char nonce[12] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	};

	const char* inputFile = "encrypt_chacha.bin";
	const char* outputFile = "decrypt.bin";

	std::ifstream fin(inputFile, std::ios::binary);
	if (!fin) {
		std::cout << "無法開啟 encrypt_chacha.bin\n";
		return -1;
	}

	std::ofstream fout(outputFile, std::ios::binary);
	if (!fout) {
		std::cout << "無法建立 decrypt.bin\n";
		return -1;
	}

	// === 初始化 ChaCha20 解密（ChaCha20 解密與加密相同 API）===
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, KEY, nonce);

	const size_t BUF_SIZE = 64 * 1024; // 64KB buffer
	unsigned char inBuf[BUF_SIZE];
	unsigned char outBuf[BUF_SIZE + 16];

	while (true) {
		fin.read((char*)inBuf, BUF_SIZE);
		std::streamsize bytesRead = fin.gcount();
		if (bytesRead <= 0)
			break;

		int outLen = 0;
		EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, (int)bytesRead);
		fout.write((char*)outBuf, outLen);
	}

	EVP_CIPHER_CTX_free(ctx);

	fin.close();
	fout.close();

	return rtn;
}

int ChaCha20_enc_file_custom(const char* inputFile, const char* outputFile,
	const unsigned char* key, const unsigned char* nonce) {
	std::ifstream fin(inputFile, std::ios::binary);
	if (!fin) {
		std::cout << "無法開啟 " << inputFile << "\n";
		return -1;
	}

	std::ofstream fout(outputFile, std::ios::binary);
	if (!fout) {
		std::cout << "無法建立 " << outputFile << "\n";
		return -1;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);

	const size_t BUF_SIZE = 64 * 1024;
	unsigned char inBuf[BUF_SIZE];
	unsigned char outBuf[BUF_SIZE + 16];

	while (true) {
		fin.read((char*)inBuf, BUF_SIZE);
		std::streamsize bytesRead = fin.gcount();
		if (bytesRead <= 0)
			break;

		int outLen = 0;
		EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, (int)bytesRead);
		fout.write((char*)outBuf, outLen);
	}

	EVP_CIPHER_CTX_free(ctx);
	fin.close();
	fout.close();

	return 0;
}

int ChaCha20_dec_file_custom(const char* inputFile, const char* outputFile, 
                             const unsigned char* key, const unsigned char* nonce) {
	std::ifstream fin(inputFile, std::ios::binary);
	if (!fin) {
		std::cout << "無法開啟 " << inputFile << "\n";
		return -1;
	}

	std::ofstream fout(outputFile, std::ios::binary);
	if (!fout) {
		std::cout << "無法建立 " << outputFile << "\n";
		return -1;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);

	const size_t BUF_SIZE = 64 * 1024; 
	unsigned char inBuf[BUF_SIZE];
	unsigned char outBuf[BUF_SIZE + 16];

	while (true) {
		fin.read((char*)inBuf, BUF_SIZE);
		std::streamsize bytesRead = fin.gcount();
		if (bytesRead <= 0)
			break;

		int outLen = 0;
		EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, (int)bytesRead);
		fout.write((char*)outBuf, outLen);
	}

	EVP_CIPHER_CTX_free(ctx);
	fin.close();
	fout.close();

	return 0;
}


int WriteToFile(const char* filename, unsigned char* buf, int len) {

	int rtn = 0;

	FILE* fout = fopen(filename, "wb");
	if (!fout) {
		printf("fopen %s error\n", filename);
		return -1;
	}
	rtn = fwrite(buf, 1, len, fout);
	if (rtn != len) {
		printf("Write file error\n");
		rtn = -1;
	}
	else {
		printf("Write file OK\n");
		rtn = 0;
	}

	if (fout)	fclose(fout);

	return rtn;
}

int ReadFromFile(const char* filename, unsigned char* buf, int len) {

	int rtn = 0;
	FILE* fin = fopen(filename, "rb");
	if (!fin) return -1;

	rtn = fread(buf, 1, len, fin);
	if (rtn != len) {
		rtn = -1;
	}
	else {
		rtn = 0;
	}

	return rtn;
}


int TPMSetRSAKey(const char* KeyName) {

	int rtn = 0;

	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;

	wchar_t nameW[128] = { 0x00 };
	mbstowcs(nameW, KeyName, strlen(KeyName) + 1);


	// Step 1: 打開 TPM 金鑰儲存提供者
	status = NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,   // 使用 TPM
		0);
	if (status != ERROR_SUCCESS) {
		printf("Open provider failed: 0x%X\n", status);
		return -1;
	}


	// Step 2: TPM 內建立 2048-bit RSA 金鑰（不可匯出私鑰）
	status = NCryptCreatePersistedKey(
		hProv,
		&hKey,
		NCRYPT_RSA_ALGORITHM,
		nameW,       // 若你希望永久儲存可用名稱
		0,
		NCRYPT_OVERWRITE_KEY_FLAG);
	if (status != ERROR_SUCCESS) {
		printf("Create key failed: 0x%X\n", status);
		return -2;
	}

	// 設定金鑰長度 2048 bits
	DWORD keyLen = 2048;
	status = NCryptSetProperty(
		hKey, NCRYPT_LENGTH_PROPERTY,
		(BYTE*)&keyLen, sizeof(DWORD), 0);

	// 完成金鑰建立（由 TPM生成）
	status = NCryptFinalizeKey(hKey, 0);
	if (status != ERROR_SUCCESS) {
		printf("Finalize key failed: 0x%X\n", status);
		return -3;
	}

	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);

	return rtn;
}

int TPMUseKeyEnc(const char* KeyName, BYTE* DataIn, DWORD DataInLen, BYTE* DataOut, DWORD* DataOutLen) {

	int rtn = 0;

	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	wchar_t nameW[128] = { 0x00 };
	mbstowcs(nameW, KeyName, strlen(KeyName) + 1);

	// Step 1: 打開 TPM 金鑰儲存提供者
	status = NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,   // 使用 TPM
		0);
	if (status != ERROR_SUCCESS) {
		printf("Open provider failed: 0x%X\n", status);
		return -1;
	}


	status = NCryptOpenKey(
		hProv,
		&hKey,
		nameW,   // ⚡ 你建立金鑰時的名稱
		0,
		0);

	if (status != ERROR_SUCCESS) {
		printf("Open key failed: 0x%X\n", status);
		return -2;
	}


	// Step 2: 使用 TPM RSA 公鑰加密 AES Key
	status = NCryptEncrypt(
		hKey,
		DataIn, DataInLen,
		NULL,
		DataOut, *DataOutLen,
		DataOutLen,
		NCRYPT_PAD_PKCS1_FLAG);      // 使用 RSA PKCS#1 padding
	if (status != ERROR_SUCCESS) {
		printf("Encrypt failed: 0x%X\n", status);
		return -3;
	}

	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);

	return rtn;
}


int TPMUseKeyDec(const char* KeyName, BYTE* DataIn, DWORD DataInLen, BYTE* DataOut, DWORD* DataOutLen) {

	int rtn = 0;

	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	wchar_t nameW[128] = { 0x00 };
	mbstowcs(nameW, KeyName, strlen(KeyName) + 1);

	BYTE decrypted[256];
	DWORD decryptedSize = sizeof(decrypted);

	// Step 1: 打開 TPM 金鑰儲存提供者
	status = NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,   // 使用 TPM
		0);
	if (status != ERROR_SUCCESS) {
		printf("Open provider failed: 0x%X\n", status);
		return -1;
	}


	status = NCryptOpenKey(
		hProv,
		&hKey,
		nameW,   // ⚡ 你建立金鑰時的名稱
		0,
		0);

	if (status != ERROR_SUCCESS) {
		printf("Open key failed: 0x%X\n", status);
		return -2;
	}

	// Step 4: 使用 TPM RSA 私鑰解密（私鑰在 TPM 內）

	status = NCryptDecrypt(
		hKey,
		DataIn, DataInLen,
		NULL,
		DataOut, *DataOutLen,
		DataOutLen,
		NCRYPT_PAD_PKCS1_FLAG);

	if (status != ERROR_SUCCESS) {
		printf("Decrypt failed: 0x%X\n", status);
		return -3;
	}

	NCryptFreeObject(hKey);
	NCryptFreeObject(hProv);

	return rtn;
}

int TPMGetPubKey(const char* KeyName, BYTE* pubKey, DWORD* pubKeySize) {

	int rtn = 0;

	NCRYPT_KEY_HANDLE hKey = 0;
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv = 0;
	wchar_t nameW[128] = { 0x00 };
	mbstowcs(nameW, KeyName, strlen(KeyName) + 1);

	status = NCryptOpenStorageProvider(
		&hProv,
		MS_PLATFORM_CRYPTO_PROVIDER,   // 使用 TPM
		0);
	if (status != ERROR_SUCCESS) {
		printf("Open provider failed: 0x%X\n", status);
		return -1;
	}


	status = NCryptOpenKey(
		hProv,
		&hKey,
		nameW,   // ⚡ 你建立金鑰時的名稱
		0,
		0);

	if (status != ERROR_SUCCESS) {
		printf("Open key failed: 0x%X\n", status);
		return -2;
	}


	status = NCryptExportKey(
		hKey,                // TPM RSA key handle (from NCryptOpenKey)
		0,                   // no export key
		BCRYPT_RSAPUBLIC_BLOB, // Export RSA public blob
		NULL,                // no parameters
		pubKey,
		*pubKeySize,
		pubKeySize,
		0);

	if (status == ERROR_SUCCESS) {
		printf("Public Key Exported, size=%u bytes.\n", *pubKeySize);
	}
	else {
		printf("Public Key Exported failed: 0x%X\n", status);
		rtn = -3;
	}

	return rtn;
}

static bool GenerateRandomBytes(BYTE* buffer, DWORD size)
{
	NTSTATUS status = BCryptGenRandom(
		NULL,           // Use system RNG
		buffer,
		size,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	return (status == 0);
}

int TPMChallengeResponse(BYTE* PubKey, DWORD PubKeyLen) {

	int rtn = 0;

	NTSTATUS status;
	BCRYPT_KEY_HANDLE hPubKey = NULL;
	BCRYPT_ALG_HANDLE hAlg = NULL;

	printf("PubKeyLen = %d\n", PubKeyLen);


	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if (status != 0) {
		printf("Open RSA provider failed: 0x%X\n", status);
		return -1;
	}

	status = BCryptImportKeyPair(
		hAlg,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		&hPubKey,
		PubKey,
		PubKeyLen,
		0);

	if (status != 0) {
		printf("Import public key failed: 0x%X\n", status);
		return -1;
	}

	BYTE challenge[32];
	if (!GenerateRandomBytes(challenge, sizeof(challenge))) {
		printf("Failed to generate random bytes.\n");
	}

	printf("challenge data :\n");
	for (DWORD i = 0; i < sizeof(challenge); i++) {
		if (i % 16 == 0)	printf("\n");
		printf("%02X ", challenge[i]);
	}
	printf("\n");


	BYTE encrypted[512];
	DWORD encryptedSize = 0;

	status = BCryptEncrypt(
		hPubKey,
		challenge,
		sizeof(challenge),
		NULL,                // PKCS1 padding → NULL
		NULL, 0,             // no IV
		encrypted, sizeof(encrypted),
		&encryptedSize,
		BCRYPT_PAD_PKCS1);

	if (status != 0) {
		printf("RSA Encrypt failed: 0x%X\n", status);
		return -1;
	}


	BYTE DataOut[256] = { 0x00 };
	DWORD DataOutLen = sizeof(DataOut);;

	rtn = TPMUseKeyDec(CARDKEYNAME, encrypted, encryptedSize, DataOut, &DataOutLen);
	if (rtn != 0) {
		printf("TPMUseKeyDec error: %d\n", rtn);
	}
	else {
		printf("TPMUseKeyDec OK\n");
		printf("Decrypted Data (%u bytes): ", DataOutLen);
		for (DWORD i = 0; i < DataOutLen; i++) {
			printf("%02X ", DataOut[i]);
		}
		printf("\n");
	}


	return rtn;
}

int ReadRegValue(const char* RegName, const char* ValName, DWORD* Val, DWORD* ValLen) {

	int rtn = 0;

	HKEY hKey;
	LONG status;
	DWORD value = 0;
	DWORD valueSize = sizeof(value);
	DWORD type = 0;

	status = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		RegName,
		0,
		KEY_READ,
		&hKey
	);

	if (status != ERROR_SUCCESS) {
		printf("RegOpenKeyExA failed: %ld\n", status);
		return -1;
	}

	status = RegQueryValueExA(
		hKey,
		ValName,
		NULL,
		&type,
		(LPBYTE)&value,
		&valueSize
	);

	if (!(status == ERROR_SUCCESS && type == REG_DWORD)) {
		printf("RegQueryValueEx failed: %ld\n", status);
		rtn = -2;
	}

	RegCloseKey(hKey);

	return rtn;
}

// ------------------------
// CRC32 計算函式
// ------------------------
uint32_t crc32(const uint8_t* data, size_t length) {
	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0; i < length; i++) {
		crc ^= data[i];

		for (int j = 0; j < 8; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
	}

	return ~crc;
}

void print_hex(unsigned char* buf, int len) {

	int i = 0;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)	printf("\n");
		printf("0x%02x, ", buf[i]);
	}
}

int ReadFromKeypro_Get(unsigned char* outBuf) {

	int rtn = 0;
	hasp_status_t status = HASP_STATUS_OK;

	hasp_feature_t feature_id = 60001;
	unsigned char vendor_code[] =
		"eApZw4pLQubJE71z6zkRH18zzQEebtatmnG4GEgoATapsLUtlFGGeq61r1dQt9BW3jVKSTkr7FhwoiqK"
		"1D3MvmNxzHLX79ycT/bBk1wd+15On+nXoI9mBvRRo6igEsR7lBzsKywK1O2devo/qnzXr5YH5vDXhoJa"
		"WJErCH/gmzejKHuaARWAo7dPrl6z4hhBFbmhWdDFyk7sxO9I+XVStaVjDNRXypBkczGfjsnYOPFjIZx4"
		"F/mIn09BBQ8bCjnnj7C1SYvGXGgM8zzxjo40Aj2wB/JFRhAf4xnCiCLAPtBmtBpN4BEMWBuKtqVHYAvk"
		"1PpWpOWJ30WOK5hwFXayzUMuaETtfZgwHKAMgzADxKSfg1QDlgFhehp098GuJu94IR1D5YHIIChdCWvW"
		"Fn0cezcmErPRqlXJ6Pn22VE7E+LRd58zpm2mhnql4jF3ncFAaFTzwpzMTIqI3VPOBRCHFeQ0GoXQs65J"
		"FJW3EShyrN4oTq6deZ8Jn11cGwJ6DPepQrTRllXfg+1qzN2+S8KuZ6B2Do+gzgnLnzj3uDiYK7p2eCMT"
		"oWTjO2hZypTFa46lzl3Drs7bA5wP6H9j1tuHzxpFi07q4bnGCF3JXOGFRp4TeTk5YNh/4A4DiDXesiWh"
		"wNWuI7dGEYpoKpfuMPLuKYQeZ5h1u3/48rGFwOK0zazk/zeRZL3NbCpoCMFuRh8Pg6GTArv52tMY9yqz"
		"640avx7sr64BEd3RU8Zc+P/wYT2YvHIVmrXPnUGzTiiNgZf6sUcORkzqj//Kl+bEQWqPMcpZn8VIeOHt"
		"+vxbo4jstn/rBmgyWu51gsw21DthaTb3SYCs/fmope07EDK0pOSh/MUFqdGQN4dtbwPFFZQ991UlNYf4"
		"eGuQiED7V7+IPpcItvPj6+nzM809J2sShrVN1cStbltYRPveVRL1UhZtW8dLPNvVllIV1B9UaFzMv8Nf"
		"2vmr6LFnIveLiYwN71s4Lg==";

	hasp_handle_t handle;
	unsigned char DataBuf[8] = { 0x00 };

	status = hasp_login(feature_id, vendor_code, &handle);
	if (status != HASP_STATUS_OK) {
		printf("hasp_login failed: %d\n", status);
		return -1;
	}

	status = hasp_read(handle, HASP_FILEID_RO, 0, sizeof(DataBuf), DataBuf);
	if (status != HASP_STATUS_OK) {
		printf("hasp_read failed: %d\n", status);
		return -2;
	}

	if (outBuf) {
		memcpy(outBuf, DataBuf, sizeof(DataBuf));
	}

	hasp_logout(handle);
	return rtn;
}

int ReadFromKeypro() {

	int rtn = 0;
	hasp_status_t status = HASP_STATUS_OK;

	hasp_feature_t feature_id = 60001;
	unsigned char vendor_code[] =
		"eApZw4pLQubJE71z6zkRH18zzQEebtatmnG4GEgoATapsLUtlFGGeq61r1dQt9BW3jVKSTkr7FhwoiqK"
		"1D3MvmNxzHLX79ycT/bBk1wd+15On+nXoI9mBvRRo6igEsR7lBzsKywK1O2devo/qnzXr5YH5vDXhoJa"
		"WJErCH/gmzejKHuaARWAo7dPrl6z4hhBFbmhWdDFyk7sxO9I+XVStaVjDNRXypBkczGfjsnYOPFjIZx4"
		"F/mIn09BBQ8bCjnnj7C1SYvGXGgM8zzxjo40Aj2wB/JFRhAf4xnCiCLAPtBmtBpN4BEMWBuKtqVHYAvk"
		"1PpWpOWJ30WOK5hwFXayzUMuaETtfZgwHKAMgzADxKSfg1QDlgFhehp098GuJu94IR1D5YHIIChdCWvW"
		"Fn0cezcmErPRqlXJ6Pn22VE7E+LRd58zpm2mhnql4jF3ncFAaFTzwpzMTIqI3VPOBRCHFeQ0GoXQs65J"
		"FJW3EShyrN4oTq6deZ8Jn11cGwJ6DPepQrTRllXfg+1qzN2+S8KuZ6B2Do+gzgnLnzj3uDiYK7p2eCMT"
		"oWTjO2hZypTFa46lzl3Drs7bA5wP6H9j1tuHzxpFi07q4bnGCF3JXOGFRp4TeTk5YNh/4A4DiDXesiWh"
		"wNWuI7dGEYpoKpfuMPLuKYQeZ5h1u3/48rGFwOK0zazk/zeRZL3NbCpoCMFuRh8Pg6GTArv52tMY9yqz"
		"640avx7sr64BEd3RU8Zc+P/wYT2YvHIVmrXPnUGzTiiNgZf6sUcORkzqj//Kl+bEQWqPMcpZn8VIeOHt"
		"+vxbo4jstn/rBmgyWu51gsw21DthaTb3SYCs/fmope07EDK0pOSh/MUFqdGQN4dtbwPFFZQ991UlNYf4"
		"eGuQiED7V7+IPpcItvPj6+nzM809J2sShrVN1cStbltYRPveVRL1UhZtW8dLPNvVllIV1B9UaFzMv8Nf"
		"2vmr6LFnIveLiYwN71s4Lg==";

	hasp_handle_t handle;
	unsigned char DataBuf[8] = { 0x00 };

	status = hasp_login(feature_id, vendor_code, &handle);
	if (status != HASP_STATUS_OK) {
		printf("hasp_login failed: %d\n", status);
		return -1;
	}

	status = hasp_read(handle, HASP_FILEID_RO, 0, sizeof(DataBuf), DataBuf);
	if (status != HASP_STATUS_OK) {
		printf("hasp_read failed: %d\n", status);
		return -2;
	}

	printf("Read Data: ");
	print_hex(DataBuf, sizeof(DataBuf));

	hasp_logout(handle);

	return rtn;
}

int KeyproEncAndDec() {

	int rtn = 0;
	hasp_status_t status = HASP_STATUS_OK;

	hasp_feature_t feature_id = 60001;
	unsigned char vendor_code[] =
		"eApZw4pLQubJE71z6zkRH18zzQEebtatmnG4GEgoATapsLUtlFGGeq61r1dQt9BW3jVKSTkr7FhwoiqK"
		"1D3MvmNxzHLX79ycT/bBk1wd+15On+nXoI9mBvRRo6igEsR7lBzsKywK1O2devo/qnzXr5YH5vDXhoJa"
		"WJErCH/gmzejKHuaARWAo7dPrl6z4hhBFbmhWdDFyk7sxO9I+XVStaVjDNRXypBkczGfjsnYOPFjIZx4"
		"F/mIn09BBQ8bCjnnj7C1SYvGXGgM8zzxjo40Aj2wB/JFRhAf4xnCiCLAPtBmtBpN4BEMWBuKtqVHYAvk"
		"1PpWpOWJ30WOK5hwFXayzUMuaETtfZgwHKAMgzADxKSfg1QDlgFhehp098GuJu94IR1D5YHIIChdCWvW"
		"Fn0cezcmErPRqlXJ6Pn22VE7E+LRd58zpm2mhnql4jF3ncFAaFTzwpzMTIqI3VPOBRCHFeQ0GoXQs65J"
		"FJW3EShyrN4oTq6deZ8Jn11cGwJ6DPepQrTRllXfg+1qzN2+S8KuZ6B2Do+gzgnLnzj3uDiYK7p2eCMT"
		"oWTjO2hZypTFa46lzl3Drs7bA5wP6H9j1tuHzxpFi07q4bnGCF3JXOGFRp4TeTk5YNh/4A4DiDXesiWh"
		"wNWuI7dGEYpoKpfuMPLuKYQeZ5h1u3/48rGFwOK0zazk/zeRZL3NbCpoCMFuRh8Pg6GTArv52tMY9yqz"
		"640avx7sr64BEd3RU8Zc+P/wYT2YvHIVmrXPnUGzTiiNgZf6sUcORkzqj//Kl+bEQWqPMcpZn8VIeOHt"
		"+vxbo4jstn/rBmgyWu51gsw21DthaTb3SYCs/fmope07EDK0pOSh/MUFqdGQN4dtbwPFFZQ991UlNYf4"
		"eGuQiED7V7+IPpcItvPj6+nzM809J2sShrVN1cStbltYRPveVRL1UhZtW8dLPNvVllIV1B9UaFzMv8Nf"
		"2vmr6LFnIveLiYwN71s4Lg==";

	hasp_handle_t handle;
	unsigned char PlainText[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	unsigned char CipherText[16] = { 0x00 };

	status = hasp_login(feature_id, vendor_code, &handle);
	if (status != HASP_STATUS_OK) {
		printf("hasp_login failed: %d\n", status);
		return -1;
	}

	status = hasp_encrypt(handle, PlainText, sizeof(PlainText));
	if (status != HASP_STATUS_OK) {
		printf("hasp_encrypt failed: %d\n", status);
		return -2;
	}

	memcpy(CipherText, PlainText, sizeof(PlainText));
	memset(PlainText, 0, sizeof(PlainText));

	printf("EncData :\n");
	print_hex(CipherText, sizeof(CipherText));

	status = hasp_decrypt(handle, CipherText, sizeof(CipherText));
	if (status != HASP_STATUS_OK) {
		printf("hasp_decrypt failed: %d\n", status);
		return -3;
	}

	memcpy(PlainText, CipherText, sizeof(CipherText));
	memset(CipherText, 0, sizeof(CipherText));


	printf("\nDecData :\n");
	print_hex(PlainText, sizeof(PlainText));

	hasp_logout(handle);

	return rtn;
}

HWND hWnd;
HWND hProgress;
HWND hLabel;
int progressValue = 0;


void InitProgressBar(HWND hWnd)
{
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&icex);

	hProgress = CreateWindowEx(
		0, PROGRESS_CLASS, NULL,
		WS_CHILD | WS_VISIBLE,
		20, 20, 300, 25,
		hWnd, NULL, GetModuleHandle(NULL), NULL
	);

	SendMessage(hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
	SendMessage(hProgress, PBM_SETPOS, 0, 0);

	// 百分比文字 Label，在進度條下面
	hLabel = CreateWindowExW(
		0, L"STATIC", L"0%",
		WS_CHILD | WS_VISIBLE | SS_CENTER,
		20, 50, 300, 20,
		hWnd, nullptr, GetModuleHandleW(nullptr), nullptr
	);
}

// UI thread 的 WindowProc
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
		InitProgressBar(hWnd);
		return 0;

	case UPDATE_PERCENT:   // 背景 thread 來的訊息
	{
		int percent = (int)wParam;
		if (percent < 0) percent = 0;
		if (percent > 100) percent = 100;

		SendMessageW(hProgress, PBM_SETPOS, percent, 0);

		wchar_t buf[16];
		swprintf(buf, 16, L"%d%%", percent);
		SetWindowTextW(hLabel, buf);

		// ★ 收到 100% 時（UI 控制後續動作）
		if (percent == 100) {
			// 例如關閉視窗
			DestroyWindow(hWnd);

			// 或發訊息給主程式
			// PostMessageW(hWnd, WM_APP + 2, 0, 0);
		}

		return 0;
	}

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void SetProgress(HWND hWnd, int percent)
{
	if (percent < 0) percent = 0;
	if (percent > 100) percent = 100;

	PostMessageW(hWnd, UPDATE_PERCENT, percent, 0);
}

int GetLabelSerialNumber(unsigned char* SerialNumber, int* Len) {

	int rtn = 0;

	QRESULT ret_code;
	HANDLE h;
	HANDLE hquery;
	char reg_exp[256] = {
	".*/Silver Label"
	//"/QSYS/HW/Core/Logging Processor/Silver Label"
	};

	ret_code = qsysOpen(&h);
	if (ret_code != 0) {
		return -1;
	}

	ret_code = qsysMakeQuery(h, reg_exp, &hquery);
	if (ret_code != 0) {
		qsysClose(h);
		return -2;
	}

	char key[256] = { 0 };
	char value[256] = { 0 };

	ret_code = qsysFirstEntry(hquery, key, 256, value, 256);
	if (ret_code != 0) {
		qsysClose(h);
		return -3;
	}

	memcpy(SerialNumber, value, strlen(value));
	*Len = strlen(value);

	qsysClose(h);

	return rtn;
}


int GetScreenUUID(unsigned char *ScreenUUID) {

	int rtn = 0;
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hRead = NULL, hWrite = NULL;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	char buffer[4096];
	DWORD bytesRead;
	DWORD total = 0;

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	// 建立 pipe
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		printf("CreatePipe failed\n");
		return 1;
	}

	// 讀取端不能被子行程繼承
	SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;   // 錯誤也一起抓
	si.hStdInput = NULL;

	char cmd[512] =
		"cmd.exe /c powershell -NoProfile -Command \""
		"Get-WmiObject -Namespace root\\wmi -Class WmiMonitorID | ForEach-Object { "
		"$mfg = ($_.ManufacturerName | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join '' ; "
		"$sn  = ($_.SerialNumberID  | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) -join '' ; "
		"if ($mfg -and $sn) { \\\"$mfg-$sn\\\" } "
		"} | Sort-Object\"";

	if (!CreateProcessA(
		NULL,
		cmd,
		NULL,
		NULL,
		TRUE,   // ⭐ 必須 TRUE，才能繼承 pipe
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi)) {

		printf("CreateProcess failed (%lu)\n", GetLastError());
		return 1;
	}

	// 父程序不需要寫入端
	CloseHandle(hWrite);

	// 讀取 PowerShell 輸出
	while (ReadFile(hRead, buffer + total,
		sizeof(buffer) - total - 1,
		&bytesRead, NULL) && bytesRead > 0) {
		total += bytesRead;
	}

	buffer[total] = '\0';

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(hRead);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// ⭐ 最終字串結果
	//printf("Monitor ID Result:\n%s\n", buffer);
	memcpy(ScreenUUID, buffer, strlen(buffer));

	return 0;
}


void Usage(void) {

	std::cout << "用法:\n";
	std::cout << "  ImageLoader.exe -a : Use key mount disk partition\n";
	std::cout << "  ImageLoader.exe -b : Write Data to EEProm\n";
	std::cout << "  ImageLoader.exe -c : Read Data to EEProm\n";
	std::cout << "  ImageLoader.exe -d : Read File and Encrypt by AES256\n";
	std::cout << "  ImageLoader.exe -e : Read File and Decrypt by AES256\n";
	std::cout << "  ImageLoader.exe -f : Read File and Encrypt by ChaCha20\n";
	std::cout << "  ImageLoader.exe -F <file> <keyfile> : Encrypt specific file by ChaCha20 using key from file\n";
	std::cout << "  ImageLoader.exe -g : Read File and Decrypt by ChaCha20\n";
	std::cout << "  ImageLoader.exe -G <file> <keyfile> : Decrypt specific file by ChaCha20 using key from file\n";
	std::cout << "  ImageLoader.exe -h : Generate TPM RSA Keys\n";
	std::cout << "  ImageLoader.exe -i : Encrypt by TPM RSA\n";
	std::cout << "  ImageLoader.exe -j : Decrypt by TPM RSA\n";
	std::cout << "  ImageLoader.exe -k : Get TPM RSA Public Key\n";
	std::cout << "  ImageLoader.exe -l : TPM C/R\n";
	std::cout << "  ImageLoader.exe -m : Read HID.\n";
	std::cout << "  ImageLoader.exe -n : CRC32 Compute time\n";
	std::cout << "  ImageLoader.exe -o : Read from Keypro\n";
	std::cout << "  ImageLoader.exe -p : Keypro Encrpyt Data and Decrypt\n";
	std::cout << "  ImageLoader.exe -q : Run the Progress Bar\n";
	std::cout << "  ImageLoader.exe -r : Get Label Serial Number\n";
	std::cout << "  ImageLoader.exe -1 <file> : Encrypt specific file (Bind to UUID)\n";
	std::cout << "  ImageLoader.exe -2 <file> : Decrypt specific file (Verify UUID Binding)\n";
	std::cout << "  ImageLoader.exe -z : Run Auto-Decryption Workflow (Keypro->UUID->EEPROM->DecFile)\n";
}

std::string g_InputFilename;
std::string g_KeyFilename;

void WorkerThread(unsigned char cmd)
{
	printf("WorkerThread Start\n");

	int rtn = 0;

	switch (cmd) {
	
	case 'a':
	{
		unsigned char key[] = "igsrd";
		MountPartition(key);
		break;
	}

	case 'b':
	{
		unsigned char DataBuf[16] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
		};

		rtn = WriteToEEProm(DataBuf, sizeof(DataBuf));
		if (rtn != 0) {
			printf("WriteToEEProm error: %d\n", rtn);
		}
		else {
			printf("WriteToEEProm OK\n");
		}
		break;
	}
	case 'c':
	{
		unsigned char DataBuf[16] = { 0x00 };
		rtn = ReadFromEEProm(DataBuf, sizeof(DataBuf));
		if (rtn != 0) {
			printf("ReadFromEEProm error: %d\n", rtn);
		}
		else {
			printf("ReadFromEEProm OK\n");
			printf("Data: ");
			for (int i = 0; i < sizeof(DataBuf); i++) {
				printf("%02X ", DataBuf[i]);
			}
			printf("\n");
		}
		break;
	}
	case 'd':
	{
		rtn = Aes256Encrypt_Test();
		if (rtn != 0) {
			printf("Aes256Encrypt_Test error: %d\n", rtn);
		}
		else {
			printf("Aes256Encrypt_Test OK\n");
		}
		break;
	}
	case 'e':
	{
		DWORD t1 = GetTickCount64();
		rtn = Aes256Decrypt_Test();
		DWORD t2 = GetTickCount64();
		if (rtn != 0) {
			printf("Aes256Decrypt_Test error: %d\n", rtn);
		}
		else {
			printf("Aes256Decrypt_Test OK\n");
			printf("Decrypt time: %llu ms\n", (unsigned long long)(t2 - t1));
		}
		break;
	}
	case 'f':
	{
		rtn = ChaCha20_enc();
		if (rtn != 0) {
			printf("ChaCha20_enc error: %d\n", rtn);
		}
		else {
			printf("ChaCha20_enc OK\n");
		}

		break;
	}
	case 'F':
	{
		printf("Encrypting file: %s\n", g_InputFilename.c_str());
		printf("Using Key file: %s\n", g_KeyFilename.c_str());
		
		unsigned char KEY[32] = { 0 };
		if (ReadFromFile(g_KeyFilename.c_str(), KEY, 32) != 0) {
			printf("Error reading key file (must be at least 32 bytes).\n");
			break;
		}

		unsigned char nonce[12] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
		};

		std::string outFile = g_InputFilename + ".enc";
		if (ChaCha20_enc_file_custom(g_InputFilename.c_str(), outFile.c_str(), KEY, nonce) == 0) {
			printf("Success! Output: %s\n", outFile.c_str());
		} else {
			printf("Encryption Failed!\n");
		}
		break;
	}
	case 'g':
	{
		DWORD t1 = GetTickCount64();
		rtn = ChaCha20_dec_and_write();
		DWORD t2 = GetTickCount64();
		if (rtn != 0) {
			printf("ChaCha20_dec_and_write error: %d\n", rtn);
		}
		else {
			printf("ChaCha20_dec_and_write OK\n");
			printf("Decrypt time: %llu ms\n", (unsigned long long)(t2 - t1));
		}


		break;
	}
	case 'G':
	{
		printf("Decrypting file: %s\n", g_InputFilename.c_str());
		printf("Using Key file: %s\n", g_KeyFilename.c_str());

		unsigned char KEY[32] = { 0 };
		if (ReadFromFile(g_KeyFilename.c_str(), KEY, 32) != 0) {
			printf("Error reading key file (must be at least 32 bytes).\n");
			break;
		}

		unsigned char nonce[12] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
		};

		std::string outFile = g_InputFilename + ".dec";
		if (ChaCha20_dec_file_custom(g_InputFilename.c_str(), outFile.c_str(), KEY, nonce) == 0) {
			printf("Success! Output: %s\n", outFile.c_str());
		}
		else {
			printf("Decryption Failed!\n");
		}
		break;
	}
	case 'h':
	{
		rtn = TPMSetRSAKey(CARDKEYNAME);
		if (rtn != 0) {
			printf("TPMSetRSAKey error: %d\n", rtn);
		}
		else {
			printf("TPMSetRSAKey OK\n");
		}

		break;
	}
	case 'i':
	{
		BYTE DataIn[32] = {
			0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
			0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x01,
			0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
			0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x02
		};
		BYTE DataOut[256] = { 0x00 };
		DWORD DataInLen = sizeof(DataIn);
		DWORD DataOutLen = sizeof(DataOut);;

		rtn = TPMUseKeyEnc(CARDKEYNAME, DataIn, DataInLen, DataOut, &DataOutLen);
		if (rtn != 0) {
			printf("TPMUseKeyEnc error: %d\n", rtn);
		}
		else {
			printf("TPMUseKeyEnc OK\n");
			printf("Encrypted Data (%u bytes): ", DataOutLen);
			for (DWORD i = 0; i < DataOutLen; i++) {
				printf("%02X ", DataOut[i]);
			}
			printf("\n");
		}

		break;
	}
	case 'j':
	{
		BYTE DataIn[] = {
			0x93,0x0F,0x05,0x7F,0xA5,0xD8,0xB3,0x82,0xAE,0xDC,0x1F,0xF0,0xF5,0x53,0x25,0x11,0x6B,0x78,0xAA,0x76,0x37,0x77,0xE2,0xB6,0x06,0x3B,0xA0,0xB9,0x40,0x26,0x56,0xDE,0xBC,0xFB,0x04,0xEA,0x44,0x1E,0x6F,0xC1,0x99,0xC2,0x14,0x83,0xA2,0x1B,0x85,0xA0,0xDD,0xFB,0x76,0xB0,0x1D,0x4D,0xA3,0x7E,0x95,0x15,0x10,0x65,0x66,0x3A,0x4A,0x1E,0xC2,0x4A,0xD6,0x0A,0x28,0xC8,0x27,0x7F,0x03,0x58,0xBE,0xDF,0x8D,0xA0,0xFE,0x33,0xC7,0xE7,0x93,0x89,0x12,0x22,0x44,0x3C,0x58,0x9A,0x49,0x88,0x6F,0xAC,0xE5,0x4D,0x16,0xCD,0x7C,0x6A,0x8F,0x65,0xF1,0x2F,0xAA,0x98,0x46,0x89,0x77,0x24,0x26,0xE4,0x29,0xB5,0xAC,0xD8,0xD8,0xBC,0x01,0xD6,0x87,0x2A,0x48,0x4B,0x6B,0xD1,0x45,0x40,0x5B,0x82,0xB8,0xF2,0x42,0x75,0x07,0xA6,0xFA,0xEA,0x46,0x49,0x40,0x15,0x68,0xEA,0x7C,0x85,0x4D,0x1A,0x2C,0x09,0x4A,0x8C,0x76,0xCA,0x7D,0x03,0x34,0xAD,0x58,0x82,0xCB,0x11,0x4E,0x9A,0xF8,0x94,0xA6,0xF6,0x6A,0x8E,0x60,0xBC,0x0D,0x5E,0x32,0x6C,0x67,0xB2,0x19,0x91,0x8C,0xBD,0x6C,0xB8,0x5E,0x2A,0xAF,0x68,0x20,0x4B,0xD6,0x3F,0x3E,0x94,0x01,0xF2,0x6B,0x27,0x88,0x33,0x16,0x27,0xB6,0x9B,0x6B,0xA0,0xAF,0xDE,0x3B,0x5A,0xE0,0xDB,0xD4,0x53,0xA9,0x58,0x99,0x43,0x6A,0x33,0x66,0x3F,0xBC,0x68,0x07,0x9A,0xF6,0xAE,0x2F,0xA8,0xBD,0x2E,0x3E,0xA2,0x1E,0x8C,0xF7,0x25,0xAC,0x83,0x5D,0x67,0x23,0x87,0x7D,0xCB,0x71,0xBA,0x9F,0x25,0x1D,0x22,0x4E,0xD7,0x10,0x83
		};
		BYTE DataOut[256] = { 0x00 };
		DWORD DataInLen = sizeof(DataIn);
		DWORD DataOutLen = sizeof(DataOut);;

		rtn = TPMUseKeyDec(CARDKEYNAME, DataIn, DataInLen, DataOut, &DataOutLen);
		if (rtn != 0) {
			printf("TPMUseKeyDec error: %d\n", rtn);
		}
		else {
			printf("TPMUseKeyDec OK\n");
			printf("Decrypted Data (%u bytes): ", DataOutLen);
			for (DWORD i = 0; i < DataOutLen; i++) {
				printf("%02X ", DataOut[i]);
			}
			printf("\n");
		}

		break;
	}
	case 'k':
	{
		BYTE PubKey[512] = { 0x00 };
		DWORD PubKeyLen = sizeof(PubKey);

		rtn = TPMGetPubKey(CARDKEYNAME, PubKey, &PubKeyLen);
		if (rtn != 0) {
			printf("TPMGetPubKey error: %d\n", rtn);
		}
		else {
			printf("TPMGetPubKey OK\n");
			printf("Public Key (%u bytes): ", PubKeyLen);
			for (DWORD i = 0; i < PubKeyLen; i++) {
				if (i % 16 == 0) printf("\n");
				printf("%02X ", PubKey[i]);
			}
			printf("\n");
		}
		break;
	}
	case 'l':
	{
		BYTE PubKey[] = {
			0x52,0x53,0x41,0x31,0x00,0x08,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0xCB,0x1F,0x1E,0xD0,0x55,
			0x21,0x47,0x6A,0x17,0x36,0xC3,0x16,0x7F,0x22,0x49,0xC9,0x8E,0x78,0x37,0xEB,0xA9,
			0x18,0xF8,0xA5,0xF3,0x9D,0x76,0x32,0x7A,0xB2,0x33,0x38,0x18,0xC7,0xFC,0xFD,0x59,
			0x58,0x42,0x27,0x6F,0xA5,0xF8,0xC1,0xC2,0x3D,0x02,0x41,0xEE,0xFD,0x42,0x09,0xB1,
			0xFB,0x8F,0x15,0x6A,0x68,0xBC,0xB5,0x7F,0xDF,0x1C,0x4B,0xA1,0x06,0x99,0x7F,0x16,
			0xD7,0xF0,0x36,0x93,0xB8,0x1D,0x39,0x77,0x09,0x75,0xB2,0x9C,0x5F,0xFF,0x31,0x53,
			0xA3,0x27,0xBA,0xC6,0x13,0x2B,0xDC,0x3B,0x3D,0x5D,0x88,0x9F,0x99,0xAE,0x4E,0x41,
			0x92,0x29,0x19,0x95,0x41,0xC2,0xD2,0xD2,0x47,0x24,0x7F,0x7E,0x15,0x22,0xD9,0xF5,
			0xAB,0x21,0x94,0x3D,0xC1,0xB7,0x84,0xA9,0x53,0x6E,0xAA,0x3F,0x60,0xAF,0x9C,0x56,
			0xA8,0x98,0x26,0xE3,0x80,0x7C,0xEF,0xD2,0xE0,0x49,0x17,0xAB,0xF1,0xDF,0x6C,0xDD,
			0xE6,0xC8,0xD4,0x02,0x9C,0x0A,0xB3,0x18,0x40,0xC4,0x7C,0xA9,0x8D,0x8D,0x81,0x27,
			0x10,0xD5,0x5D,0xBC,0x47,0x10,0x79,0x50,0x4D,0x51,0x8E,0x5A,0x66,0xC5,0xCE,0x7D,
			0xE2,0x5E,0x5D,0x65,0xCA,0x3A,0xF9,0xBA,0x95,0xF6,0x06,0x76,0x70,0xA2,0x05,0xDB,
			0x56,0xAA,0x25,0x65,0x07,0xEB,0x50,0x8F,0xC4,0xEE,0xAE,0x9A,0xC2,0xF5,0x8D,0x9A,
			0x43,0xF0,0x57,0x41,0xE2,0x80,0x9C,0x3A,0xEF,0xA1,0x5E,0x2C,0xE2,0xAB,0xF3,0x8F,
			0xA4,0x29,0x56,0xCE,0x74,0x21,0xDC,0xF3,0xE1,0x1A,0x8D,0x94,0xF7,0x7D,0xB1,0xD5,
			0xD8,0x9E,0x42,0x40,0xA0,0x23,0xEA,0x9D,0xA8,0xD0,0x53
		};
		DWORD PubKeyLen = sizeof(PubKey);

		rtn = TPMChallengeResponse(PubKey, PubKeyLen);
		if (rtn != 0) {
			printf("TPMChallengeResponse error: %d\n", rtn);
		}
		else {
			printf("TPMChallengeResponse OK\n");
		}
		break;
	}
	case 'm':
	{
		DWORD RegVal = 0;
		DWORD RegValSize = sizeof(RegVal);
		DWORD t1 = GetTickCount64();
		rtn = ReadRegValue("SYSTEM\\CurrentControlSet\\Services\\mouhid", "Start", &RegVal, &RegValSize);
		DWORD t2 = GetTickCount64();
		if (rtn != 0) {
			printf("ReadRegValue error: %d\n", rtn);
		}
		else {
			printf("ReadRegValue OK\n");
			printf("RegVal = %u\n", RegVal);
			printf("ReadRegValue time: %llu ms\n", (unsigned long long)(t2 - t1));
		}
		break;
	}
	case 'n':
	{
		uint8_t buffer[32] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 , 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e , 0x0f,
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 , 0x88,
			0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x02,
		};

		DWORD t1 = GetTickCount64();
		uint32_t crc = crc32(buffer, sizeof(buffer));
		DWORD t2 = GetTickCount64();
		printf("CRC32 = 0x%08X (decimal: %u)\n", crc, crc);
		printf("crc32 time: %llu ms\n", (unsigned long long)(t2 - t1));

		break;
	}
	case 'o':
	{
		rtn = ReadFromKeypro();
		if (rtn != 0) {
			printf("ReadFromKeypro error: %d\n", rtn);
		}
		else {
			printf("ReadFromKeypro OK\n");
		}

		break;
	}
	case 'p':
	{
		rtn = KeyproEncAndDec();
		if (rtn != 0) {
			printf("KeyproEncAndDec error: %d\n", rtn);
		}

		break;
	}
	case 'q':
	{
		for (int i = 0; i <= 100; i++) {
			SetProgress(hWnd, i);
			Sleep(1000);
		}
		break;
	}
	case 'r':
	{

		unsigned char SerialNumber[256] = { 0x00 };
		int Len = 0;
		rtn = GetLabelSerialNumber(SerialNumber, &Len);
		if(rtn != 0) {
			printf("GetLabelSerialNumber error: %d\n", rtn);
		}
		else {
			printf("GetLabelSerialNumber OK\n");
			printf("Label Serial Number: ");
			for (int i = 0; i < Len; i++) {
				printf("%c", SerialNumber[i]);
			}
			printf("\n");
		}	


		break;
	}
	case 's':
	{
		unsigned char ScreenUUID[4096] = { 0x00 };
		rtn = GetScreenUUID(ScreenUUID);
		if (rtn != 0) {
			printf("GetScreenUUID error: %d\n", rtn);
		}
		else {
			crc32((const uint8_t* )ScreenUUID, strlen((const char *)ScreenUUID));
			printf("GetScreenUUID OK\n");
			printf("ScreenUUID crc: \n");
			printf("CRC32 = 0x%08X\n", ScreenUUID);
		}
		break;
	}

	case '1':
	{
		printf("=== Encrypt Deck Key (-1) ===\n");
		printf("Input File: %s\n", g_InputFilename.c_str());

		// 1. Prepare Data
		unsigned char RawKey[32] = {
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33
		};

		unsigned char Nonce[12] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
		};

		char RealUUID[256] = { 0 };
		int UUIDLen = 0;

		printf("[TEST MODE] Using Fake UUID for encryption.\n");
		strcpy(RealUUID, "TEST-REAL-UUID-1234");
		/*
		if (GetLabelSerialNumber((unsigned char*)RealUUID, &UUIDLen) != 0) {
			strcpy(RealUUID, "UNKNOWN_UUID");
		}
		*/
		printf("UUID: %s\n", RealUUID);

		// 2. Derive Key
		unsigned char SessionKey[32];
		Derive_Session_Key(RawKey, 32, RealUUID, SessionKey);
		printf("Session Key Derived.\n");

		// 3. Encrypt
		std::string outFile = g_InputFilename + ".enc";
		printf("Encrypting '%s' -> '%s'...\n", g_InputFilename.c_str(), outFile.c_str());
		
		if (ChaCha20_enc_file_custom(g_InputFilename.c_str(), outFile.c_str(), SessionKey, Nonce) == 0) {
			printf("Success.\n");
		}
		else {
			printf("Encryption Failed!\n");
		}
		break;
	}
	case '2':
	{
		printf("=== Decrypt Deck Key (-2) ===\n");
		printf("Input File: %s\n", g_InputFilename.c_str());

		// 1. Prepare Data (Must match Encrypt side)
		unsigned char RawKey[32] = {
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33
		};

		unsigned char Nonce[12] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
		};

		char RealUUID[256] = { 0 };
		int UUIDLen = 0;

		printf("[TEST MODE] Using Fake UUID for decryption.\n");
		strcpy(RealUUID, "TEST-REAL-UUID-1234");
		/*
		if (GetLabelSerialNumber((unsigned char*)RealUUID, &UUIDLen) != 0) {
			strcpy(RealUUID, "UNKNOWN_UUID");
		}
		*/
		printf("UUID: %s\n", RealUUID);

		// 2. Derive Key
		unsigned char SessionKey[32];
		Derive_Session_Key(RawKey, 32, RealUUID, SessionKey);
		printf("Session Key Derived.\n");

		// 3. Decrypt
		std::string outFile = g_InputFilename + ".dec";
		printf("Decrypting '%s' -> '%s'...\n", g_InputFilename.c_str(), outFile.c_str());

		if (ChaCha20_dec_file_custom(g_InputFilename.c_str(), outFile.c_str(), SessionKey, Nonce) == 0) {
			printf("Success.\n");
		}
		else {
			printf("Decryption Failed!\n");
		}
		break;
	}
	case 'z':
	{
		printf("=== Run Auto-Decryption Workflow (-z) ===\n");

		// 1. Get Raw Key (Simulate Reading from Keypro)
		unsigned char RawKey[32] = {
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
			0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33
		};
		printf("Step 1: Keypro Data Loaded (Simulated).\n");

		// 2. Get UUID (Simulate Hardware Read)
		char RealUUID[256] = { 0 };
		strcpy(RealUUID, "TEST-REAL-UUID-1234");
		printf("Step 2: UUID Loaded: %s\n", RealUUID);

		// 3. Derive Session Key
		unsigned char SessionKey[32];
		Derive_Session_Key(RawKey, 32, RealUUID, SessionKey);
		printf("Step 3: Session Key Derived (Hash(Keypro + UUID)).\n");

		// 4. Decrypt Deck Key (mykey.bin.enc) -> Memory
		const char* encKeyFile = "mykey.bin.enc";
		unsigned char DeckKeyEncBuf[32]; // Assuming DeckKey is 32 bytes
		unsigned char DeckKey[32];       // The decrypted DeckKey

		// Read encrypted key file
		if (ReadFromFile(encKeyFile, DeckKeyEncBuf, 32) != 0) {
			printf("Error: Failed to read '%s' (Must be 32 bytes).\n", encKeyFile);
			break;
		}

		// Fixed Nonce (Must match what was used to encrypt mykey.bin.enc in case '1')
		unsigned char Nonce[12] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
		};

		// Decrypt in memory
		if (ChaCha20_Decrypt_Buffer(DeckKeyEncBuf, 32, DeckKey, SessionKey, Nonce) != 0) {
			printf("Error: Failed to decrypt Deck Key.\n");
			break;
		}
		printf("Step 4: Deck Key Decrypted (Held in Memory).\n");

		// 5. Decrypt Content (input.bin.enc) using DeckKey -> final_output.bin
		const char* encContentFile = "input.bin.enc";
		const char* finalOutputFile = "final_output.bin";

		printf("Step 5: Decrypting '%s' -> '%s'...\n", encContentFile, finalOutputFile);
		
		if (ChaCha20_dec_file_custom(encContentFile, finalOutputFile, DeckKey, Nonce) == 0) {
			printf("=== Workflow Success! Output saved to '%s' ===\n", finalOutputFile);
		}
		else {
			printf("Error: Failed to decrypt content file.\n");
		}

		break;
	}
	default:
		Usage();
		break;
	}

}


int main(int argc, char* argv[])
{

	int rtn = 0;
	unsigned cmd = 0;

	if (argc < 2) {
		Usage();
		return 0;
	}

	std::string arg1 = argv[1];
	if (arg1 == "-a") {
		cmd = 'a';
	}
	else if (arg1 == "-b") {
		cmd = 'b';
	}
	else if (arg1 == "-c") {
		cmd = 'c';
	}
	else if (arg1 == "-d") {
		cmd = 'd';
	}
	else if (arg1 == "-e") {
		cmd = 'e';
	}
	else if (arg1 == "-f") {
		cmd = 'f';
	}
	else if (arg1 == "-F") {
		if (argc >= 4) {
			cmd = 'F';
			g_InputFilename = argv[2];
			g_KeyFilename = argv[3];
		}
		else {
			printf("Error: -F requires input filename and key filename.\n");
			Usage();
			return 0;
		}
	}
	else if (arg1 == "-g") {
		cmd = 'g';
	}
	else if (arg1 == "-G") {
		if (argc >= 4) {
			cmd = 'G';
			g_InputFilename = argv[2];
			g_KeyFilename = argv[3];
		}
		else {
			printf("Error: -G requires input filename and key filename.\n");
			Usage();
			return 0;
		}
	}
	else if (arg1 == "-h") {
		cmd = 'h';
	}
	else if (arg1 == "-i") {
		cmd = 'i';
	}
	else if (arg1 == "-j") {
		cmd = 'j';
	}
	else if (arg1 == "-k") {
		cmd = 'k';
	}
	else if (arg1 == "-l") {
		cmd = 'l';
	}
	else if (arg1 == "-m") {
		cmd = 'm';
	}
	else if (arg1 == "-n") {
		cmd = 'n';
	}
	else if (arg1 == "-o") {
		cmd = 'o';
	}
	else if (arg1 == "-p") {
		cmd = 'p';
	}
	else if (arg1 == "-q") {
		cmd = 'q';
	}
	else if (arg1 == "-r") {
		cmd = 'r';
	}
	else if (arg1 == "-1") {
		if (argc >= 3) {
			cmd = '1';
			g_InputFilename = argv[2];
		}
		else {
			printf("Error: -1 requires input filename.\n");
			Usage();
			return 0;
		}
	}
	else if (arg1 == "-2") {
		if (argc >= 3) {
			cmd = '2';
			g_InputFilename = argv[2];
		}
		else {
			printf("Error: -2 requires input filename.\n");
			Usage();
			return 0;
		}
	}
	else if (arg1 == "-z") {
		cmd = 'z';
	}
	else {
		Usage();
		return 0;
	}

	std::thread t(WorkerThread, cmd);
	t.detach();   // 讓 thread 自己跑，不阻塞主程式

	/* 顯示進度條 */
	{
		HINSTANCE hInst = GetModuleHandle(NULL);

		WNDCLASS wc = { 0 };
		wc.lpfnWndProc = WndProc;
		wc.hInstance = hInst;
		wc.lpszClassName = L"MyWin32Window";
		wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

		RegisterClass(&wc);

		hWnd = CreateWindow(
			L"MyWin32Window",
			L"Auto Progress Demo",
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT, CW_USEDEFAULT,
			400, 150,
			NULL, NULL, hInst, NULL
		);

		ShowWindow(hWnd, SW_SHOW);
		UpdateWindow(hWnd);

		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return 0;
}

