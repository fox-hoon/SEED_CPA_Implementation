#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#define _FOLD_ "C:\\"
#define AlignedTraceFN "SEED.traces"
#define PlaintextFN "plaintext.txt"

typedef uint32_t ULONG;
typedef uint8_t UCHAR;

ULONG T;
#define TwoWordLRot(A,B) 				\
		T = A;							\
		A = (A<<8) ^ (B>>24);			\
		B = (B<<8) ^ (T>>24);           \

#define TwoWordRRot(A,B) 				\
		T = A;							\
		A = (A>>8) ^ (B<<24);			\
		B = (B>>8) ^ (T<<24);			\

const UCHAR SEED_S1box[256] = { 0xa9, 0x85, 0xd6, 0xd3, 0x54, 0x1d, 0xac, 0x25, 0x5d, 0x43, 0x18, 0x1e, 0x51, 0xfc, 0xca, 0x63, 0x28, 0x44, 0x20, 0x9d, 0xe0, 0xe2, 0xc8, 0x17, 0xa5, 0x8f, 0x03, 0x7b, 0xbb, 0x13, 0xd2, 0xee, 0x70, 0x8c, 0x3f, 0xa8, 0x32, 0xdd, 0xf6, 0x74, 0xec, 0x95, 0x0b, 0x57, 0x5c, 0x5b, 0xbd, 0x01, 0x24, 0x1c, 0x73, 0x98, 0x10, 0xcc, 0xf2, 0xd9, 0x2c, 0xe7, 0x72, 0x83, 0x9b, 0xd1, 0x86, 0xc9, 0x60, 0x50, 0xa3, 0xeb, 0x0d, 0xb6, 0x9e, 0x4f, 0xb7, 0x5a, 0xc6, 0x78, 0xa6, 0x12, 0xaf, 0xd5, 0x61, 0xc3, 0xb4, 0x41, 0x52, 0x7d, 0x8d, 0x08, 0x1f, 0x99, 0x00, 0x19, 0x04, 0x53, 0xf7, 0xe1, 0xfd, 0x76, 0x2f, 0x27, 0xb0, 0x8b, 0x0e, 0xab, 0xa2, 0x6e, 0x93, 0x4d, 0x69, 0x7c, 0x09, 0x0a, 0xbf, 0xef, 0xf3, 0xc5, 0x87, 0x14, 0xfe, 0x64, 0xde, 0x2e, 0x4b, 0x1a, 0x06, 0x21, 0x6b, 0x66, 0x02, 0xf5, 0x92, 0x8a, 0x0c, 0xb3, 0x7e, 0xd0, 0x7a, 0x47, 0x96, 0xe5, 0x26, 0x80, 0xad, 0xdf, 0xa1, 0x30, 0x37, 0xae, 0x36, 0x15, 0x22, 0x38, 0xf4, 0xa7, 0x45, 0x4c, 0x81, 0xe9, 0x84, 0x97, 0x35, 0xcb, 0xce, 0x3c, 0x71, 0x11, 0xc7, 0x89, 0x75, 0xfb, 0xda, 0xf8, 0x94, 0x59, 0x82, 0xc4, 0xff, 0x49, 0x39, 0x67, 0xc0, 0xcf, 0xd7, 0xb8, 0x0f, 0x8e, 0x42, 0x23, 0x91, 0x6c, 0xdb, 0xa4, 0x34, 0xf1, 0x48, 0xc2, 0x6f, 0x3d, 0x2d, 0x40, 0xbe, 0x3e, 0xbc, 0xc1, 0xaa, 0xba, 0x4e, 0x55, 0x3b, 0xdc, 0x68, 0x7f, 0x9c, 0xd8, 0x4a, 0x56, 0x77, 0xa0, 0xed, 0x46, 0xb5, 0x2b, 0x65, 0xfa, 0xe3, 0xb9, 0xb1, 0x9f, 0x5e, 0xf9, 0xe6, 0xb2, 0x31, 0xea, 0x6d, 0x5f, 0xe4, 0xf0, 0xcd, 0x88, 0x16, 0x3a, 0x58, 0xd4, 0x62, 0x29, 0x07, 0x33, 0xe8, 0x1b, 0x05, 0x79, 0x90, 0x6a, 0x2a, 0x9a };
const UCHAR SEED_S1box_inv[256] = { 0x5a, 0x2f, 0x80, 0x1a, 0x5c, 0xfa, 0x7c, 0xf6, 0x57, 0x6e, 0x6f, 0x2a, 0x84, 0x44, 0x66, 0xb8, 0x34, 0xa5, 0x4d, 0x1d, 0x75, 0x95, 0xf0, 0x17, 0xa, 0x5b, 0x7b, 0xf9, 0x31, 0x5, 0xb, 0x58, 0x12, 0x7d, 0x96, 0xbb, 0x30, 0x7, 0x8c, 0x63, 0x10, 0xf5, 0xfe, 0xdd, 0x38, 0xc6, 0x79, 0x62, 0x91, 0xe8, 0x24, 0xf7, 0xc0, 0xa0, 0x94, 0x92, 0x97, 0xb2, 0xf1, 0xd0, 0xa3, 0xc5, 0xc9, 0x22, 0xc7, 0x53, 0xba, 0x9, 0x11, 0x9a, 0xdb, 0x89, 0xc2, 0xb1, 0xd6, 0x7a, 0x9b, 0x6b, 0xce, 0x47, 0x41, 0xc, 0x54, 0x5d, 0x4, 0xcf, 0xd7, 0x2b, 0xf2, 0xad, 0x49, 0x2d, 0x2c, 0x8, 0xe4, 0xeb, 0x40, 0x50, 0xf4, 0xf, 0x77, 0xde, 0x7f, 0xb3, 0xd2, 0x6c, 0xfd, 0x7e, 0xbd, 0xea, 0x69, 0xc4, 0x20, 0xa4, 0x3a, 0x32, 0x27, 0xa8, 0x61, 0xd8, 0x4b, 0xfb, 0x88, 0x1b, 0x6d, 0x55, 0x86, 0xd3, 0x8d, 0x9c, 0xae, 0x3b, 0x9e, 0x1, 0x3e, 0x74, 0xef, 0xa7, 0x83, 0x65, 0x21, 0x56, 0xb9, 0x19, 0xfc, 0xbc, 0x82, 0x6a, 0xac, 0x29, 0x8a, 0x9f, 0x33, 0x59, 0xff, 0x3c, 0xd4, 0x13, 0x46, 0xe3, 0xd9, 0x90, 0x68, 0x42, 0xbf, 0x18, 0x4c, 0x99, 0x23, 0x0, 0xcc, 0x67, 0x6, 0x8e, 0x93, 0x4e, 0x64, 0xe2, 0xe7, 0x85, 0x52, 0xdc, 0x45, 0x48, 0xb7, 0xe1, 0xcd, 0x1c, 0xca, 0x2e, 0xc8, 0x70, 0xb4, 0xcb, 0xc3, 0x51, 0xaf, 0x73, 0x4a, 0xa6, 0x16, 0x3f, 0xe, 0xa1, 0x35, 0xee, 0xa2, 0xb5, 0x87, 0x3d, 0x1e, 0x3, 0xf3, 0x4f, 0x2, 0xb6, 0xd5, 0x37, 0xaa, 0xbe, 0xd1, 0x25, 0x78, 0x8f, 0x14, 0x5f, 0x15, 0xe0, 0xec, 0x8b, 0xe6, 0x39, 0xf8, 0x9d, 0xe9, 0x43, 0x28, 0xda, 0x1f, 0x71, 0xed, 0xc1, 0x36, 0x72, 0x98, 0x81, 0x26, 0x5e, 0xab, 0xe5, 0xdf, 0xa9, 0xd, 0x60, 0x76, 0xb0 };
const UCHAR SEED_S2box_inv[256] = { 0xd6, 0xb9, 0x6b, 0xa7, 0x6d, 0xb7, 0x1b, 0x70, 0x5a, 0xaf, 0xf6, 0x51, 0x94, 0x36, 0xe8, 0x81, 0xa6, 0x1a, 0xb4, 0x5c, 0xc1, 0xa0, 0x26, 0x24, 0x56, 0xb1, 0x83, 0xce, 0x1c, 0xd3, 0xca, 0x4b, 0x69, 0xcc, 0x6c, 0x8e, 0xf2, 0xd4, 0xeb, 0x3c, 0x30, 0x14, 0xbb, 0x39, 0x4d, 0x2, 0x95, 0x3d, 0xe0, 0x63, 0xec, 0x12, 0x4f, 0xa5, 0x1e, 0xf0, 0x0, 0xea, 0x93, 0xfd, 0xe3, 0x2d, 0x33, 0x2c, 0xb3, 0x42, 0x40, 0xbf, 0xc, 0x29, 0xd7, 0x82, 0xc6, 0x9d, 0xfe, 0x1f, 0xf9, 0x8f, 0x31, 0xd5, 0xe9, 0x79, 0xda, 0xf5, 0xd1, 0xa, 0xbe, 0x58, 0xd9, 0x77, 0x99, 0xf, 0x8a, 0x54, 0xbc, 0xcf, 0x9, 0x74, 0x11, 0x8d, 0xa8, 0xe2, 0x3a, 0x45, 0x6e, 0xee, 0x66, 0xe, 0x22, 0xa9, 0x97, 0xd, 0xa2, 0x6f, 0x3f, 0x44, 0xab, 0xa3, 0xb0, 0xd0, 0x9e, 0xc7, 0x3b, 0x89, 0xe7, 0x61, 0xdc, 0xa4, 0x4a, 0x80, 0xcb, 0xfa, 0xed, 0xc0, 0x5e, 0xf7, 0x21, 0xc2, 0x65, 0x47, 0xcd, 0x86, 0x2e, 0xfb, 0x7a, 0x19, 0x9b, 0xef, 0x55, 0xe1, 0x88, 0xc8, 0x2f, 0x73, 0x7c, 0xc3, 0x92, 0x72, 0x91, 0x98, 0x15, 0x8c, 0x8b, 0x7d, 0xf3, 0x34, 0x3, 0x17, 0x23, 0xbd, 0x4e, 0x7e, 0x46, 0x49, 0x59, 0x8, 0xc4, 0x67, 0xd2, 0x6, 0xad, 0x13, 0xe4, 0xff, 0x7, 0x5f, 0x96, 0xe6, 0x1d, 0xb6, 0x75, 0x87, 0x43, 0x62, 0x28, 0x10, 0x25, 0x5b, 0xaa, 0xb, 0x90, 0xde, 0x4c, 0xf4, 0x9f, 0x5d, 0xfc, 0x4, 0x7f, 0x68, 0x50, 0x18, 0x41, 0xac, 0x2b, 0x6a, 0x38, 0xf8, 0xdd, 0x71, 0x7b, 0x78, 0x5, 0x37, 0xb5, 0x2a, 0x16, 0x84, 0xe5, 0xc5, 0x76, 0xf1, 0x1, 0x53, 0xae, 0xdb, 0x85, 0xd8, 0x52, 0x20, 0xba, 0x3e, 0x9a, 0x9c, 0x27, 0x64, 0x32, 0x48, 0x57, 0x35, 0xb8, 0xa1, 0xc9, 0xdf, 0xb2, 0x60 };
const UCHAR SEED_S2box[256] = { 0x38, 0xe8, 0x2d, 0xa6, 0xcf, 0xde, 0xb3, 0xb8, 0xaf, 0x60, 0x55, 0xc7, 0x44, 0x6f, 0x6b, 0x5b, 0xc3, 0x62, 0x33, 0xb5, 0x29, 0xa0, 0xe2, 0xa7, 0xd3, 0x91, 0x11, 0x06, 0x1c, 0xbc, 0x36, 0x4b, 0xef, 0x88, 0x6c, 0xa8, 0x17, 0xc4, 0x16, 0xf4, 0xc2, 0x45, 0xe1, 0xd6, 0x3f, 0x3d, 0x8e, 0x98, 0x28, 0x4e, 0xf6, 0x3e, 0xa5, 0xf9, 0x0d, 0xdf, 0xd8, 0x2b, 0x66, 0x7a, 0x27, 0x2f, 0xf1, 0x72, 0x42, 0xd4, 0x41, 0xc0, 0x73, 0x67, 0xac, 0x8b, 0xf7, 0xad, 0x80, 0x1f, 0xca, 0x2c, 0xaa, 0x34, 0xd2, 0x0b, 0xee, 0xe9, 0x5d, 0x94, 0x18, 0xf8, 0x57, 0xae, 0x08, 0xc5, 0x13, 0xcd, 0x86, 0xb9, 0xff, 0x7d, 0xc1, 0x31, 0xf5, 0x8a, 0x6a, 0xb1, 0xd1, 0x20, 0xd7, 0x02, 0x22, 0x04, 0x68, 0x71, 0x07, 0xdb, 0x9d, 0x99, 0x61, 0xbe, 0xe6, 0x59, 0xdd, 0x51, 0x90, 0xdc, 0x9a, 0xa3, 0xab, 0xd0, 0x81, 0x0f, 0x47, 0x1a, 0xe3, 0xec, 0x8d, 0xbf, 0x96, 0x7b, 0x5c, 0xa2, 0xa1, 0x63, 0x23, 0x4d, 0xc8, 0x9e, 0x9c, 0x3a, 0x0c, 0x2e, 0xba, 0x6e, 0x9f, 0x5a, 0xf2, 0x92, 0xf3, 0x49, 0x78, 0xcc, 0x15, 0xfb, 0x70, 0x75, 0x7f, 0x35, 0x10, 0x03, 0x64, 0x6d, 0xc6, 0x74, 0xd5, 0xb4, 0xea, 0x09, 0x76, 0x19, 0xfe, 0x40, 0x12, 0xe0, 0xbd, 0x05, 0xfa, 0x01, 0xf0, 0x2a, 0x5e, 0xa9, 0x56, 0x43, 0x85, 0x14, 0x89, 0x9b, 0xb0, 0xe5, 0x48, 0x79, 0x97, 0xfc, 0x1e, 0x82, 0x21, 0x8c, 0x1b, 0x5f, 0x77, 0x54, 0xb2, 0x1d, 0x25, 0x4f, 0x00, 0x46, 0xed, 0x58, 0x52, 0xeb, 0x7e, 0xda, 0xc9, 0xfd, 0x30, 0x95, 0x65, 0x3c, 0xb6, 0xe4, 0xbb, 0x7c, 0x0e, 0x50, 0x39, 0x26, 0x32, 0x84, 0x69, 0x93, 0x37, 0xe7, 0x24, 0xa4, 0xcb, 0x53, 0x0a, 0x87, 0xd9, 0x4c, 0x83, 0x8f, 0xce, 0x3b, 0x4a, 0xb7 };
const ULONG SEED_KC[24] = { 0x9e3779b9UL, 0x3c6ef373UL, 0x78dde6e6UL, 0xf1bbcdccUL, 0xe3779b99UL, 0xc6ef3733UL, 0x8dde6e67UL, 0x1bbcdccfUL, 0x3779b99eUL, 0x6ef3733cUL, 0xdde6e678UL, 0xbbcdccf1UL, 0x779b99e3UL, 0xef3733c6UL, 0xde6e678dUL, 0xbcdccf1bUL, 0x79b99e37UL, 0xf3733c6eUL, 0xe6e678ddUL, 0xcdccf1bbUL, 0x9b99e377UL, 0x3733c6efUL, 0x6e678ddeUL, 0xdccf1bbcUL };

int startpoint = 0;
int endpoint = 0;
float** data;
UCHAR** plaintext;
double* Sx, * Sxx, * Sxy, * corrT;
int TraceLength, TraceNum;
ULONG xor_key;
ULONG RK[2][2] = { 0 };

void SEED_G(ULONG* S) {
	UCHAR  Y[4];

	Y[0] = SEED_S1box[((*S) >> 0) & 0xFF];
	Y[1] = SEED_S2box[((*S) >> 8) & 0xFF];
	Y[2] = SEED_S1box[((*S) >> 16) & 0xFF];
	Y[3] = SEED_S2box[((*S) >> 24) & 0xFF];

	(*S) = ((ULONG)((Y[0] & 0xFC) ^ (Y[1] & 0xF3) ^ (Y[2] & 0xCF) ^ (Y[3] & 0x3F)) << 0) |
		((ULONG)((Y[0] & 0xF3) ^ (Y[1] & 0xCF) ^ (Y[2] & 0x3F) ^ (Y[3] & 0xFC)) << 8) |
		((ULONG)((Y[0] & 0xCF) ^ (Y[1] & 0x3F) ^ (Y[2] & 0xFC) ^ (Y[3] & 0xF3)) << 16) |
		((ULONG)((Y[0] & 0x3F) ^ (Y[1] & 0xFC) ^ (Y[2] & 0xF3) ^ (Y[3] & 0xCF)) << 24);
}

void SEED_G_INV(ULONG* S) {
	UCHAR Z[4];
	Z[0] = ((*S) >> 0) & 0xFF;
	Z[1] = ((*S) >> 8) & 0xFF;
	Z[2] = ((*S) >> 16) & 0xFF;
	Z[3] = ((*S) >> 24) & 0xFF;

	UCHAR U[4];
	U[0] = Z[0] ^ Z[1] ^ Z[2];
	U[1] = Z[0] ^ Z[1] ^ Z[3];
	U[2] = Z[0] ^ Z[2] ^ Z[3];
	U[3] = Z[1] ^ Z[2] ^ Z[3];

	UCHAR Y[4];
	Y[0] = SEED_S1box_inv[(U[0] & 0xC0) ^ (U[1] & 0x30) ^ (U[2] & 0x0C) ^ (U[3] & 0x03)];
	Y[1] = SEED_S2box_inv[(U[0] & 0x03) ^ (U[1] & 0xC0) ^ (U[2] & 0x30) ^ (U[3] & 0x0C)];
	Y[2] = SEED_S1box_inv[(U[0] & 0x0C) ^ (U[1] & 0x03) ^ (U[2] & 0xC0) ^ (U[3] & 0x30)];
	Y[3] = SEED_S2box_inv[(U[0] & 0x30) ^ (U[1] & 0x0C) ^ (U[2] & 0x03) ^ (U[3] & 0xC0)];

	ULONG X = Y[3];
	X = X << 8;
	X += Y[2];
	X = X << 8;
	X += Y[1];
	X = X << 8;
	X += Y[0];

	(*S) = X;
}

ULONG out_32bit(UCHAR* x) {
	ULONG a = x[0];
	a = a << 8;
	a += x[1];
	a = a << 8;
	a += x[2];
	a = a << 8;
	a += x[3];
	return a;
}

void read_file_trace(void) {
	char buf[256];
	int err, i, j;
	FILE* rfp;
	rfp = fopen("C:\\", "rb"); //trace ��ġ
	if (rfp == NULL) {
		printf("File Open Error1!!\n");
	}
	fread(&TraceLength, 4, 1, rfp);
	fread(&TraceNum, 4, 1, rfp);

	float* trace;
	trace = (float*)calloc(TraceLength, sizeof(float));
	data = (float**)calloc(TraceNum, sizeof(float*));
	for (i = 0; i < TraceNum; i++) {
		//������ startpoint~endpoint �� ��ŭ�� ����
		data[i] = (float*)calloc(endpoint - startpoint, sizeof(float));
		fread(trace, 4, TraceLength, rfp);
		for (j = 0; j < endpoint - startpoint; j++) {
			data[i][j] = trace[j + startpoint];
		}
	}
	fclose(rfp);
	free(trace);
	
}

void read_file_plaintext(void) {
	unsigned char x, y, temp[34];
	char buf[256] = { 0 };
	int err, i, j;
	FILE* rfp;
	rfp = fopen("C:\\", "rb"); //�� ��ġ
	if (rfp == NULL) {
		printf("File Open Error2!!\n");
	}
	plaintext = (unsigned char**)calloc(TraceNum, sizeof(unsigned char*));
	for (i = 0; i < TraceNum; i++) {
		fread(buf, 1, 34, rfp);//-->16bytes�� �ٲ㼭 plaintext[i]�� ���� �ʿ�
		plaintext[i] = (unsigned char*)calloc(16, sizeof(unsigned char));
		for (j = 0; j < 16; j++) {
			x = buf[2 * j];
			y = buf[2 * j + 1];
			//���������� ���ڿ� ó�� ex)x=15,y=16...
			if (x >= 'A' && x <= 'Z')x = x - 'A' + 10; //'0'~'9','A'~'F','a'~'f'
			else if (x >= 'a' && x <= 'z')x = x - 'a' + 10;
			else if (x >= '0' && x <= '9')x -= '0';
			if (y >= 'A' && y <= 'Z')y = y - 'A' + 10; //'0'~'9','A'~'F','a'~'f'
			else if (y >= 'a' && y <= 'z')y = y - 'a' + 10;
			else if (y >= '0' && y <= '9')y -= '0';
			plaintext[i][j] = x * 16 + y;
		}
	}
	fclose(rfp);
	
}
//2�� ° G�Լ��� ���� CPA(Ki,0)
ULONG Left_key(ULONG xor_key) {
	int k, i, err, j, key;
	unsigned char hw_iv, iv;
	double Sy, Syy;
	char buf[256];
	FILE* wfp;
	//SEED_G(C^D^K1,0^K1,1)
	ULONG* temp = (ULONG*)calloc(TraceNum, sizeof(ULONG));
	for (i = 0; i < TraceNum; i++) {
		ULONG c = out_32bit(&plaintext[i][8]);
		ULONG d = out_32bit(&plaintext[i][12]);
		temp[i] = xor_key ^ c ^ d;
		SEED_G(&temp[i]);
	}

	ULONG leftkey = 0;
	for (i = 0; i < 4; i++) {
		//printf("%x\n", realkey);
		double max = 0;
		int maxkey = 0;
		for (key = 0; key < 256; key++) {
			//printf("%d KEY\n", key);
			Sy = 0;
			Syy = 0;
			memset(Sxy, 0, sizeof(double) * (endpoint - startpoint));
			for (j = 0; j < TraceNum; j++) {
				//������ F�Լ��ȿ� 2��° G�Լ��� ���� CPA
				ULONG c = out_32bit(&plaintext[j][8]);
				if (i % 2 == 1)
					//1byte�� ������ ���� 1byte + 1byte�� ���� 0xff�� �Ѿ��� ���� �����ؾ���
					iv = SEED_S2box[(((c ^ (leftkey + (key << (8 * i)))) + temp[j]) >> (8 * i)) & 0xff];
				else
					iv = SEED_S1box[(((c ^ (leftkey + (key << (8 * i)))) + temp[j]) >> (8 * i)) & 0xff];

				hw_iv = 0;
				//�ع� ����Ʈ �� ���(1�� ������ ���)
				for (k = 0; k < 8; k++)hw_iv += ((iv >> k) & 1);
				Sy += hw_iv;
				Syy += hw_iv * hw_iv;
				for (k = 0; k < endpoint - startpoint; k++) {
					Sxy[k] += hw_iv * data[j][k];
				}
			}
			//������ ���� ���
			for (k = 0; k < endpoint - startpoint; k++) {
				corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / 
					sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
				if (fabs(corrT[k]) > max) { //������ �ִ밪 ���ϱ�
					maxkey = key;
					max = fabs(corrT[k]);
				}

			}

			sprintf_s(buf, 256 * sizeof(char), "%scorrtrace\\%02dth_block_%02x.corrtrace", _FOLD_, i, key);
			if ((err = fopen_s(&wfp, buf, "wb")))
			{
				printf("File Open Error3!!\n");
			}
			fwrite(corrT, sizeof(double), endpoint - startpoint, wfp);
			fclose(wfp);
			printf(".");
		}
		printf("%02dth_block : maxkey(%02X),maxcorr(%lf)\n", i, maxkey, max);
		leftkey += maxkey << (8 * i); //8bit¥�� 4���� �� maxkey�� 32bit realkey�� ����
		//printf("%x\n", realkey);
	}
	free(temp);

	return leftkey;
}
//1�� ° G�Լ��� ���� CPA(Ki,0^Ki,1)
ULONG XOR_key(void) {
	int k, i, err, j, key;
	unsigned char hw_iv, iv;
	double Sy, Syy;
	char buf[256];
	FILE* wfp;
	ULONG xor_key = 0;
	for (i = 8; i < 12; i++) {
		double max = 0;
		int maxkey = 0;
		for (key = 0; key < 256; key++) {
			//printf("%d KEY\n", key);
			Sy = 0;
			Syy = 0;
			memset(Sxy, 0, sizeof(double) * (endpoint - startpoint));
			for (j = 0; j < TraceNum; j++) {
				//������ S2box[PT[8] ^ PT[12] ^ RK[0] ^ RK[4]]�� ������ K1,0^K1,1�� ���� �ѹ��� ����
				if (i % 2 == 1) {
					iv = SEED_S1box[plaintext[j][i] ^ plaintext[j][i + 4] ^ key];
				}
				else {
					iv = SEED_S2box[plaintext[j][i] ^ plaintext[j][i + 4] ^ key];
				}
				hw_iv = 0;
				//�ع� ����Ʈ �� ���(1�� ������ ���)
				for (k = 0; k < 8; k++)hw_iv += ((iv >> k) & 1);
				Sy += hw_iv;
				Syy += hw_iv * hw_iv;
				for (k = 0; k < endpoint - startpoint; k++) {
					Sxy[k] += hw_iv * data[j][k];
				}
			}
			//������ ���� ���
			for (k = 0; k < endpoint - startpoint; k++) {
				corrT[k] = ((double)TraceNum * Sxy[k] - Sx[k] * Sy) / 
					sqrt(((double)TraceNum * Sxx[k] - Sx[k] * Sx[k]) * ((double)TraceNum * Syy - Sy * Sy));
				if (fabs(corrT[k]) > max) { //������ �ִ밪 ���ϱ�
					maxkey = key;
					max = fabs(corrT[k]);
				}

			}

			sprintf_s(buf, 256 * sizeof(char), "%scorrtrace\\%02dth_block_%02x.corrtrace", _FOLD_, i - 8, key);
			if ((err = fopen_s(&wfp, buf, "wb")))
			{
				printf("File Open Error3!!\n");
			}
			fwrite(corrT, sizeof(double), endpoint - startpoint, wfp);
			fclose(wfp);
			printf(".");
		}
		printf("%02dth_block : maxkey(%02X),maxcorr(%lf)\n", i - 8, maxkey, max);
		xor_key += maxkey << (8 * (11 - i)); //8bit¥�� 4���� maxkey�� 32bit xor_key�� ����
	}
	return xor_key;
}


void Round1_ENC(ULONG key0, ULONG key1) {
	for (int i = 0; i < TraceNum; i++) {
		ULONG L[2] = { 0 }, R[2] = { 0 }, temp[2];
		ULONG K[2] = { key0, key1 };
		//L,R�� ���� ����
		L[0] = out_32bit(&plaintext[i][0]);
		L[1] = out_32bit(&plaintext[i][4]);
		R[0] = out_32bit(&plaintext[i][8]);
		R[1] = out_32bit(&plaintext[i][12]);
		//F�Լ�
		temp[0] = R[0] ^ K[0];
		temp[1] = R[1] ^ K[1];

		temp[1] ^= temp[0];

		SEED_G(temp + 1);
		temp[0] += temp[1];

		SEED_G(temp);
		temp[1] += temp[0];

		SEED_G(temp + 1);
		temp[0] += temp[1];

		L[0] ^= temp[0];
		L[1] ^= temp[1];
		//Left->Right
		//Right->Left�� �ʿ����. 2���� F�Լ����� CPA�� �Ϸ��
		plaintext[i][11] = L[0] & 0xff;
		L[0] = L[0] >> 8;
		plaintext[i][10] = L[0] & 0xff;
		L[0] = L[0] >> 8;
		plaintext[i][9] = L[0] & 0xff;
		L[0] = L[0] >> 8;
		plaintext[i][8] = L[0] & 0xff;
		plaintext[i][15] = L[1] & 0xff;
		L[1] = L[1] >> 8;
		plaintext[i][14] = L[1] & 0xff;
		L[1] = L[1] >> 8;
		plaintext[i][13] = L[1] & 0xff;
		L[1] = L[1] >> 8;
		plaintext[i][12] = L[1] & 0xff;
	}
}

void cal_masterkey(void) {
	FILE* f_masterKey;
	ULONG T0[2] = { 0 }, T1[2] = { 0 };

	T0[0] = RK[0][0]; //K1,0
	T1[0] = RK[0][1]; //K1,1
	T0[1] = RK[1][0]; //K2,0
	T1[1] = RK[1][1]; //K2,1
	SEED_G_INV(&T0[0]);
	SEED_G_INV(&T0[1]);
	SEED_G_INV(&T1[0]);
	SEED_G_INV(&T1[1]);

	//SEED Ű������ �Լ����� ���Ǵ� ���� ���
	T0[0] += SEED_KC[0];
	T0[1] += SEED_KC[1];
	T1[0] -= SEED_KC[0];
	T1[1] -= SEED_KC[1];

	ULONG X = 0x89111111; // T0[0] - T0[1]
	ULONG Y = 0x11111111; // T1[0] - T1[1]

	f_masterKey = fopen("C:\\", "wb"); //������ Ű ��ġ
	if (f_masterKey == NULL) {
		printf("File Open Error4!!\n");
	}
	
	for (int i = 0x0; i <= 0xff; i++) {
		int A[4] = { 0 }, B[4] = { 0 };
		A[0] += i & 0xff;
		A[1] += A[0] - (X & 0xff);
		if (A[1] < 0) {
			A[1] += 0x100;
			A[2]--;
		}
		A[2] += A[1] - ((X >> 8) & 0xff);
		if (A[2] < 0) {
			A[2] += 0x100;
			A[3]--;
		}
		A[3] += A[2] - ((X >> 16) & 0xff);
		if (A[3] < 0) {
			A[3] += 0x100;
			B[0]--;
		}
		B[0] += A[3] - ((X >> 24) & 0xff);
		if (B[0] < 0) {
			B[0] += 0x100;
		}
		B[1] += B[0] - (Y & 0xff);
		if (B[1] < 0) {
			B[1] += 0x100;
			B[2]--;
		}
		B[2] += B[1] - ((Y >> 8) & 0xff);
		if (B[2] < 0) {
			B[2] += 0x100;
			B[3]--;
		}
		B[3] += B[2] - ((Y >> 16) & 0xff);
		if (B[3] < 0) {
			B[3] += 0x100;
		}

		UCHAR AA[4], BB[4];
		for (int j = 0; j < 4; j++) {
			AA[3 - j] = (UCHAR)A[j];
			BB[3 - j] = (UCHAR)B[j];
		}

		ULONG AAA = out_32bit(&AA[0]);
		ULONG BBB = out_32bit(&BB[0]);
		ULONG C = T0[0] - AAA;
		ULONG D = BBB - T1[0];

		if (AAA + C != T0[0] || BBB - D != T1[0]) {
			continue;
		}

		TwoWordRRot(AAA, BBB);

		if (AAA + C != T0[1] || BBB - D != T1[1]) {
			continue;
		}

		TwoWordLRot(AAA, BBB);
		//printf("Master Key : %08X%08X%08X%08X\n", AAA, BBB, C, D);
		fprintf(f_masterKey, "%08X%08X%08X%08X\n", AAA, BBB, C, D);
	}
	fclose(f_masterKey);
}

void CPA(void) {
	int i, j;

	//1���� CPA
	startpoint = 485000;
	endpoint = 490000;
	//���� �б�
	read_file_trace();

	//�� �б�
	read_file_plaintext();

	//correlation ���� ���ϱ� ���� ���� �迭 �޸� �Ҵ�
	Sx = (double*)calloc(endpoint - startpoint, sizeof(double));
	Sxx = (double*)calloc(endpoint - startpoint, sizeof(double));
	Sxy = (double*)calloc(endpoint - startpoint, sizeof(double));
	corrT = (double*)calloc(endpoint - startpoint, sizeof(double));
	//Sx,Sxx �� ���
	for (i = 0; i < TraceNum; i++) {
		for (j = 0; j < endpoint - startpoint; j++) {
			Sx[j] += data[i][j];
			Sxx[j] += data[i][j] * data[i][j];
		}
	}

	printf("\t\t\t<K1,0 ^ K1,1>\n");
	//K1,0 ^ K1,1
	xor_key = XOR_key();

	printf("\t\t\t<K1,0>\n");
	//K1,0�� RK[0][0]�� ����
	RK[0][0] = Left_key(xor_key);

	//K1,1�� ���ؼ� RK[0][1]�� ����
	RK[0][1] = xor_key ^ RK[0][0];
	printf("\n1Round Key : %08X %08X\n\n", RK[0][0], RK[0][1]);

	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);

	//1���� ��ȣȭ
	Round1_ENC(RK[0][0], RK[0][1]);

	//2���� CPA
	startpoint = 505000;
	endpoint = 515000;

	read_file_trace();

	Sx = (double*)calloc(endpoint - startpoint, sizeof(double));
	Sxx = (double*)calloc(endpoint - startpoint, sizeof(double));
	Sxy = (double*)calloc(endpoint - startpoint, sizeof(double));
	corrT = (double*)calloc(endpoint - startpoint, sizeof(double));

	for (i = 0; i < TraceNum; i++) {
		for (j = 0; j < endpoint - startpoint; j++) {
			Sx[j] += data[i][j];
			Sxx[j] += data[i][j] * data[i][j];
		}
	}

	printf("\t\t\t<K2,0 ^ K2,1>\n");
	//K2,0^K2,1
	xor_key = XOR_key();

	printf("\t\t\t<K2,0>\n");
	//K2,0�� RK[1][0]�� ����
	RK[1][0] = Left_key(xor_key);

	////K2,1�� ���ؼ� RK[1][1]�� ����
	RK[1][1] = xor_key ^ RK[1][0];
	printf("\n2Round Key : %08X %08X\n\n", RK[1][0], RK[1][1]);

	free(Sx);
	free(Sxx);
	free(Sxy);
	free(corrT);
	free(data);
	free(plaintext);

	//������ Ű ���
	printf("\t\t\t<Master Key>\n");
	cal_masterkey();
	printf("\n\t\t\tmasterkey.txt���Ϸ� ����\n");

}

int main(void) {
	CPA();
	return 0;
}