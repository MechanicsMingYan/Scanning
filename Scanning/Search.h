#pragma once
#include <iostream>
#include <fstream>
#include <Dbghelp.h>
#include "CPeFile.h"
//2017年1月9日 10:34:38

/*
bool类型的初始化均为false
筛选值非nullptr时将会进行筛选,当多项中有一项不符合则后续筛选则不会执行
并将相关的bool结果赋值为false
*/
typedef struct _HARDCODE {
	bool if_sign_success;
	bool if_image_success;
	bool if_filesize_success;
	bool if_signedtrue_success;
	unsigned long file_size_start;//文件最小值
	unsigned long file_size_end;//文件最大值
	char* sign_str;				//特征码
	char* image_md5;			//图片特征
	char* signedture;			//关键签名
	char* notes;				//备注信息
}HARDCODE, *PHARDCODE;

/*
char*转byte
*/
unsigned int change_num(
	const char* revstr,
	const int length,
	char* ignore);

unsigned int change_num(
	const wchar_t* revstr,
	const int length,
	char* ignore);
/*
byte转char*
*/
bool change_str(
	const unsigned char num,
	char* receive_str);

bool change_str(
	const unsigned char num,
	wchar_t* receive_str);

/*
bytes转char*
*/
bool change_chars(
	const char* chars,
	const unsigned int chars_size,
	char* data);

bool change_chars(
	const char* chars,
	const unsigned int chars_size,
	wchar_t* data);

unsigned int search_byte(
	const unsigned int start_addr,
	const unsigned int over_addr,
	unsigned char* chars,
	unsigned char* ignore,
	const unsigned int signature_len);

bool search_signature(
	const unsigned int start_addr,
	const unsigned int over_addr,
	const char * signature);

bool search_image_md5(
	CPeFile * lp_pe,
	const char * file_data,
	const char * signature);

bool search_signedtrue(
	CPeFile * lp_pe,
	const char * file_data,
	const char * signature);

int search_feature(
	const PHARDCODE hard_code,
	const unsigned int dwCount,
	CPeFile * lp_pe,
	const char *lp_file_data);

unsigned int get_file_data(
	const wchar_t* file_path,
	char * data);

int matching_feature(
	const PHARDCODE hard_code,
	const unsigned int hard_member_number,
	const wchar_t * file_path);

bool get_code_feature(
	const wchar_t * file_path,
	const unsigned int code_shift,
	const char * signatyre_data,
	const unsigned int signatyre_data_len);

bool get_image_feature(
	const wchar_t * file_path,
	char *rs_md5);