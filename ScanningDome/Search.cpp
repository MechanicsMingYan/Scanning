#include "stdafx.h"
#include "md5.h"
#include "Search.h"
#include <time.h>

#pragma comment(lib,"Dbghelp.lib")

unsigned int change_num(
	const char* revstr,
	const int length,
	unsigned char* ignore)
{
	int   num[16] = { 0 };
	int   count = 1;
	int   result = 0;

	for (int i = length - 1; i >= 0; i--){
		if (revstr[i] >= '0' && revstr[i] <= '9')
			num[i] = revstr[i] - 48;	//字符0的ASCII值为48
		else if (revstr[i] >= 'a' && revstr[i] <= 'f')
			num[i] = revstr[i] - 'a' + 10;
		else if (revstr[i] >= 'A' && revstr[i] <= 'F')
			num[i] = revstr[i] - 'A' + 10;
		else if (revstr[i] == '?'){
			*ignore = true;
			break;
		}
		result = result + num[i] * count;
		count = count * 16;				//十六进制(如果是八进制就在这里乘以8)    
	}

	return result;
}

unsigned int change_num(
	const wchar_t* revstr,
	const int length,
	char* ignore)
{
	int   num[16] = { 0 };
	int   count = 1;
	int   result = 0;

	for (int i = length - 1; i >= 0; i--){
		if (revstr[i] >= L'0' && revstr[i] <= L'9')
			num[i] = revstr[i] - 48;	//字符0的ASCII值为48
		else if (revstr[i] >= L'a' && revstr[i] <= L'f')
			num[i] = revstr[i] - L'a' + 10;
		else if (revstr[i] >= L'A' && revstr[i] <= L'F')
			num[i] = revstr[i] - L'A' + 10;
		else if (revstr[i] == L'?'){
			*ignore = true;
			break;
		}
		result = result + num[i] * count;
		count = count * 16;				//十六进制(如果是八进制就在这里乘以8)    
	}

	return result;
}

bool change_str(
	const unsigned char num, 
	char* receive_str)
{
	if (num > 0x0f){
		itoa(num, receive_str, 16);
	}
	else {
		*(receive_str) = '0';
		itoa(num, receive_str + 1, 16);
	}

	return true;
}

bool change_str(
	const unsigned char num,
	wchar_t* receive_str)
{
	if (num > 0x0f){
		_itow(num, receive_str, 16);
	}
	else {
		*(receive_str) = '0';
		_itow(num, receive_str + 1, 16);
	}

	return true;
}

bool change_chars(
	const char* chars,
	const unsigned int chars_size,
	char* data)
{
	for (int i = 0; i < chars_size; i++) {
		change_str(chars[i], data + i * 2);
	}
	return true;
}

bool change_chars(
	const char* chars,
	const unsigned int chars_size,
	wchar_t* data)
{
	for (int i = 0; i < chars_size; i++) {
		change_str(chars[i], data + i * 2);
	}
	return true;
}

unsigned int search_byte(
	const unsigned int start_addr,
	const unsigned int over_addr,
	unsigned char* chars,
	unsigned char* ignore,
	const unsigned int signature_len)
{
	const int kSearch_Size = 0x1000;
	unsigned int search_addr = 0;
	unsigned int image_base = start_addr;
	unsigned char save[kSearch_Size] = { 0 };

	while (image_base < over_addr && search_addr == 0) {
		signed int size = image_base + kSearch_Size - over_addr;
		if (size > 0) {
			size = over_addr - image_base;
			memcpy(save, reinterpret_cast<const void*>(image_base), size);
		}
		else {
			size = kSearch_Size;
			memcpy(save, reinterpret_cast<const void*>(image_base), kSearch_Size);
		}

		for (int j = 0; j < size - signature_len; j++) {
			if (save[j] == chars[0]) {
				int x = 1;
				for (; x < signature_len; x++) {
					if (ignore != nullptr && ignore[x] == TRUE)
						continue;
					else if (save[j + x] == chars[x])
						continue;
					else
						break;
				}
				if (x == signature_len) {
					search_addr = image_base + j;
					break;
				}
			}
		}
		image_base += kSearch_Size - signature_len;
	}
	
	return search_addr;
}

bool search_signature(
	const PHARDCODE hard_code,
	const int hard_number,
	const unsigned int start_addr, 
	const unsigned int over_addr
)
{
	bool if_success = false;
	const int kSearch_Size = 0x1000;
	unsigned int image_base = start_addr;

	for (size_t i = 0; i < hard_number; i++){
		auto signature = hard_code[i].sign_str;
		if (signature == nullptr){
			hard_code[i].if_sign_success = true;
			continue;
		}
		if (!hard_code[i].if_signedtrue_success) {
			hard_code[i].if_sign_success = false;
			continue;
		}

		int signature_len = strlen(signature) / 2;
		unsigned char* chars = new unsigned char[signature_len];
		unsigned char* ignore = new unsigned char[signature_len];

		memset(ignore, 0, signature_len);

		for (int i = 0; i < signature_len; i++) {
			chars[i] = change_num(signature + i * 2, 2, &ignore[i]);
		}

		auto search_addr = search_byte(start_addr, over_addr, chars, ignore, signature_len);

		if (search_addr) {
			hard_code[i].if_sign_success = true;
		}

		if (chars)
			delete[]chars;
		if (ignore)
			delete[]ignore;
	}
	
	return if_success;
}

DWORD CalcOffset(DWORD Rva, PIMAGE_NT_HEADERS32  pNtH)
{
	//PIMAGE_NT_HEADERS32 pnt=pNtH;
	PIMAGE_SECTION_HEADER pSecHTemp = IMAGE_FIRST_SECTION(pNtH);//区段头
	int index = 0;

	while (!(Rva >= pSecHTemp->VirtualAddress&&
		Rva<pSecHTemp->VirtualAddress + pSecHTemp->SizeOfRawData))
	{
		//找完所有区段还没有找到
		if (index>pNtH->FileHeader.NumberOfSections)
		{
			return Rva;
		}
		++index;
		++pSecHTemp;
	}
	auto v = Rva - pSecHTemp->VirtualAddress + pSecHTemp->PointerToRawData;;
	return v;
}


bool search_image_md5(
	const PHARDCODE hard_code,
	const int hard_number,
	CPeFile * lp_pe,
	const char * file_data)
{
	bool if_success = false;
	auto p_nt_header = const_cast<PIMAGE_NT_HEADERS32>(lp_pe->GetNtHeader());
	auto p_data_directory = &lp_pe->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (p_data_directory->Size == 0 || p_data_directory->VirtualAddress == 0){
		return false;
	}
	auto p_reg_directory = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(const_cast<char*>(file_data) + CalcOffset(p_data_directory->VirtualAddress, p_nt_header));
	auto re_size = p_reg_directory->NumberOfIdEntries + p_reg_directory->NumberOfNamedEntries;
	auto p_reg_directory_entry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>((long)p_reg_directory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	char ResourceName[15][16] = { "鼠标指针","位图","图标","菜单","对话框",
		"字符串列表","字体目录","字体","快捷键","非格式化资源",
		"消息列表","鼠标指针组","图标组","版本信息" };
	for (DWORD FirstOrder = 0; FirstOrder < re_size; FirstOrder++){
		if (p_reg_directory_entry->Name != 0x03) {
			p_reg_directory_entry++;
			continue;
		}

		auto p_reg_directory2 = (PIMAGE_RESOURCE_DIRECTORY)((long)p_reg_directory + p_reg_directory_entry->OffsetToDirectory);
		auto re_size2 = p_reg_directory2->NumberOfIdEntries + p_reg_directory2->NumberOfNamedEntries;
		auto p_reg_directory_entry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((long)p_reg_directory2 + sizeof(IMAGE_RESOURCE_DIRECTORY));
		for (unsigned int second_order = 0; second_order < re_size2; second_order++) {
			if (p_reg_directory_entry2->DataIsDirectory != 1) {
				break;
			}
			
			auto p_reg_directory3 = (PIMAGE_RESOURCE_DIRECTORY)((long)p_reg_directory + p_reg_directory_entry2->OffsetToDirectory);
			auto p_reg_directory_entry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((long)p_reg_directory3 + sizeof(IMAGE_RESOURCE_DIRECTORY));
			auto reg_data = (PIMAGE_RESOURCE_DATA_ENTRY)((long)p_reg_directory + p_reg_directory_entry3->OffsetToData);
			auto image_data = reinterpret_cast<const char*>(reinterpret_cast<unsigned long>(file_data) + CalcOffset(reg_data->OffsetToData, p_nt_header));
			
			if (reg_data->Size > 0x50000){
				break;
			}
			string str_md5 = "";
			MD5 md5;                 //定义MD5的类  
			if (!IsBadReadPtr(image_data, reg_data->Size)) {
				md5.update(image_data, reg_data->Size);
				str_md5 = md5.toString();
			}
			for (size_t i = 0; i < hard_number; i++) {
				auto image_md5 = hard_code[i].image_md5;
				if (image_md5 == nullptr || image_md5 == str_md5) {
					hard_code[i].if_image_success = true;
				}
			}
			//return true;
			p_reg_directory_entry2++;
		}
		p_reg_directory_entry++;
	}

	return if_success;
}

bool search_signedtrue(
	const PHARDCODE hard_code,
	const int hard_number,
	CPeFile * lp_pe,
	const char * file_data)
{
	bool if_success = false;
	unsigned long lp_certificate_number = 0;
	auto p_data_directory = &lp_pe->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_SECURITY];
	/*if (!lp_pe->ReadSecurity()) {
		return false;
	}*/
	auto hard_security = lp_pe->GetCertificate(&lp_certificate_number);
	if (!lp_certificate_number){
		return false;
	}

	for (size_t i = 0; i < hard_number; i++) {
		auto signature = hard_code[i].signedture;
		if (signature == nullptr) {
			hard_code[i].if_signedtrue_success = true;
			continue;
		}
		if (!hard_code[i].if_image_success){
			hard_code[i].if_signedtrue_success = false;
			continue;
		}
		auto search_addr = search_byte(
			reinterpret_cast<unsigned long>(file_data) + p_data_directory->VirtualAddress,
			reinterpret_cast<unsigned long>(file_data) + p_data_directory->VirtualAddress + p_data_directory->Size,
			reinterpret_cast<unsigned char*>(const_cast<char*>(signature)),
			nullptr,
			strlen(signature));
		if (search_addr) {
			hard_code[i].if_signedtrue_success = true;
		}
		
	}

	return if_success;
}

int search_feature(
	const PHARDCODE hard_code,
	const unsigned int dwCount,
	CPeFile * lp_pe,
	const char *lp_file_data)
{
	int if_success_index = -1;
	bool if_sig_success = false;
	bool if_image_success = false;
	bool if_signedtrue_success = false;
	unsigned long lp_furst_resource_id = 0;
	unsigned int dwValue = 0;
	unsigned short Num = 0;
	
	auto herader = lp_pe->GetSectionHeader(&Num);
	if (!herader) {
		return false;
	}
	auto hard_header = &herader[0];
	for (size_t i = 0; i < Num; i++) {
		hard_header = &herader[i];
		if ((!strcmp((char*)hard_header->Name, ".text") ||

			(hard_header->Characteristics & IMAGE_SCN_CNT_CODE) ||
			(hard_header->Characteristics & IMAGE_SCN_MEM_EXECUTE)) &&
			hard_header->SizeOfRawData > 0x200
			) {
			break;
		}
	}

	if (!(!strcmp((char*)hard_header->Name, ".text") ||
		(hard_header->Characteristics & IMAGE_SCN_CNT_CODE) ||
		(hard_header->Characteristics & IMAGE_SCN_MEM_EXECUTE))) {
		hard_header = nullptr;
	}
	if (lp_file_data){
		//图片征码匹配
		//if (lp_pe->ReadResource()) {
			search_image_md5(hard_code, dwCount, lp_pe, lp_file_data);
		//}
		//签名征码匹配
		search_signedtrue(hard_code, dwCount, lp_pe, lp_file_data);

		if (hard_header) {
			auto pvStartAddress = reinterpret_cast<unsigned int>(lp_file_data + hard_header->PointerToRawData);
			auto pvover_addrAddress = pvStartAddress + hard_header->SizeOfRawData;
			if_sig_success = search_signature(hard_code, dwCount, pvStartAddress, pvover_addrAddress) > 0;
		}
	}
	
	return if_success_index;
}

unsigned int get_file_data(
	const wchar_t* file_path, 
	char * data)
{
	struct _stat st;
	std::ifstream fin(file_path, std::ios::binary);
	if (!fin.is_open()) {
		return false;
	}
	_wstat(file_path, &st);
	if (!st.st_size) {
		return false;
	}
	if (data){
		fin.read(data, st.st_size);
	}
	fin.close();
	return st.st_size;
}


int matching_feature(
	const PHARDCODE hard_code,
	const unsigned int hard_member_number,
	const wchar_t * file_path)
{
	int if_success_index = -1;
	CPeFile pe;
	//auto start_time = clock();
	
	for (size_t i = 0; i < hard_member_number; i++) {
		hard_code[i].if_sign_success = false;
		hard_code[i].if_image_success = false;
		hard_code[i].if_filesize_success = false;
		hard_code[i].if_signedtrue_success = false;
	}

	auto st_size = get_file_data(file_path, nullptr);
	if (!st_size){
		return if_success_index;
	}

	auto file_data = new char[st_size];
	if (!get_file_data(file_path, file_data)){
		return if_success_index;
	}

	auto if_openfile_success = pe.Attach(file_path);
	if (if_openfile_success == 0UL || 
		if_openfile_success == 1UL || 
		if_openfile_success == 2UL){
		return if_success_index;
	}
	
	for (size_t i = 0; i < hard_member_number; i++) {
		if (!hard_code[i].file_size_end || 
			(hard_code[i].file_size_start < st_size && 
			hard_code[i].file_size_end > st_size)) {
			hard_code[i].if_filesize_success = true;
		}
	}

	if_success_index = search_feature(
		hard_code,
		hard_member_number,
		&pe,
		file_data);

	delete file_data;
	return if_success_index;
}


bool get_code_feature(
	const wchar_t * file_path,
	const unsigned int code_shift,
	const char * signatyre_data,
	const unsigned int signatyre_data_len)
{
	unsigned short Num = 0;
	CPeFile pe;
	auto st_size = get_file_data(file_path, nullptr);
	if (!st_size) {
		return false;
	}

	auto file_data = new char[st_size];
	if (!get_file_data(file_path, file_data)) {
		return false;
	}

	pe.Attach(file_path);
	auto herader = pe.GetSectionHeader(&Num);

	if (!herader) {
		return false;
	}

	auto he = herader[0];
	for (size_t i = 0; i < Num; i++) {
		he = herader[i];
		if ((!strcmp((char*)he.Name, ".text") || 

			(he.Characteristics & IMAGE_SCN_CNT_CODE) ||
			(he.Characteristics & IMAGE_SCN_MEM_EXECUTE)) &&
			he.SizeOfRawData > 0x200
			) {
			break;
		}
	}

	if (!(!strcmp((char*)he.Name, ".text") ||
		(he.Characteristics & IMAGE_SCN_CNT_CODE) ||
			(he.Characteristics & IMAGE_SCN_MEM_EXECUTE))) {
		return false;
	}

	if (he.PointerToRawData + he.SizeOfRawData <
		he.PointerToRawData + signatyre_data_len + code_shift) {
		return false;
	}

	memcpy(
		reinterpret_cast<void*>(const_cast<char*>(signatyre_data)),
		(file_data + he.PointerToRawData + code_shift),
		signatyre_data_len);

	return true;
}

bool get_image_feature(
	const wchar_t * file_path,
	char *rs_md5)
{
	unsigned short Num = 0;
	CPeFile pe;

	auto st_size = get_file_data(file_path, nullptr);
	if (!st_size) {
		return false;
	}

	auto file_data = new char[st_size];
	if (!get_file_data(file_path, file_data)) {
		return false;
	}

	auto if_openfile_success = pe.Attach(file_path);
	if (if_openfile_success == 0UL ||
		if_openfile_success == 1UL ||
		if_openfile_success == 2UL) {
		return false;
	}
	
	auto p_nt_header = const_cast<PIMAGE_NT_HEADERS32>(pe.GetNtHeader());
	auto p_data_directory = &pe.GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if (p_data_directory->Size == 0 || p_data_directory->VirtualAddress == 0) {
		return false;
	}
	auto p_reg_directory = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(const_cast<char*>(file_data) + CalcOffset(p_data_directory->VirtualAddress, p_nt_header));
	auto re_size = p_reg_directory->NumberOfIdEntries + p_reg_directory->NumberOfNamedEntries;
	auto p_reg_directory_entry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>((long)p_reg_directory + sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (DWORD FirstOrder = 0; FirstOrder < re_size; FirstOrder++) {
		if (p_reg_directory_entry->Name != 0x03) {
			p_reg_directory_entry++;
			continue;
		}

		auto p_reg_directory2 = (PIMAGE_RESOURCE_DIRECTORY)((long)p_reg_directory + p_reg_directory_entry->OffsetToDirectory);
		auto re_size2 = p_reg_directory2->NumberOfIdEntries + p_reg_directory2->NumberOfNamedEntries;
		auto p_reg_directory_entry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((long)p_reg_directory2 + sizeof(IMAGE_RESOURCE_DIRECTORY));
		for (unsigned int second_order = 0; second_order < re_size2; second_order++) {
			if (p_reg_directory_entry2->DataIsDirectory != 1) {
				break;
			}
			//解析第三层 
			auto p_reg_directory3 = (PIMAGE_RESOURCE_DIRECTORY)((long)p_reg_directory + p_reg_directory_entry2->OffsetToDirectory);
			auto p_reg_directory_entry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((long)p_reg_directory3 + sizeof(IMAGE_RESOURCE_DIRECTORY));
			auto reg_data = (PIMAGE_RESOURCE_DATA_ENTRY)((long)p_reg_directory + p_reg_directory_entry3->OffsetToData);
			auto image_data = reinterpret_cast<const char*>(reinterpret_cast<unsigned long>(file_data) + CalcOffset(reg_data->OffsetToData, p_nt_header));
			
			if (reg_data->Size > 0x50000) {
				break;
			}
			string str_md5 = "";
			MD5 md5;                 //定义MD5的类  
			if (!IsBadReadPtr(image_data, reg_data->Size)) {
				md5.update(image_data, reg_data->Size);
				str_md5 = md5.toString();
			}

			if (str_md5 != "" && rs_md5) {
				strcpy(rs_md5, str_md5.c_str());
				return true;
			}

			p_reg_directory_entry2++;
		}
		p_reg_directory_entry++;
	}

	return false;
}