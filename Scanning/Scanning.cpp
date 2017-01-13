// Scanning.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <io.h>
#include <Locale.h>
#include <time.h>
#include "Search.h"

using namespace std;

HARDCODE g_hard_code[] = {
	{ false,false,false,false,800 * 1024,1024 * 1024,nullptr,"3df06392ad18984a0064f578b501fa90","Tencent Technology(Shenzhen)","QQ管家-在线" },
	{ false,false,false,false,45000 * 1024,55000 * 1024,nullptr,"401dbe95c3295acdacdf2d66c1cd2f36","Tencent Technology(Shenzhen)","QQ管家-离线"},
	{ false,false,false,false,20000 * 1024,70000 * 1024,nullptr,"a24c4560db5c2326e4a686be98ca9f30","360","360安全卫士-离线" },
	{ false,false,false,false,25000 * 1024,35000 * 1024,nullptr,"f04ca155224d69f9f6b2228a44728d2b","360","360安全卫士-国际" },
	{ false,false,false,false,25000 * 1024,35000 * 1024 ,nullptr,"e6a66c2b5064e5b53d8e1ed19635d876","Beijing Kingsoft Security software Co","金山毒霸-离线" },
	{ false,false,false,false,0,0,nullptr,"695284efecdf292b65cd3e84f4fcd144","Beijing Kingsoft Security software Co","金山毒霸-在线" },
};

bool enumeration_call_back(wchar_t *file_path, wchar_t*file_name)
{
	static unsigned int exe_file_number = 0;
	int index = -1;
	wchar_t file_all_name[512] = { 0 };
	wchar_t* pdot = nullptr;
	wcscpy(file_all_name, file_path);
	wcscat(file_all_name, file_name);
	if ((pdot = wcsrchr(file_all_name, '.')) && wcscmp(pdot, L".exe") == 0){
		exe_file_number++;
		auto start_time = clock();
		auto file_name = wcsrchr(file_all_name, '\\') + 1;
		index = matching_feature(g_hard_code, _countof(g_hard_code), file_all_name);

		/*for (unsigned int i = 0; i < _countof(g_hard_code); i++) {
			if (g_hard_code[i].if_image_success && g_hard_code[i].if_signedtrue_success && g_hard_code[i].if_sign_success){
				index = i;
				break;
			}
		}*/

		if (wcslen(file_name) > 15){
			file_name[15] = L'\0';
		}

		if (index >= 0){
			wprintf(L"%d\t%s", exe_file_number, file_name);
			printf("\t%s\tms:%d\n", g_hard_code[index].notes, clock() - start_time);
		}
		else{
			wprintf(L"%d\t%s\t%s\tms:%d\n", exe_file_number, wcsrchr(file_all_name, '\\') + 1, L"不匹配", clock() - start_time);
		}
		for (unsigned int i = 0; i < _countof(g_hard_code); i++){
			g_hard_code[i].if_image_success = false;
			g_hard_code[i].if_signedtrue_success = false;
			g_hard_code[i].if_sign_success = false;
		}
		
	}
	return true;
}

bool enumeration_all_file(const wchar_t * file_path)
{

	wchar_t convert_path[512] = { 0 };
	wchar_t convert_search[512] = { 0 };
	_wfinddata_t fd;
	wcscpy(convert_search, file_path);
	wcscat(convert_search, L"*");
	intptr_t pf = _wfindfirst(convert_search, &fd);
	if (pf == -1){
		return false;
	}

	while (!_wfindnext(pf, &fd)){

		if (wcscmp(fd.name, L".") == 0 || wcscmp(fd.name, L"..") == 0){
			continue;
		}

		wcscpy(convert_path, file_path);
		if (fd.attrib == _A_SUBDIR){
			wcscat(convert_path, fd.name);
			wcscat(convert_path, L"\\");
			enumeration_all_file(convert_path);
		}
		else{
			enumeration_call_back(convert_path, fd.name);
			//wprintf(L"%s%s\n", convert_path, fd.name);
		}

	}
	_findclose(pf);
	return true;
}

int main()
{
	_wsetlocale(LC_ALL, L"chs");
	/*枚举目录并匹配特征*/
	//auto path = L"E:\\";//L"C:\\Users\\Mecha\\Desktop\\共享\\";
	//auto path = L"E:\\共享\\";
	//auto path3 = L"F:\\";
	//enumeration_all_file(path);
	//printf("枚举完成\n");

	/*匹配单条特征*/
	//auto path2 = L"E:\\共享\\360安全卫士\\离线安装包\\10.3.0.2009\\setup_10.3.0.2001g - 副本.exe";
	auto path2 = L"E:\\共享\\QQ电脑管家\\在线安装包\\QQPCDownload1349\\QQPCDownload1349.exe";
	auto index = matching_feature(g_hard_code, _countof(g_hard_code) ,path2);
	if (index != -1){
		printf("枚举完成,结果:%s\n", g_hard_code[index].notes);
	}
	else {
		printf("枚举完成,未发现匹配项\n");
	}
	
	getchar();
    return 0;
}



BOOL OnInitDialog()
{

	//m_TreeRESOURCE.DeleteAllItems();
	//HTREEITEM hitem = m_TreeRESOURCE.InsertItem("资源表");
	return true;
}
