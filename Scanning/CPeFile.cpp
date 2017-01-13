#include "stdafx.h"
#include <assert.h>
#include <new>
#include "CPeFile.h"



//读取标志m_dwReadFlag取值（仅在类中使用）
#define PE_READ_FLAG_EXPORT				0x00000001UL
#define PE_READ_FLAG_IMPORT				0x00000002UL
#define PE_READ_FLAG_RESOURCE			0x00000004UL
#define PE_READ_FLAG_EXCEPTION			0x00000008UL
#define PE_READ_FLAG_SECURITY			0x00000010UL
#define PE_READ_FLAG_BASERELOCATION		0x00000020UL
#define PE_READ_FLAG_DEBUG				0x00000040UL
#define PE_READ_FLAG_TLS				0x00000080UL
#define PE_READ_FLAG_LOADCONFIG			0x00000100UL
#define PE_READ_FLAG_BOUNDIMPORT		0x00000200UL
#define PE_READ_FLAG_DELAYIMPORT		0x00000400UL
#define PE_READ_FLAG_ALL				(PE_READ_FLAG_EXPORT | PE_READ_FLAG_IMPORT | PE_READ_FLAG_RESOURCE | PE_READ_FLAG_EXCEPTION | \
										PE_READ_FLAG_SECURITY | PE_READ_FLAG_BASERELOCATION | PE_READ_FLAG_DEBUG | PE_READ_FLAG_TLS | \
										PE_READ_FLAG_LOADCONFIG | PE_READ_FLAG_BOUNDIMPORT | PE_READ_FLAG_DELAYIMPORT)


CPeFile::CPeFile()
	: m_dwType(0UL)
	, m_dwReadFlag(0UL)
	, m_lpExportManager(NULL)
	, m_lpImportManager(NULL)
	, m_lpResourceManager(NULL)
	, m_lpExceptionManager(NULL)
	, m_lpSecurityManager(NULL)
	, m_lpBaseRelocationManager(NULL)
	, m_lpDebugManager(NULL)
	, m_lpTLSManager(NULL)
	, m_lpLoadConfigManager(NULL)
	, m_lpBoundImportManager(NULL)
	, m_lpDelayImportManager(NULL)
{
}

CPeFile::~CPeFile()
{
	Detach();
}

DWORD CPeFile::Attach(LPCTSTR lpszFilePath)
{
	assert(!m_dwType);
	assert(lpszFilePath);

	int ret = OpenPeFile(lpszFilePath);
	if (ret == -1)
		return 0UL;
	else if (ret == 0)
		return 1UL;
	__try
	{
		m_dwType = CheckHeaders();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		CloseFile();
		return 2UL;
	}
	if (!m_dwType)
		CloseFile();
	return m_dwType;
}

void CPeFile::Detach()
{
	if (m_dwType == IMAGE_NT_SIGNATURE)
		ClearAll();
	if (m_dwType)
	{
		CloseFile();
		m_dwType = 0UL;
	}
}

DWORD CPeFile::GetAttachInfo() const
{
	return m_dwType;
}

HANDLE CPeFile::GetFileHandle() const
{
	assert(m_dwType);
	return m_hFile;
}

DWORD_PTR CPeFile::GetMappedFileStart() const
{
	assert(m_dwType);
	return (DWORD_PTR)m_lpMemory;
}

DWORD_PTR CPeFile::GetMappedFileOffset(DWORD dwFoa) const
{
	assert(m_dwType);
	return MakePtr(DWORD_PTR, m_lpMemory, dwFoa);
}

const IMAGE_DOS_HEADER* CPeFile::GetDosHeader() const
{
	assert(m_dwType);
	return m_lpDosHeader;
}

DWORD CPeFile::GetDosEntryPoint() const
{
	assert(m_dwType);
	return ((DWORD)m_lpDosHeader->e_cs + (DWORD)m_lpDosHeader->e_cparhdr) * 0x10UL + (DWORD)m_lpDosHeader->e_ip;
}

const IMAGE_NT_HEADERS32* CPeFile::GetNtHeader() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE || m_dwType == IMAGE_OS2_SIGNATURE || m_dwType == IMAGE_OS2_SIGNATURE_LE);
	return m_lpNtHeader;
}

BOOL CPeFile::Is64Bit() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	return m_b64Bit;
}

ULONGLONG CPeFile::GetImageBase() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (m_b64Bit)
		return ((IMAGE_NT_HEADERS64*)m_lpNtHeader)->OptionalHeader.ImageBase;
	return (ULONGLONG)m_lpNtHeader->OptionalHeader.ImageBase;
}

const IMAGE_DATA_DIRECTORY* CPeFile::GetDataDirectory() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (m_b64Bit)
		return ((IMAGE_NT_HEADERS64*)m_lpNtHeader)->OptionalHeader.DataDirectory;
	return m_lpNtHeader->OptionalHeader.DataDirectory;
}

DWORD CPeFile::GetDataDirectoryEntryRva(DWORD dwIndex) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	return GetDataDirectory()[dwIndex].VirtualAddress;
}

const IMAGE_SECTION_HEADER* CPeFile::GetSectionHeader(LPWORD lpSectionNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (lpSectionNum)
		*lpSectionNum = m_lpNtHeader->FileHeader.NumberOfSections;
	return m_lpSectionHeader;
}

BOOL CPeFile::RvaToFoa(DWORD dwRva, LPDWORD lpFoa, LPWORD lpSection) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	WORD wSectionNum = m_lpNtHeader->FileHeader.NumberOfSections;
	DWORD dwAlignment = m_lpNtHeader->OptionalHeader.SectionAlignment;
	for (WORD i = 0; i < wSectionNum; ++i)
	{
		DWORD dwBegin = m_lpSectionHeader[i].VirtualAddress;
		if (i == 0U && dwRva < dwBegin)
		{
			if (lpFoa)
				*lpFoa = dwRva;
			if (lpSection)
				*lpSection = (WORD)-1;
			return TRUE;
		}
		DWORD dwBlockCount = m_lpSectionHeader[i].SizeOfRawData / dwAlignment;
		dwBlockCount += m_lpSectionHeader[i].SizeOfRawData % dwAlignment ? 1 : 0;
		if (dwRva >= dwBegin && dwRva < dwBegin + dwBlockCount * dwAlignment)
		{
			if (lpFoa)
				*lpFoa = m_lpSectionHeader[i].PointerToRawData + dwRva - dwBegin;
			if (lpSection)
				*lpSection = (WORD)i;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CPeFile::FoaToRva(DWORD dwFoa, LPDWORD lpRva, LPWORD lpSection) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	WORD wSectionNum = m_lpNtHeader->FileHeader.NumberOfSections;
	for (WORD i = 0; i < wSectionNum; ++i)
	{
		DWORD dwBegin = m_lpSectionHeader[i].PointerToRawData;
		if (i == 0U && dwFoa < dwBegin)
		{
			if (lpRva)
				*lpRva = dwFoa;
			if (lpSection)
				*lpSection = (WORD)-1;
			return TRUE;
		}
		if (dwFoa >= dwBegin && dwFoa < dwBegin + m_lpSectionHeader[i].SizeOfRawData)
		{
			if (lpRva)
				*lpRva = m_lpSectionHeader[i].VirtualAddress + (dwFoa - m_lpSectionHeader[i].PointerToRawData);
			if (lpSection)
				*lpSection = (WORD)i;
			return TRUE;
		}
	}
	return FALSE;
}

DWORD CPeFile::VaToRva(DWORD dwVa) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	return dwVa - (DWORD)GetImageBase();
}

DWORD CPeFile::VaToRva(ULONGLONG ullVa) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	return (DWORD)(ullVa - GetImageBase());
}

ULONGLONG CPeFile::RvaToVa(DWORD dwRva) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	return GetImageBase() + (ULONGLONG)dwRva;
}

BOOL CPeFile::ReadExport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadExport())
		return TRUE;
	__try
	{
		if (ReadExportAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_EXPORT;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadImport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadImport())
		return TRUE;
	__try
	{
		if (ReadImportAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_IMPORT;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadResource()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadResource())
		return TRUE;
	__try
	{
		if (ReadResourceAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_RESOURCE;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadException()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadException())
		return TRUE;
	__try
	{
		if (ReadExceptionAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_EXCEPTION;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadSecurity()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadSecurity())
		return TRUE;
	__try
	{
		if (ReadSecurityAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_SECURITY;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadBaseRelocation()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadBaseRelocation())
		return TRUE;
	__try
	{
		if (ReadBaseRelocationAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_BASERELOCATION;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadDebug()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadDebug())
		return TRUE;
	__try
	{
		if (ReadDebugAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_DEBUG;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadTLS()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadTLS())
		return TRUE;
	__try
	{
		if (ReadTLSAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_TLS;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadLoadConfig()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadLoadConfig())
		return TRUE;
	__try
	{
		if (ReadLoadConfigAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_LOADCONFIG;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadBoundImport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadBoundImport())
		return TRUE;
	__try
	{
		if (ReadBoundImportAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_BOUNDIMPORT;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

BOOL CPeFile::ReadDelayImport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadDelayImport())
		return TRUE;
	__try
	{
		if (ReadDelayImportAux())
		{
			m_dwReadFlag |= PE_READ_FLAG_DELAYIMPORT;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}

void CPeFile::ClearExport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadExport())
	{
		ClearExportAux();
		m_dwReadFlag &= ~PE_READ_FLAG_EXPORT;
	}
}

void CPeFile::ClearImport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadImport())
	{
		ClearImportAux();
		m_dwReadFlag &= ~PE_READ_FLAG_IMPORT;
	}
}

void CPeFile::ClearResource()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadResource())
	{
		ClearResourceAux();
		m_dwReadFlag &= ~PE_READ_FLAG_RESOURCE;
	}
}

void CPeFile::ClearException()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadException())
	{
		ClearExceptionAux();
		m_dwReadFlag &= ~PE_READ_FLAG_EXCEPTION;
	}
}

void CPeFile::ClearSecurity()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadSecurity())
	{
		ClearSecurityAux();
		m_dwReadFlag &= ~PE_READ_FLAG_SECURITY;
	}
}

void CPeFile::ClearBaseRelocation()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadBaseRelocation())
	{
		ClearBaseRelocationAux();
		m_dwReadFlag &= ~PE_READ_FLAG_BASERELOCATION;
	}
}

void CPeFile::ClearDebug()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadDebug())
	{
		ClearDebugAux();
		m_dwReadFlag &= ~PE_READ_FLAG_DEBUG;
	}
}

void CPeFile::ClearTLS()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadTLS())
	{
		ClearTLSAux();
		m_dwReadFlag &= ~PE_READ_FLAG_TLS;
	}
}

void CPeFile::ClearLoadConfig()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadLoadConfig())
	{
		ClearLoadConfigAux();
		m_dwReadFlag &= ~PE_READ_FLAG_LOADCONFIG;
	}
}

void CPeFile::ClearBoundImport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadBoundImport())
	{
		ClearBoundImportAux();
		m_dwReadFlag &= ~PE_READ_FLAG_BOUNDIMPORT;
	}
}

void CPeFile::ClearDelayImport()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (IsReadDelayImport())
	{
		ClearDelayImportAux();
		m_dwReadFlag &= ~PE_READ_FLAG_DELAYIMPORT;
	}
}

void CPeFile::ClearAll()
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (m_dwReadFlag /*& PE_READ_FLAG_ALL*/)
	{
		ClearExportAux();
		ClearImportAux();
		ClearResourceAux();
		ClearSecurityAux();
		ClearBaseRelocationAux();
		ClearDebugAux();
		ClearTLSAux();
		ClearLoadConfigAux();
		ClearBoundImportAux();
		ClearDelayImportAux();
		m_dwReadFlag = 0UL;
	}
}

BOOL CPeFile::IsReadExport() const
{
	return (m_dwReadFlag & PE_READ_FLAG_EXPORT) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadImport() const
{
	return (m_dwReadFlag & PE_READ_FLAG_IMPORT) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadResource() const
{
	return (m_dwReadFlag & PE_READ_FLAG_RESOURCE) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadException() const
{
	return (m_dwReadFlag & PE_READ_FLAG_EXCEPTION) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadSecurity() const
{
	return (m_dwReadFlag & PE_READ_FLAG_SECURITY) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadBaseRelocation() const
{
	return (m_dwReadFlag & PE_READ_FLAG_BASERELOCATION) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadDebug() const
{
	return (m_dwReadFlag & PE_READ_FLAG_DEBUG) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadTLS() const
{
	return (m_dwReadFlag & PE_READ_FLAG_TLS) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadLoadConfig() const
{
	return (m_dwReadFlag & PE_READ_FLAG_LOADCONFIG) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadBoundImport() const
{
	return (m_dwReadFlag & PE_READ_FLAG_BOUNDIMPORT) ? TRUE : FALSE;
}

BOOL CPeFile::IsReadDelayImport() const
{
	return (m_dwReadFlag & PE_READ_FLAG_DELAYIMPORT) ? TRUE : FALSE;
}

const IMAGE_EXPORT_DIRECTORY* CPeFile::GetExportDirectory() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadExport());
	return m_lpExportManager ? m_lpExportManager->m_lpExportDirectory : NULL;
}

const DWORD* CPeFile::GetExportFunction(LPDWORD lpFuncNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadExport());
	if (!m_lpExportManager)
	{
		if (lpFuncNum)
			*lpFuncNum = 0UL;
		return NULL;
	}
	if (lpFuncNum)
		*lpFuncNum = m_lpExportManager->m_lpExportDirectory->NumberOfFunctions;
	return m_lpExportManager->m_lpExportFunction;
}

const DWORD* CPeFile::GetExportName(LPDWORD lpNameNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadExport());
	if (!m_lpExportManager)
	{
		if (lpNameNum)
			*lpNameNum = 0UL;
		return NULL;
	}
	if (lpNameNum)
		*lpNameNum = m_lpExportManager->m_lpExportDirectory->NumberOfNames;
	return m_lpExportManager->m_lpExportName;
}

const WORD* CPeFile::GetExportNameOrdinal(LPDWORD lpNameNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadExport());
	if (!m_lpExportManager)
	{
		if (lpNameNum)
			*lpNameNum = 0UL;
		return NULL;
	}
	if (lpNameNum)
		*lpNameNum = m_lpExportManager->m_lpExportDirectory->NumberOfNames;
	return m_lpExportManager->m_lpExportNameOrdinal;
}

DWORD CPeFile::ParseExportFunction(DWORD dwIndex) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadExport());
	assert(m_lpExportManager);
	assert(dwIndex < m_lpExportManager->m_lpExportDirectory->NumberOfFunctions);
	DWORD i = 0UL;
	for (; i < m_lpExportManager->m_lpExportDirectory->NumberOfNames; ++i)
		if ((DWORD)m_lpExportManager->m_lpExportNameOrdinal[i] == dwIndex)
			return i;
	return i;
}

const IMAGE_IMPORT_DESCRIPTOR* CPeFile::GetImportDescriptor(LPDWORD lpImportDescriptorNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadImport());
	if (!m_lpImportManager)
	{
		if(lpImportDescriptorNum)
			*lpImportDescriptorNum = 0UL;
		return NULL;
	}
	if (lpImportDescriptorNum)
		*lpImportDescriptorNum = m_lpImportManager->m_dwImportDescriptorNum;
	return m_lpImportManager->m_lpImportDescriptor;
}

const IMAGE_THUNK_DATA32* CPeFile::GetImportThunkData(DWORD iImport, LPDWORD lpCount) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadImport());
	assert(m_lpImportManager && iImport < m_lpImportManager->m_dwImportDescriptorNum);
	if(lpCount)
		*lpCount = m_lpImportManager->m_lpThunkDataCount[iImport];
	return m_lpImportManager->m_lpThunkData[iImport];
}

int CPeFile::ParseThunkData(const IMAGE_THUNK_DATA32* lpThunk, LPDWORD lpParam) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(lpThunk);
	if (m_b64Bit)
	{
		if (IMAGE_SNAP_BY_ORDINAL64(((IMAGE_THUNK_DATA64*)lpThunk)->u1.Ordinal))
		{
			if (lpParam)
				*lpParam = IMAGE_ORDINAL64(((IMAGE_THUNK_DATA64*)lpThunk)->u1.Ordinal);
			return 1;
		}
		else
		{
			DWORD dwFoa;
			if (!RvaToFoa((DWORD)(((IMAGE_THUNK_DATA64*)lpThunk)->u1.AddressOfData), &dwFoa))
				return 0;
			if (lpParam)
				*lpParam = dwFoa;
			return 2;
		}
	}
	else
	{
		if (IMAGE_SNAP_BY_ORDINAL32(lpThunk->u1.Ordinal))
		{
			if (lpParam)
				*lpParam = IMAGE_ORDINAL32(lpThunk->u1.Ordinal);
			return 1;
		}
		else
		{
			DWORD dwFoa;
			if (!RvaToFoa((DWORD)lpThunk->u1.AddressOfData, &dwFoa))
				return 0;
			if (lpParam)
				*lpParam = dwFoa;
			return 2;
		}
	}
}

int CPeFile::GetFirstResourceId(PIDTYPE lpFirstID) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadResource());
	assert(lpFirstID);
	if (m_lpResourceManager)
	{
		*lpFirstID = (IDTYPE)m_lpResourceManager;
		return m_lpResourceManager->m_dwLevel ? 1 : 2;
	}
	return FALSE;
}

int CPeFile::GetNextResourceId(IDTYPE Id, DWORD iRes, PIDTYPE NextID) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadResource());
	//assert(Id && iRes < ((CPeResourceManager*)Id)->m_dwResourceDirectoryEntryNum && NextID);
	if (!((CPeResourceManager*)Id)->m_dwLevel)
		return 0;
	CPeResourceManager* lpNextResource = ((CPeResourceManager*)Id)->m_lpNext + iRes;
	if (!lpNextResource->m_lpResourceDirectory)
		return 0;
	*NextID = (IDTYPE)lpNextResource;
	return lpNextResource->m_dwLevel ? 1 : 2;
}

const IMAGE_RESOURCE_DIRECTORY* CPeFile::ParseResourceDirectory(IDTYPE Id, LPDWORD lpEntryNum, LPDWORD lpLevel, IMAGE_RESOURCE_DIRECTORY_ENTRY** lpResourceEntry) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadResource());
	assert(Id);
	IMAGE_RESOURCE_DIRECTORY* lpResouce = ((CPeResourceManager*)Id)->m_lpResourceDirectory;
	if (lpEntryNum)
		*lpEntryNum = ((CPeResourceManager*)Id)->m_dwResourceDirectoryEntryNum;
	if (lpLevel)
		*lpLevel = ((CPeResourceManager*)Id)->m_dwLevel;
	if (lpResourceEntry)
		*lpResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(lpResouce + 1);
	return lpResouce;
}

const IMAGE_RESOURCE_DATA_ENTRY* CPeFile::ParseResourceData(IDTYPE Id) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadResource());
	assert(Id);
	return (IMAGE_RESOURCE_DATA_ENTRY*)((CPeResourceManager*)Id)->m_lpResourceDirectory;
}

int CPeFile::ParseResourceDirectoryEntry(const IMAGE_RESOURCE_DIRECTORY_ENTRY* lpEntry, LPDWORD dwParam) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(lpEntry && dwParam);
	if (lpEntry->NameIsString)
	{
		*dwParam = (DWORD)((DWORD_PTR)m_lpResourceManager->m_lpResourceDirectory - GetMappedFileStart()) + (DWORD)lpEntry->NameOffset;
		return 2;
	}
	*dwParam = (DWORD)lpEntry->Id;
	return 1;
}

const IMAGE_RUNTIME_FUNCTION_ENTRY* CPeFile::GetRuntimeFunction(LPDWORD lpRuntimeFunctionNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadException());
	if (!m_lpExceptionManager)
	{
		if (lpRuntimeFunctionNum)
			*lpRuntimeFunctionNum = 0UL;
		return NULL;
	}
	if (lpRuntimeFunctionNum)
		*lpRuntimeFunctionNum = m_lpExceptionManager->m_dwRuntimeFunctionNum;
	return m_lpExceptionManager->m_lpRuntimeFunctionStart;
}

const WIN_CERTIFICATE* const* CPeFile::GetCertificate(LPDWORD lpCertificateNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadSecurity());
	if (!m_lpSecurityManager)
	{
		if (lpCertificateNum)
			*lpCertificateNum = 0UL;
		return NULL;
	}
	if (lpCertificateNum)
		*lpCertificateNum = m_lpSecurityManager->m_dwSecuritNum;
	return m_lpSecurityManager->m_lpSecurity;
}

const IMAGE_BASE_RELOCATION* const* CPeFile::GetBaseRelocation(LPDWORD lpBaseRelocationNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadBaseRelocation());
	assert(lpBaseRelocationNum);
	if (!m_lpBaseRelocationManager)
	{
		*lpBaseRelocationNum = 0UL;
		return NULL;
	}
	*lpBaseRelocationNum = m_lpBaseRelocationManager->m_dwBaseRelocationNum;
	return m_lpBaseRelocationManager->m_lpBaseRelocation;
}

const WORD* CPeFile::GetBaseRelocationBlock(const IMAGE_BASE_RELOCATION* lpBaseRelocation, LPDWORD lpCount) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadBaseRelocation());
	assert(lpBaseRelocation);
	if (lpCount)
		*lpCount = (lpBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
	return (WORD*)(lpBaseRelocation + 1);
}

WORD CPeFile::ParseBaseRelocationBlock(WORD wBaseRelocationBlock, LPWORD lpParam)
{
	if (lpParam)
		*lpParam = wBaseRelocationBlock & 0x0FFF;
	return (wBaseRelocationBlock & 0xF000) >> 12;
}

const IMAGE_DEBUG_DIRECTORY* CPeFile::GetDebugDirectory(LPDWORD lpDebugDirectoryNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadDebug());
	if (!m_lpDebugManager)
	{
		if (lpDebugDirectoryNum)
			*lpDebugDirectoryNum = 0UL;
		return NULL;
	}
	if (lpDebugDirectoryNum)
		*lpDebugDirectoryNum = m_lpDebugManager->m_dwDebugDirectoryNum;
	return m_lpDebugManager->m_lpDebugDirectory;
}

LPCVOID CPeFile::GetDebugInfoStart(DWORD dwIndex)
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadDebug());
	assert(m_lpDebugManager && dwIndex < m_lpDebugManager->m_dwDebugDirectoryNum);
	if (m_lpDebugManager->m_lpDebugDirectory[dwIndex].PointerToRawData)
		return (LPCVOID)GetMappedFileOffset(m_lpDebugManager->m_lpDebugDirectory[dwIndex].PointerToRawData);
	else if (m_lpDebugManager->m_lpDebugDirectory[dwIndex].AddressOfRawData)
	{
		DWORD dwFoa;
		if (RvaToFoa(m_lpDebugManager->m_lpDebugDirectory[dwIndex].AddressOfRawData, &dwFoa))
			return (LPCVOID)GetMappedFileOffset(dwFoa);
	}
	return NULL;
}

const IMAGE_TLS_DIRECTORY32* CPeFile::GetTLSDirectory() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadTLS());
	return m_lpTLSManager ? m_lpTLSManager->m_lpTLSDirectory : NULL;
}

const DWORD* CPeFile::GetTLSCallback(LPDWORD lpCallbackNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadTLS());
	if (!m_lpTLSManager)
	{
		if (lpCallbackNum)
			*lpCallbackNum = 0UL;
		return NULL;
	}
	if (lpCallbackNum)
		*lpCallbackNum = m_lpTLSManager->m_dwTLSCallbackNum;
	return m_lpTLSManager->m_lpTLSCallback;
}

const IMAGE_LOAD_CONFIG_DIRECTORY32* CPeFile::GetLoadConfigDirectory() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadLoadConfig());
	return m_lpLoadConfigManager ? m_lpLoadConfigManager->m_lpLoadConfigDirectory : NULL;
}

const IMAGE_BOUND_IMPORT_DESCRIPTOR* const* CPeFile::GetBoundImportDescriptor(LPDWORD lpBoundImportNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadBoundImport());
	if (!m_lpBoundImportManager)
	{
		if (lpBoundImportNum)
			*lpBoundImportNum = 0UL;
		return NULL;
	}
	if (lpBoundImportNum)
		*lpBoundImportNum = m_lpBoundImportManager->m_dwBoundImportDescriptorNum;
	return m_lpBoundImportManager->m_lpBoundImportDescriptor;
}

const IMAGE_BOUND_FORWARDER_REF* CPeFile::GetBoundImportForwarderRef(DWORD iBoundImport, LPDWORD lpRefNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadBoundImport());
	assert(m_lpBoundImportManager && iBoundImport < m_lpBoundImportManager->m_dwBoundImportDescriptorNum);
	if(lpRefNum)
		*lpRefNum = m_lpBoundImportManager->m_lpBoundImportDescriptor[iBoundImport]->NumberOfModuleForwarderRefs;
	return (IMAGE_BOUND_FORWARDER_REF*)(m_lpBoundImportManager->m_lpBoundImportDescriptor[iBoundImport] + 1);
}

const IMAGE_DELAYLOAD_DESCRIPTOR* CPeFile::GetDelayImportDescriptor(LPDWORD lpDelayImportNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	assert(IsReadDelayImport());
	if (!m_lpDelayImportManager)
	{
		if (lpDelayImportNum)
			*lpDelayImportNum = 0UL;
		return NULL;
	}
	if (lpDelayImportNum)
		*lpDelayImportNum = m_lpDelayImportManager->m_dwDelayImportDescriptorNum;
	return m_lpDelayImportManager->m_lpDelayImportDescriptor;
}

int CPeFile::OpenPeFile(LPCTSTR lpszFilePath)
{
	m_hFile = ::CreateFile(lpszFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (m_hFile != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER liFileSize;
		if (::GetFileSizeEx(m_hFile, &liFileSize) && liFileSize.QuadPart == 0LL)
		{
			::CloseHandle(m_hFile);
			return -1;
		}
		m_hFileMap = ::CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0UL, 0UL, NULL);
		if (m_hFileMap)
		{
			m_lpMemory = ::MapViewOfFile(m_hFileMap, FILE_MAP_READ, 0UL, 0UL, 0U); //32位程序打开数G文件会失败
			if (m_lpMemory)
				return 1;
			::CloseHandle(m_hFileMap);
		}
		::CloseHandle(m_hFile);
	}
	return 0;
}

void CPeFile::CloseFile()
{
	__try
	{
		::UnmapViewOfFile(m_lpMemory);
		::CloseHandle(m_hFileMap);
		::CloseHandle(m_hFile);
	}
	__except (1)
	{

	}
	
}

DWORD CPeFile::CheckHeaders()
{
	m_lpDosHeader = (IMAGE_DOS_HEADER*)m_lpMemory;
	if (m_lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0UL;
	if (!m_lpDosHeader->e_lfanew)
		return (DWORD)IMAGE_DOS_SIGNATURE;
	m_lpNtHeader = MakePtr(IMAGE_NT_HEADERS32*, m_lpMemory, m_lpDosHeader->e_lfanew);
	if (IsBadReadPtr((unsigned long*)m_lpNtHeader, sizeof(unsigned long)))
		return 0UL;
	if (IsBadReadPtr((unsigned long*)&m_lpNtHeader->Signature, sizeof(unsigned long)))
		return 0UL;
	if (LOWORD(m_lpNtHeader->Signature) == IMAGE_OS2_SIGNATURE || LOWORD(m_lpNtHeader->Signature) == IMAGE_OS2_SIGNATURE_LE)
		return (DWORD)LOWORD(m_lpNtHeader->Signature);
	if (m_lpNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0UL;
	switch (m_lpNtHeader->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		m_b64Bit = FALSE;
		break;
	case  IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_b64Bit = TRUE;
		break;
	default:
		return 0UL;
	}
	m_lpSectionHeader = (IMAGE_SECTION_HEADER*)IMAGE_FIRST_SECTION(m_lpNtHeader);
	return (DWORD)IMAGE_NT_SIGNATURE;
}

BOOL CPeFile::ReadExportAux()
{
	DWORD dwExportRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (dwExportRva)
	{
		DWORD dwExportFoa;
		if (!RvaToFoa(dwExportRva, &dwExportFoa))
			return FALSE;
		m_lpExportManager = new CPeExportManager;
		if (!m_lpExportManager->Initialize((IMAGE_EXPORT_DIRECTORY*)GetMappedFileOffset(dwExportFoa), this))
		{
			ClearExportAux();
			return FALSE;
		}
	}
	return TRUE;
}

BOOL CPeFile::ReadImportAux()
{
	DWORD dwImportRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (dwImportRva)
	{
		DWORD dwImportFoa;
		if (!RvaToFoa(dwImportRva, &dwImportFoa))
			return FALSE;
		m_lpImportManager = new CPeImportManager;
		if (!m_lpImportManager->Initialize((IMAGE_IMPORT_DESCRIPTOR*)GetMappedFileOffset(dwImportFoa), this))
		{
			ClearImportAux();
			return FALSE;
		}
	}
	return TRUE;
}

BOOL CPeFile::ReadResourceAux()
{
	DWORD dwResourceRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (dwResourceRva)
	{
		DWORD dwResourceFoa;
		if (!RvaToFoa(dwResourceRva, &dwResourceFoa))
			return FALSE;
		m_lpResourceManager = new CPeResourceManager((IMAGE_RESOURCE_DIRECTORY*)GetMappedFileOffset(dwResourceFoa));
	}
	return TRUE;
}

BOOL CPeFile::ReadExceptionAux()
{
	DWORD dwExceptionRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
	if (dwExceptionRva)
	{
		DWORD dwExceptionFoa;
		if (!RvaToFoa(dwExceptionRva, &dwExceptionFoa))
			return FALSE;
		m_lpExceptionManager = new CPeExceptionManager((IMAGE_RUNTIME_FUNCTION_ENTRY*)GetMappedFileOffset(dwExceptionFoa), this);
	}
	return TRUE;
}

BOOL CPeFile::ReadSecurityAux()
{
	DWORD dwSecurityFoa = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_SECURITY); //由于不会被映射到内存中，VirtualAddress是FOA，而不是一个RVA
	if (dwSecurityFoa)
		m_lpSecurityManager = new CPeSecurityManager((WIN_CERTIFICATE*)GetMappedFileOffset(dwSecurityFoa), GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	return TRUE;
}

BOOL CPeFile::ReadBaseRelocationAux()
{
	DWORD dwBaseRelocationRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (dwBaseRelocationRva)
	{
		DWORD dwBaseRelocationFoa;
		if (!RvaToFoa(dwBaseRelocationRva, &dwBaseRelocationFoa))
			return FALSE;
		m_lpBaseRelocationManager = new CPeBaseRelocationManager((IMAGE_BASE_RELOCATION*)GetMappedFileOffset(dwBaseRelocationFoa));
	}
	return TRUE;
}

BOOL CPeFile::ReadDebugAux()
{
	DWORD dwDebugRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_DEBUG);
	if (dwDebugRva)
	{
		DWORD dwDebugFoa;
		if (!RvaToFoa(dwDebugRva, &dwDebugFoa))
			return FALSE;
		m_lpDebugManager = new CPeDebugManager((IMAGE_DEBUG_DIRECTORY*)GetMappedFileOffset(dwDebugFoa), this);
	}
	return TRUE;
}

BOOL CPeFile::ReadTLSAux()
{
	DWORD dwTLSRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_TLS);
	if (dwTLSRva)
	{
		DWORD dwTLSFoa;
		if (!RvaToFoa(dwTLSRva, &dwTLSFoa))
			return FALSE;
		m_lpTLSManager = new CPeTLSManager;
		if (!m_lpTLSManager->Initialize((IMAGE_TLS_DIRECTORY32*)GetMappedFileOffset(dwTLSFoa), this))
		{
			ClearTLSAux();
			return FALSE;
		}
	}
	return TRUE;
}

BOOL CPeFile::ReadLoadConfigAux()
{
	DWORD dwLoadConfigRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	if (dwLoadConfigRva)
	{
		DWORD dwLoadConfigFoa;
		if (!RvaToFoa(dwLoadConfigRva, &dwLoadConfigFoa))
			return FALSE;
		m_lpLoadConfigManager = new CPeLoadConfigManager((IMAGE_LOAD_CONFIG_DIRECTORY32*)GetMappedFileOffset(dwLoadConfigFoa));
	}
	return TRUE;
}

BOOL CPeFile::ReadBoundImportAux()
{
	DWORD dwBoundImportRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
	if (dwBoundImportRva)
	{
		DWORD dwBoundImportFoa;
		if (!RvaToFoa(dwBoundImportRva, &dwBoundImportFoa))
			return FALSE;
		m_lpBoundImportManager = new CPeBoundImportManager((IMAGE_BOUND_IMPORT_DESCRIPTOR*)GetMappedFileOffset(dwBoundImportFoa));
	}
	return TRUE;
}

BOOL CPeFile::ReadDelayImportAux()
{
	DWORD dwDelayImportRva = GetDataDirectoryEntryRva(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	if (dwDelayImportRva)
	{
		DWORD dwDelayImportFoa;
		if (!RvaToFoa(dwDelayImportRva, &dwDelayImportFoa))
			return FALSE;
		m_lpDelayImportManager = new CPeDelayImportManager((IMAGE_DELAYLOAD_DESCRIPTOR*)GetMappedFileOffset(dwDelayImportFoa));
	}
	return TRUE;
}

void CPeFile::ClearExportAux()
{
	delete m_lpExportManager;
	m_lpExportManager = NULL;
}

void CPeFile::ClearImportAux()
{
	delete m_lpImportManager;
	m_lpImportManager = NULL;
}

void CPeFile::ClearResourceAux()
{
	delete m_lpResourceManager;
	m_lpResourceManager = NULL;
}

void CPeFile::ClearExceptionAux()
{
	delete m_lpExceptionManager;
	m_lpExceptionManager = NULL;
}

void CPeFile::ClearSecurityAux()
{
	delete m_lpSecurityManager;
	m_lpSecurityManager = NULL;
}

void CPeFile::ClearBaseRelocationAux()
{
	delete m_lpBaseRelocationManager;
	m_lpBaseRelocationManager = NULL;
}

void CPeFile::ClearDebugAux()
{
	delete m_lpDebugManager;
	m_lpDebugManager = NULL;
}

void CPeFile::ClearTLSAux()
{
	delete m_lpTLSManager;
	m_lpTLSManager = NULL;
}

void CPeFile::ClearLoadConfigAux()
{
	delete m_lpLoadConfigManager;
	m_lpLoadConfigManager = NULL;
}

void CPeFile::ClearBoundImportAux()
{
	delete m_lpBoundImportManager;
	m_lpBoundImportManager = NULL;
}

void CPeFile::ClearDelayImportAux()
{
	delete m_lpDelayImportManager;
	m_lpDelayImportManager = NULL;
}



//CPeFile::CPeExportManager类

CPeFile::CPeExportManager::CPeExportManager()
	: m_lpExportFunction(NULL)
	, m_lpExportName(NULL)
	, m_lpExportNameOrdinal(NULL)
{
}

BOOL CPeFile::CPeExportManager::Initialize(IMAGE_EXPORT_DIRECTORY* lpExportStart, const CPeFile* lpPe)
{
	m_lpExportDirectory = lpExportStart;
	DWORD nExportFunction = m_lpExportDirectory->NumberOfFunctions;
	if (nExportFunction)
	{
		DWORD dwExportFuncFoa;
		if (!lpPe->RvaToFoa(m_lpExportDirectory->AddressOfFunctions, &dwExportFuncFoa))
			return FALSE;
		m_lpExportFunction = (DWORD*)lpPe->GetMappedFileOffset(dwExportFuncFoa);
	}
	DWORD nExportName = m_lpExportDirectory->NumberOfNames;
	if (nExportName)
	{
		m_lpExportName = new DWORD[nExportName];
		DWORD dwExportNameFoa;
		if (!lpPe->RvaToFoa(m_lpExportDirectory->AddressOfNames, &dwExportNameFoa))
			return FALSE;
		m_lpExportName = (DWORD*)lpPe->GetMappedFileOffset(dwExportNameFoa);
		DWORD dwExportNameOrdinalFoa;
		if (!lpPe->RvaToFoa(m_lpExportDirectory->AddressOfNameOrdinals, &dwExportNameOrdinalFoa))
			return FALSE;
		m_lpExportNameOrdinal = (WORD*)lpPe->GetMappedFileOffset(dwExportNameOrdinalFoa);
	}
	return TRUE;
}


//CPeFile::CPeImportManager类

CPeFile::CPeImportManager::CPeImportManager()
	: m_lpThunkDataCount(NULL)
	, m_lpThunkData(NULL)
{
}

CPeFile::CPeImportManager::~CPeImportManager()
{
	delete[] m_lpThunkData;
	delete[] m_lpThunkDataCount;
}

BOOL CPeFile::CPeImportManager::Initialize(IMAGE_IMPORT_DESCRIPTOR* lpImportStart, const CPeFile* lpPe)
{
	m_lpImportDescriptor = lpImportStart;
	m_dwImportDescriptorNum = 0UL;
	while (lpImportStart->Name)
	{
		++m_dwImportDescriptorNum;
		++lpImportStart;
	}
	if (m_dwImportDescriptorNum)
	{
		m_lpThunkDataCount = new DWORD[m_dwImportDescriptorNum];
		m_lpThunkData = new IMAGE_THUNK_DATA32*[m_dwImportDescriptorNum];
		for (DWORD i = 0; i < m_dwImportDescriptorNum; ++i)
		{
			m_lpThunkDataCount[i] = 0;
			m_lpThunkData[i] = NULL;
		}
		for (DWORD i = 0; i < m_dwImportDescriptorNum; ++i)
		{
			DWORD dwThunk = m_lpImportDescriptor[i].OriginalFirstThunk;
			if (!dwThunk)
				dwThunk = m_lpImportDescriptor[i].FirstThunk;
			DWORD dwThunkFoa;
			if (!lpPe->RvaToFoa(dwThunk, &dwThunkFoa))
				return FALSE;
			m_lpThunkData[i] = (IMAGE_THUNK_DATA32*)lpPe->GetMappedFileOffset(dwThunkFoa);
			if(lpPe->Is64Bit())
			{
				IMAGE_THUNK_DATA64* lpThunkStart = (IMAGE_THUNK_DATA64*)m_lpThunkData[i];
				while (lpThunkStart->u1.AddressOfData)
				{
					++m_lpThunkDataCount[i];
					++lpThunkStart;
				}
			}
			else
			{
				IMAGE_THUNK_DATA32* lpThunkStart = m_lpThunkData[i];
				while (lpThunkStart->u1.AddressOfData)
				{
					++m_lpThunkDataCount[i];
					++lpThunkStart;
				}
			}
		}
	}
	return TRUE;
}


//CPeFile::CPeResourceManager类

CPeFile::CPeResourceManager::CPeResourceManager()
	: m_lpResourceDirectory(NULL)
	, m_lpNext(NULL)
{
}

CPeFile::CPeResourceManager::CPeResourceManager(IMAGE_RESOURCE_DIRECTORY* lpResourceStart)
	: m_lpResourceDirectory(NULL)
	, m_lpNext(NULL)
{
	assert(lpResourceStart);
	SearchResource(lpResourceStart, 1, lpResourceStart);
}

CPeFile::CPeResourceManager::~CPeResourceManager()
{
	delete[] m_lpNext;
}

void CPeFile::CPeResourceManager::SearchResource(IMAGE_RESOURCE_DIRECTORY* lpResourceDirectory, DWORD dwLevel, IMAGE_RESOURCE_DIRECTORY* lpResourceStart)
{
	m_lpResourceDirectory = lpResourceDirectory;
	m_dwLevel = dwLevel;
	if (!dwLevel || !lpResourceDirectory)
	{
		m_dwResourceDirectoryEntryNum = 0UL;
		return;
	}
	m_dwResourceDirectoryEntryNum = (DWORD)lpResourceDirectory->NumberOfNamedEntries + (DWORD)lpResourceDirectory->NumberOfIdEntries;
	if (m_dwResourceDirectoryEntryNum)
	{
		m_lpNext = new CPeResourceManager[m_dwResourceDirectoryEntryNum];
		IMAGE_RESOURCE_DIRECTORY_ENTRY* lpResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(lpResourceDirectory + 1);
		for (DWORD i = 0; i < m_dwResourceDirectoryEntryNum; ++i)
		{
			DWORD dwOffset = (DWORD)(lpResourceEntry + i)->OffsetToDirectory;
			if (dwOffset)
			{
				IMAGE_RESOURCE_DIRECTORY* lpNextDirectory = MakePtr(IMAGE_RESOURCE_DIRECTORY*, lpResourceStart, dwOffset);
				if ((lpResourceEntry + i)->DataIsDirectory)
					m_lpNext[i].SearchResource(lpNextDirectory, dwLevel + 1, lpResourceStart);
				else
					m_lpNext[i].SearchResource(lpNextDirectory, 0, NULL);
			}
			else
				m_lpNext[i].SearchResource(NULL, dwLevel + 1, NULL);
		}
	}
}


//CPeFile::CPeExceptionManager类

CPeFile::CPeExceptionManager::CPeExceptionManager(IMAGE_RUNTIME_FUNCTION_ENTRY* lpRuntimeFunctionStart, const CPeFile* lpPe)
{
	//早期的Borland链接器Size域为结构的数目，而不是字节大小
	m_dwRuntimeFunctionNum = lpPe->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	m_lpRuntimeFunctionStart = lpRuntimeFunctionStart;
}


//CPeFile::CPeSecurityManager类

CPeFile::CPeSecurityManager::CPeSecurityManager(WIN_CERTIFICATE* lpSecurityStart, int dwSize)
	: m_lpSecurity(NULL)
{
	WIN_CERTIFICATE* pCertificate = lpSecurityStart;
	m_dwSecuritNum = 0UL;
	while (dwSize && pCertificate->dwLength)
	{
		++m_dwSecuritNum;
		dwSize -= pCertificate->dwLength;
		pCertificate = MakePtr(WIN_CERTIFICATE*, pCertificate, pCertificate->dwLength);
	}
	if (m_dwSecuritNum)
	{
		m_lpSecurity = new WIN_CERTIFICATE*[m_dwSecuritNum];
		m_lpSecurity[0] = lpSecurityStart;
		for (DWORD i = 1; i < m_dwSecuritNum; ++i)
			m_lpSecurity[i] = MakePtr(WIN_CERTIFICATE*, pCertificate, pCertificate->dwLength);
	}
}

CPeFile::CPeSecurityManager::~CPeSecurityManager()
{
	delete[] m_lpSecurity;
}


//CPeFile::CPeBaseRelocationManager类

CPeFile::CPeBaseRelocationManager::CPeBaseRelocationManager(IMAGE_BASE_RELOCATION* lpBaseRelocationStart)
	: m_lpBaseRelocation(NULL)
{
	IMAGE_BASE_RELOCATION* lpBaseRelocation = lpBaseRelocationStart;
	m_dwBaseRelocationNum = 0UL;
	while (lpBaseRelocation->VirtualAddress)
	{
		++m_dwBaseRelocationNum;
		lpBaseRelocation = MakePtr(IMAGE_BASE_RELOCATION*, lpBaseRelocation, lpBaseRelocation->SizeOfBlock);
	}
	if (m_dwBaseRelocationNum)
	{
		m_lpBaseRelocation = new IMAGE_BASE_RELOCATION*[m_dwBaseRelocationNum];
		m_lpBaseRelocation[0] = lpBaseRelocationStart;
		for (DWORD i = 1; i < m_dwBaseRelocationNum; ++i)
			m_lpBaseRelocation[i] = MakePtr(IMAGE_BASE_RELOCATION*, m_lpBaseRelocation[i - 1], m_lpBaseRelocation[i - 1]->SizeOfBlock);
	}
}

CPeFile::CPeBaseRelocationManager::~CPeBaseRelocationManager()
{
	delete[] m_lpBaseRelocation;
}


//CPeFile::CPeDebugManager类

CPeFile::CPeDebugManager::CPeDebugManager(IMAGE_DEBUG_DIRECTORY* lpDebugStart, const CPeFile* lpPe)
{
	//早期的Borland链接器Size域为结构的数目，而不是字节大小
	WORD wSectionNum = lpPe->m_lpNtHeader->FileHeader.NumberOfSections;
	for (WORD i = 0; i < wSectionNum; ++i)
	{
		if (!strncmp((const char*)lpPe->m_lpSectionHeader[i].Name, ".debug", 6))
			if (lpPe->m_lpSectionHeader[i].VirtualAddress == lpPe->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)
			{
				m_dwDebugDirectoryNum = lpPe->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
				m_lpDebugDirectory = (IMAGE_DEBUG_DIRECTORY*)lpPe->GetMappedFileOffset(lpDebugStart->PointerToRawData);
				return;
			}
	}
	m_dwDebugDirectoryNum = lpPe->GetDataDirectory()[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
	m_lpDebugDirectory = lpDebugStart;
}


//CPeFile::CPeTLSManager类

BOOL CPeFile::CPeTLSManager::Initialize(IMAGE_TLS_DIRECTORY32* lpTLSStart, const CPeFile* lpPe)
{
	m_dwTLSCallbackNum = 0UL;
	if (lpPe->Is64Bit())
	{
		IMAGE_TLS_DIRECTORY64* lpTLSStart64 = (IMAGE_TLS_DIRECTORY64*)lpTLSStart;
		if (lpTLSStart64->AddressOfCallBacks)
		{
			DWORD dwRva = lpPe->VaToRva(lpTLSStart64->AddressOfCallBacks);
			DWORD dwFoa;
			if (!lpPe->RvaToFoa(dwRva, &dwFoa))
				return FALSE;
			ULONGLONG* lpCallbackStart = (ULONGLONG*)lpPe->GetMappedFileOffset(dwFoa);
			m_lpTLSCallback = (DWORD*)lpCallbackStart;
			while (*lpCallbackStart++)
				++m_dwTLSCallbackNum;
		}
		else
			m_lpTLSCallback = NULL;
		m_lpTLSDirectory = lpTLSStart;
	}
	else
	{
		if (lpTLSStart->AddressOfCallBacks)
		{
			DWORD dwRva = lpPe->VaToRva(lpTLSStart->AddressOfCallBacks);
			DWORD dwFoa;
			if (!lpPe->RvaToFoa(dwRva, &dwFoa))
				return FALSE;
			DWORD* lpCallbackStart = (DWORD*)lpPe->GetMappedFileOffset(dwFoa);
			m_lpTLSCallback = lpCallbackStart;
			while (*lpCallbackStart++)
				++m_dwTLSCallbackNum;
		}
		else
			m_lpTLSCallback = NULL;
		m_lpTLSDirectory = lpTLSStart;
	}
	return TRUE;
}


//CPeFile::CPeLoadConfigManager类

CPeFile::CPeLoadConfigManager::CPeLoadConfigManager(IMAGE_LOAD_CONFIG_DIRECTORY32* lpLoadConfigStart)
	: m_lpLoadConfigDirectory(lpLoadConfigStart)
{
}


//CPeFile::CPeBoundImportManager类

CPeFile::CPeBoundImportManager::CPeBoundImportManager(IMAGE_BOUND_IMPORT_DESCRIPTOR* lpBoundImportStart)
	: m_lpBoundImportDescriptor(NULL)
{
	IMAGE_BOUND_IMPORT_DESCRIPTOR* lpBoundImport = lpBoundImportStart;
	m_dwBoundImportDescriptorNum = 0UL;
	while (lpBoundImport->TimeDateStamp || lpBoundImport->OffsetModuleName || lpBoundImport->NumberOfModuleForwarderRefs)
	{
		++m_dwBoundImportDescriptorNum;
		lpBoundImport = MakePtr(IMAGE_BOUND_IMPORT_DESCRIPTOR*, lpBoundImport + 1, lpBoundImport->NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF));
	}
	if (m_dwBoundImportDescriptorNum)
	{
		m_lpBoundImportDescriptor = new IMAGE_BOUND_IMPORT_DESCRIPTOR*[m_dwBoundImportDescriptorNum];
		m_lpBoundImportDescriptor[0] = lpBoundImportStart;
		for (DWORD i = 1; i < m_dwBoundImportDescriptorNum; ++i)
			m_lpBoundImportDescriptor[i] = MakePtr(IMAGE_BOUND_IMPORT_DESCRIPTOR*, m_lpBoundImportDescriptor[i - 1] + 1, m_lpBoundImportDescriptor[i - 1]->NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF));
	}
}

CPeFile::CPeBoundImportManager::~CPeBoundImportManager()
{
	delete[] m_lpBoundImportDescriptor;
}


//CPeFile::CPeDelayImportManager类

CPeFile::CPeDelayImportManager::CPeDelayImportManager(IMAGE_DELAYLOAD_DESCRIPTOR* lpDelayImportStart)
	: m_lpDelayImportDescriptor(lpDelayImportStart)
{
	m_dwDelayImportDescriptorNum = 0UL;
	while (lpDelayImportStart->DllNameRVA)
	{
		++m_dwDelayImportDescriptorNum;
		++lpDelayImportStart;
	}
}
