/*
 * Author:       Broihon
 * Copyright:    Guided Hacking� � 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "PDB_Download.h"

struct CallbackData
{
	InjectionLib * pInjLib = nullptr;
	std::vector<std::pair<int, bool>> info;

	bool connected			= false;
	bool download_finished	= false;
	bool import_finished	= false;
};

void __stdcall pdb_download_update_callback(DownloadProgressWindow * hProgressWindow, void * pData);

void ShowPDBDownload(InjectionLib * InjLib)
{
	CallbackData data;
	data.pInjLib = InjLib;

	std::vector<QString> labels;

	labels.push_back("ntdll.pdb");
	data.info.push_back({ 0, false });
#ifdef _WIN64
	labels.push_back("wntdll.pdb");
	data.info.push_back({ 0, true });
#endif

	auto CurrentOS = QOperatingSystemVersion::current();
	if (CurrentOS >= QOperatingSystemVersion::Windows7 && CurrentOS < QOperatingSystemVersion::Windows8) //no == operator provided
	{
		labels.push_back("kernel32.pdb");
		data.info.push_back({ 1, false });
#ifdef _WIN64
		labels.push_back("wkernel32.pdb");
		data.info.push_back({ 1, true });
#endif
	}

	DownloadProgressWindow * ProgressWindow = new(std::nothrow) DownloadProgressWindow("PDB 下载", labels, "正在等待网络连接...", 300, Q_NULLPTR);
	if (ProgressWindow == Q_NULLPTR)
	{
		THROW("Failed to create download progress window.");
	}

	ProgressWindow->SetCallbackFrequency(25);
	ProgressWindow->SetCallbackArg(&data);
	ProgressWindow->SetCallback(pdb_download_update_callback);
	ProgressWindow->SetCloseValue(PEB_ERR_INTERRUPTED);

	ProgressWindow->show();
	auto ret = ProgressWindow->Execute();

	delete ProgressWindow;

	g_Console->update_external();

	QString error_msg = "";

	if (ret > 0)
	{
		error_msg = "下载/导入失败。错误代码: 0x";
		QString number = QStringLiteral("%1").arg(ret, 8, 0x10, QLatin1Char('0'));
		error_msg += number;
		error_msg += "\n缺少 PDB 文件时注入器无法正常工作。\n请重启注入器。";
	}
	else if (ret < 0)
	{
		InjLib->InterruptDownload();

		switch (ret)
		{
			case PEB_ERR_INTERRUPTED:
				error_msg = "下载已中断。\n缺少 PDB 文件时注入器无法正常工作。\n请重启注入器。";
				break;

			case PEB_ERR_CONNECTION_BLOCKED:
				error_msg = "连接 Microsoft Symbol Server 被阻止。\n这可能由防火墙规则导致。\n缺少 PDB 文件时注入器无法正常工作。\n请重启注入器。";
				break;

			case PEB_ERR_NO_INTERNET:
				error_msg = "网络连接已中断。\n缺少 PDB 文件时注入器无法正常工作。\n请重启注入器。";
				break;

			default:
				error_msg = "未知错误代码。\n缺少 PDB 文件时注入器无法正常工作。\n请重启注入器。";
		}
	}

	if (ret != PDB_ERR_SUCCESS)
	{
		g_Console->update_external();

		StatusBox(false, error_msg);
	}
}

void __stdcall pdb_download_update_callback(DownloadProgressWindow * hProgressWindow, void * pData)
{
	if (!hProgressWindow || !pData)
	{
		THROW("Invalid data passed to update callback\n");

		return;
	}

	auto * data = reinterpret_cast<CallbackData *>(pData);

	auto lib = data->pInjLib;

	if (!data->download_finished)
	{
		if (lib->GetSymbolState() == INJ_ERR_SYMBOL_INIT_NOT_DONE)
		{
			for (UINT i = 0; i < data->info.size(); ++i)
			{
				float progress = lib->GetDownloadProgressEx(data->info[i].first, data->info[i].second);
				hProgressWindow->SetProgress(i, progress);
			}

			if (InternetCheckConnectionW(L"https://msdl.microsoft.com", FLAG_ICC_FORCE_CONNECTION, NULL) == FALSE)
			{
				if (GetLastError() == ERROR_INTERNET_CANNOT_CONNECT)
				{
					data->connected = false;

					hProgressWindow->SetStatus("无法连接到 Microsoft Symbol Server...");
					hProgressWindow->SetDone(PEB_ERR_CONNECTION_BLOCKED);
				}
				else if (data->connected)
				{
					data->connected = false;

					hProgressWindow->SetStatus("正在等待网络连接...");
					hProgressWindow->SetDone(PEB_ERR_NO_INTERNET);
				}
			}
			else
			{
				if (!data->connected)
				{
					data->connected = true;

					hProgressWindow->SetStatus("正在从 Microsoft Symbol Server 下载 PDB 文件...");
				}
			}
		}
		else
		{
			auto symbol_state = lib->GetSymbolState();
			if (symbol_state != INJ_ERR_SUCCESS)
			{
				hProgressWindow->SetDone((int)symbol_state);
			}
			else
			{
				for (UINT i = 0; i < data->info.size(); ++i)
				{
					hProgressWindow->SetProgress(i, 1.0f);
				}

				hProgressWindow->SetStatus("下载完成，正在解析导入...");

				data->download_finished = true;
			}	
		}
	}
	else if (!data->import_finished)
	{
		if (lib->GetImportState() != INJ_ERR_IMPORT_HANDLER_NOT_DONE)
		{
			auto import_state = lib->GetImportState();
			if (import_state != INJ_ERR_SUCCESS)
			{
				hProgressWindow->SetDone((int)import_state);

				return;
			}
			else
			{
				hProgressWindow->SetStatus("导入已解析...");

				data->import_finished = true;
			}
		}		
	}	
	else
	{
		hProgressWindow->SetDone(PDB_ERR_SUCCESS);
	}
}