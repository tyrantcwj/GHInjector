/*
 * Author:       Broihon
 * Copyright:    Guided Hacking� � 2012-2023 Guided Hacking LLC
*/

#include "pch.h"

#include "GuiScanHook.h"

GuiScanHook::GuiScanHook(QWidget * parent, FramelessWindow * FramelessParent, InjectionLib * InjectionLib)
	: QWidget(parent)
{
	ui.setupUi(this);

	if (!InjectionLib)
	{
		THROW("Injection library pointer is NULL.");
	}

	m_InjectionLib		= InjectionLib;
	m_FramelessParent	= FramelessParent;

	ui.lv_scanhook->setSelectionMode(QAbstractItemView::SelectionMode::NoSelection);

	connect(ui.btn_scan, SIGNAL(clicked()), this, SLOT(scan_clicked()));
	connect(ui.btn_unhook, SIGNAL(clicked()), this, SLOT(unhook_clicked()));

	m_Model = new(std::nothrow) QStringListModel(this);
	if (m_Model == Q_NULLPTR)
	{
		THROW("Failed to create string list model for hook scanner.");
	}

	m_HookList << "请先" << "选择进程";

	m_Model->setStringList(m_HookList);
	ui.lv_scanhook->setModel(m_Model);

	if (!m_InjectionLib->LoadingStatus())
	{
		emit StatusBox(false, "找不到 GH 注入库，或未正确加载。");
	}
}

GuiScanHook::~GuiScanHook()
{

}

void GuiScanHook::setItem(const std::vector<std::wstring> & item)
{
	m_HookList.clear();

	for (const auto & i : item)
	{
		m_HookList << QString::fromStdWString(i);
	}

	m_Model->setStringList(m_HookList);
}

std::vector<int> GuiScanHook::get_selected_indices() const
{
	std::vector<int> res;	

	foreach(const QModelIndex & index, ui.lv_scanhook->selectionModel()->selectedIndexes())
	{
		res.push_back(index.row());
	}

	return res;
}

void GuiScanHook::get_from_inj_to_sh(int PID)
{
	m_PID = PID;

	ui.btn_scan->setText("扫描 PID " + QString::number(PID));

	emit scan_clicked();
}

void GuiScanHook::scan_clicked()
{
	update_title("扫描 Hook");

	if (!m_InjectionLib->LoadingStatus())
	{
		setItem({ L"注入库未加载" });
		g_print("Injection library not loaded\n");

		return;
	}

	if (m_PID == 0)
	{
		setItem({ L"请选择进程" });
		g_print("No process selected\n");

		return;
	}

	HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_PID);
	if (!hProc)
	{
		setItem({ L"请选择进程" });
		g_print("Invalid process id\n");

		return;
	}

	DWORD dwExitCode = STILL_ACTIVE;
	if (!GetExitCodeProcess(hProc, &dwExitCode))
	{
		setItem({ L"请选择进程" });
		g_print("Process doesn't exist\n");

		return;
	}

	CloseHandle(hProc);

	if (dwExitCode != STILL_ACTIVE)
	{
		setItem({ L"请选择进程" });
		g_print("Process doesn't exist\n");

		return;
	}

	std::vector<std::wstring> tempHookList;

	bool val_ret = m_InjectionLib->ValidateInjectionFunctions(m_PID, tempHookList);
	if (!val_ret)
	{
		ui.lv_scanhook->setSelectionMode(QAbstractItemView::SelectionMode::NoSelection);
		setItem({ L"扫描 Hook 失败" });
	}
	else if (tempHookList.empty())
	{
		ui.lv_scanhook->setSelectionMode(QAbstractItemView::SelectionMode::NoSelection);
		setItem({ L"未发现 Hook" });
	}
	else
	{
		ui.lv_scanhook->setSelectionMode(QAbstractItemView::SelectionMode::ExtendedSelection);
		setItem(tempHookList);

		auto hook_count = tempHookList.size();

		if (hook_count == 1)
		{
			update_title("发现 1 个 Hook");
		}
		else
		{
			update_title(QString::number(hook_count) + " 个 Hook");
		}
	}
}

void GuiScanHook::unhook_clicked()
{
	if (!m_InjectionLib->LoadingStatus())
	{
		return;
	}

	if (m_PID == 0)
	{
		return;
	}

	std::vector<int> selected = get_selected_indices();
	if (!selected.size())
	{
		return;
	}

	bool res_ret = m_InjectionLib->RestoreInjectionFunctions(selected);
	if (!res_ret)
	{
		StatusBox(false, "恢复 Hook 失败");
	}

	m_HookList.clear();
	m_Model->setStringList(m_HookList);
	scan_clicked();
}

void GuiScanHook::update_title(const QString title)
{
	if (m_FramelessParent)
	{
		m_FramelessParent->setWindowTitle(title);
	}
	else
	{
		this->setWindowTitle(title);
	}
}