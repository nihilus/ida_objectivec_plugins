#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <funcs.hpp>
#ifdef _MSC_VER
#include <Windows.h>
#pragma comment(lib,"user32.lib")
#include "thirdparty/glog/basictypes.h"
#include "thirdparty/glog/logging.h"
#endif
#include "objc/objc_string.h"
#include "objc/objc_restore.h"

class PluginMain:public objc::ObjcString,objc::ObjcRestore
{
public:
	PluginMain():seg_initialize_(false){
		hook_to_notification_point(HT_IDP,RuntimeCallbackEvent,NULL);
	}
	~PluginMain(){
		unhook_from_notification_point(HT_IDP,RuntimeCallbackEvent,NULL);
	}
	bool seg_initialize() const{
		return seg_initialize_;
	}
	void set_seg_initialize(){
		seg_initialize_ = true;
	}
	static PluginMain* Instance(bool is_term = false){
		static PluginMain* g_main;
		if(!g_main){
			PluginMain* new_info = new PluginMain;
			if(InterlockedCompareExchangePointer(reinterpret_cast<void**>(&g_main),new_info,NULL)){
				delete new_info;
			}
		}
		if(is_term&&g_main){
			delete g_main;
			g_main = NULL;
		}
		return g_main;
	}
	static int idaapi RuntimeCallbackEvent(void* user_data,int event_id,va_list va){
		return 0;
	}
	static int idaapi Initialize(void){
		if(inf.filetype==f_MACHO&&(ph.id==PLFM_386||ph.id==PLFM_MIPS||ph.id==PLFM_ARM)){
			Instance();
		}
		return PLUGIN_OK;
	}
	static void idaapi Terminate(void){
		if(inf.filetype==f_MACHO&&(ph.id==PLFM_386||ph.id==PLFM_MIPS||ph.id==PLFM_ARM)){
			Instance(true);
		}
	}
	static void idaapi Run(int arg){
		if(inf.filetype==f_MACHO&&(ph.id==PLFM_386||ph.id==PLFM_MIPS||ph.id==PLFM_ARM)){
			if(!Instance()->seg_initialize()){
				Instance()->objc::ObjcRestore::ClassSeg();
				Instance()->objc::ObjcRestore::MetaClassSeg();
				Instance()->objc::ObjcRestore::NlSymbolPtrSeg();
				Instance()->objc::ObjcRestore::ClsRefsSeg();
				Instance()->objc::ObjcRestore::CategorySeg();
				Instance()->objc::ObjcRestore::MessageRefsSeg();
				Instance()->objc::ObjcRestore::CFStringSeg();
				Instance()->objc::ObjcRestore::ModuleInfoSeg();
				Instance()->objc::ObjcRestore::SymbolsSeg();
				Instance()->objc::ObjcRestore::DataSegObjc2();
				Instance()->objc::ObjcRestore::ObjcDataSegObjc2();
				Instance()->objc::ObjcRestore::ObjcConstSegObjc2();
				Instance()->set_seg_initialize();
			}
		}
	}
	static const char* long_comment;
	static const char* about_comment;
	static const char* short_name;
	static const char* hotkey;
private:
	bool seg_initialize_;
	DISALLOW_EVIL_CONSTRUCTORS(PluginMain);
};
const char* PluginMain::long_comment = "this plugin to help you reverse analysis objc";
const char* PluginMain::about_comment = "this is objc reverse analysis assistant";
const char* PluginMain::short_name = "objc_analysis";
const char* PluginMain::hotkey = "Ctrl-A";
//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_FIX,
	PluginMain::Initialize,
	PluginMain::Terminate,
	PluginMain::Run,
	PluginMain::long_comment,
	PluginMain::about_comment,
	PluginMain::short_name,
	PluginMain::hotkey
};
