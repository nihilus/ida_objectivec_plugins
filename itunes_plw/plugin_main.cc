#include <vector>
#include <string>
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

class PluginMain
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
	bool IsCodeSeg(const segment_t* seg){
		return (segtype(seg->startEA)==SEG_CODE);
	}
	bool IsValidEA(uint32 ea){
		if(inf.minEA <= ea && ea <= inf.maxEA){
			return true;
		}
		else{
			return false;
		}
	}
	const std::string GetCodeSegName(const ea_t& seg_ea){
		char seg_name[1024] = {0};
		if(get_segm_name(getseg(seg_ea),seg_name,1024)>0){
			return (std::string(seg_name));
		}
		else{
			return (std::string(""));
		}
	}
	void CodeTableItemDisp(const ea_t& base,const ea_t& table){
		LOG(INFO)<<__FUNCTION__<<table<<"->"<<(get_original_long(table)+base)<<std::endl;
		if(!IsValidEA(get_original_long(table))){
			patch_long(table,get_original_long(table)+base);
		}
		for(ea_t start=table+4;IsValidEA(start);start=start+4){
			char name[256] = {0};
			if(get_name(BADADDR,start,name,256)!=NULL){
				break;
			}
			if(!IsValidEA(get_original_long(start))){
				uint64 addr = get_original_long(start);
				patch_long(start,addr+base);
				LOG(INFO)<<__FUNCTION__<<start<<"->"<<(addr+base)<<std::endl;
			}
		}
	}
	bool IsAddInstr(){
		return (cmd.itype==NN_add&&cmd.is_canon_insn()&&!strnicmp(cmd.get_canon_mnem(),"add",3)&&
			cmd.size==7&&cmd.Op1.dtyp==dt_dword&&cmd.Op1.is_reg(cmd.Op1.reg));
	}
	void AddInstrAnalyizer(bool cond_found_a,bool cond_found_b,bool cond_found_c,ea_t cond_base,
		ea_t cond_base_b,const ea_t& start,const ea_t& end,ea_t& it){
		if(IsAddInstr())
		{
				if(cond_found_a&&cond_found_b){
							LOG(INFO)<<"cond_found_c:addr="<<it<<std::endl;
							if(cmd.Op2.type==o_reg){
								//some handler!!!
							}
							else if(cmd.Op2.type==o_displ){
								/*example:
								.text:10001AC2 mov     ecx, [ebp-24h]
								.text:10001AC5 add     eax, dword_11751820[ecx*4]*/
								it=next_head(it,end);
								if(decode_insn(it)==0){
									return;
								}
								msg("cond_found_c:addr=%x base=%x table=%x\n",it,cond_base,cmd.Op2.addr);
								CodeTableItemDisp(cond_base,cmd.Op2.addr);
								patch_byte(cond_base_b,0x90);
								patch_byte(cond_base_b+1,0x90);
								patch_byte(cond_base_b+2,0x90);
								patch_byte(cond_base_b+3,0x90);
								patch_byte(cond_base_b+4,0x90);
								patch_byte(it,0xFF);
								patch_byte(it+1,0x24);
								analyze_area(start,end);
							}
							else if(cmd.Op2.type==o_mem){
								msg("cond_found_c:addr=%x base=%x table=%x\n",it,cond_base,cmd.Op2.addr);
								CodeTableItemDisp(cond_base,cmd.Op2.addr);
								patch_byte(cond_base_b,0x90);
								patch_byte(cond_base_b+1,0x90);
								patch_byte(cond_base_b+2,0x90);
								patch_byte(cond_base_b+3,0x90);
								patch_byte(cond_base_b+4,0x90);
								patch_byte(it,0xFF);
								patch_byte(it+1,0x24);
								analyze_area(start,end);
							}
						}				
		}
	}
	void CodeSegAnalyizer(const ea_t& start,const ea_t& end){
		try{
			bool cond_found_a = false;
			bool cond_found_b = false;
			ea_t cond_base = 0;
			ea_t cond_base_b = 0;
			bool cond_found_c = false;
			for(ea_t it=start;it!=end;it=next_head(it,end)){
				if(decode_insn(it)==0){
					break;
				}
				if(cmd.itype==NN_movzx&&!strnicmp(cmd.get_canon_mnem(),"movzx",5)&&cmd.size==3&&
					cmd.Op1.is_reg(cmd.Op1.reg)&&cmd.Op2.is_reg(cmd.Op2.reg)){
						cond_found_a = true;
						LOG(INFO)<<"cond_found_a:addr="<<it<<std::endl;
				}
				else if(cmd.itype==NN_mov&&!strnicmp(cmd.get_canon_mnem(),"mov",3)&&cmd.size==5&&cmd.Op1.is_reg(cmd.Op1.reg)&&
					cmd.Op2.is_imm(cmd.Op2.value)&&IsValidEA(cmd.Op2.value)){
						if(cond_found_a){
							cond_found_b = true;
							cond_base = cmd.Op2.value;
							cond_base_b = it;
							LOG(INFO)<<"cond_found_b:addr="<<it<<std::endl;
						}
						else{
							cond_base_b = it;
							ea_t next_it=next_head(it,end);
							if(decode_insn(next_it)==0){
								return;
							}
							if(cmd.itype==NN_jmp||cmd.itype==NN_jmpfi||cmd.itype==NN_jmpni||IsAddInstr()){
								AddInstrAnalyizer(true,true,cond_found_c,cmd.Op2.value,cond_base_b,start,end,next_it);
								cond_found_c = true;
								cond_found_a = false;
								cond_found_b = false;
								cond_base = 0;
							}
						}
				}
				else if(IsAddInstr()){//sub_1002E021
					if(cond_found_a&&cond_found_b){
						AddInstrAnalyizer(cond_found_a,cond_found_b,cond_found_c,cond_base,cond_base_b,start,end,it);
						cond_found_c = true;
						cond_found_a = false;
						cond_found_b = false;
						cond_base = 0;
					}
				}
			}
		}
		catch(...){
			LOG(ERROR)<<__FUNCTION__<<"exception!"<<std::endl;
		}
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
		if(inf.filetype==f_PE&&ph.id==PLFM_386){
			Instance();
		}
		return PLUGIN_OK;
	}
	static void idaapi Terminate(void){
		if(inf.filetype==f_PE&&ph.id==PLFM_386){
			Instance(true);
		}
	}
	static void idaapi Run(int arg){
		if(inf.filetype==f_PE&&ph.id==PLFM_386){
// 			int seg_num = get_segm_qty();
// 			for(int sindex=0;sindex<seg_num;sindex++){
// 				if(Instance()->IsCodeSeg(getnseg(sindex))){
// 					const std::string seg_name = Instance()->GetCodeSegName(getnseg(sindex)->startEA);
// 					msg("code_seg=%s\r\n",seg_name.c_str());
// 					Instance()->CodeSegAnalyizer(getnseg(sindex)->startEA,getnseg(sindex)->endEA);
// 				}
// 			}
			ea_t ea = get_screen_ea();
			if(isCode(get_flags_novalue(ea))){
				func_t* func =  get_func(ea);
				if(func!=NULL){
					Instance()->CodeSegAnalyizer(func->startEA,func->endEA);
				}
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
const char* PluginMain::long_comment = "this plugin to help you reverse analysis itunes.dll";
const char* PluginMain::about_comment = "this is itunes.dll reverse analysis plugins";
const char* PluginMain::short_name = "itunes_plw";
const char* PluginMain::hotkey = "Ctrl-Q";
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
