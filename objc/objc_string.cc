#include "objc/objc_string.h"
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
#include <nalt.hpp>
#include <cstdio>
#include "thirdparty/glog/scoped_ptr.h"

namespace objc{
	void ObjcString::Platform386String(){
		ea_t ea = get_screen_ea();
		if(isCode(get_flags_novalue(ea))){
			func_t *cur_func = get_func(ea);
			ea_t relocate_base = 0;
			for(ea_t opcode_bytes = cur_func->startEA;opcode_bytes<cur_func->endEA;opcode_bytes = get_item_end(opcode_bytes)){
				if(decode_insn(opcode_bytes) <= 0){
					break;
				}
				if(cmd.itype==NN_call&&get_original_long(opcode_bytes)==0xE8&&get_original_long(opcode_bytes+1)==0&&cmd.size==5){
					relocate_base = get_item_end(opcode_bytes);
				}
				else if((relocate_base!=0&&cmd.itype==NN_lea||cmd.itype==NN_mov||cmd.itype==NN_cmp)&&cmd.size==UA_MAXOP){
					uint32 str_offset = get_original_long(opcode_bytes+2);
					uint32 str_address = str_offset + relocate_base;
					str_address = get_original_long(str_address);
					if(cmd.itype==NN_mov&&IsStringType(str_address)&&
						(isData(get_flags_novalue(str_address)))||ObjcValidEA::IsValidAddress(str_address)){
						patch_long(opcode_bytes+2, str_address);
						AddComment(opcode_bytes,str_address);
					}
					else if(cmd.itype==NN_lea){
						str_address = str_offset + relocate_base;

						if(get_original_long(str_address+(sizeof(uint32)*1))==0x7C8){//CFString
							str_address = str_address+(sizeof(uint32)*2);
						}
						if(IsStringType(str_address)&&
							(isData(get_flags_novalue(str_address)))||ObjcValidEA::IsValidAddress(str_address)){
							patch_long(opcode_bytes+2, str_address);
							AddComment(opcode_bytes,str_address);
						}
					}
				}
			}
			analyze_area(cur_func->startEA,cur_func->endEA);
		}
	}
	bool ObjcString::IsStringType(uint32 ea){
		return (get_str_type(ea)!=-1);
	}
	std::string ObjcString::GetString(uint32 address,uint32 type){
		size_t len = get_max_ascii_length(address, type, false);
		scoped_array<char> str(new char[len+10]);
		get_ascii_contents(address, len, type, str.get(), len+1);
		return str.get();
	}
	std::string	ObjcString::ReplaceAll(const std::string& str,const std::string& old_value,const std::string& new_value){
		std::string strs = str;
		for(;;){   
			std::string::size_type   pos(0);   
			if((pos=strs.find(old_value))!=std::string::npos){
				strs.replace(pos,old_value.length(),new_value);
			}
			else{
				break;
			}
		}   
		return strs;   
	}
	void ObjcString::AddComment(uint32 to_ea,uint32 ea){
		std::string comment = std::string("\"")+GetString(ea,get_str_type(ea))+std::string("\"");
		set_cmt(to_ea,comment.c_str(),false);
		msg("Fixing opcode at (%x %s)\n",ea,comment.c_str());
	}
}