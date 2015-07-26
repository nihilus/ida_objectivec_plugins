#include "objc/objc_restore.h"
#include <typeinf.hpp>
#include <ida.hpp>
#include <auto.hpp>
#include <struct.hpp>
#include <algorithm>

namespace objc{
	ObjcRestore::ObjcRestore(void){
	}
	ObjcRestore::~ObjcRestore(void){
	}
	void ObjcRestore::ClassSeg(){
		segment_t* ea = get_segm_by_name("__class");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			if(get_name(BADADDR,start,name,1024)!=NULL){
				const char ocn[] = "_objc_class_name_";
				if(!strncmp(name,ocn,strlen(ocn))){
					std::string new_rename(name+sizeof(ocn)-1);
					set_name(start,new_rename.c_str());
					std::string new_instance_vars_name = std::string("ivars_")+new_rename;
					set_name(get_original_long(start+0x18),new_instance_vars_name.c_str());
					std::string new_methods_name = std::string("methods_")+new_rename;
					set_name(get_original_long(start+0x1C),new_methods_name.c_str());
					RenameMethodMemberName(get_original_long(start+0x1C),new_rename);
				}
			}
		}
	}
	void ObjcRestore::MetaClassSeg(){
		segment_t* ea = get_segm_by_name("__meta_class");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char next_test[1024] = {0};
			if(get_name(BADADDR,start,next_test,1024)!=NULL){
				ea_t str = get_original_long(start+0x8);
				std::string name = ObjcString::GetString(str,get_str_type(str));
				std::string meta_class_name = std::string("MetaClass")+name;
				if(!set_name(start,meta_class_name.c_str())){
					RenameIncEA(start,"",meta_class_name);
				}
				std::string method_name = std::string("method_impl_")+name;
				if(!set_name(get_original_long(start+0x1C),method_name.c_str())){
					RenameIncEA(start,"",method_name);
				}
				RenameMethodMemberName(get_original_long(start+0x1C),name);
			}
		}
	}
	void ObjcRestore::NlSymbolPtrSeg(){
		segment_t* ea = get_segm_by_name("__nl_symbol_ptr");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			get_name(BADADDR,start,name,1024);
			std::string message_refs_name = std::string("ptr_")+std::string(name);
			if(set_name(start,message_refs_name.c_str())){
				continue;
			}
			for(int i=0;i<100;i++){
				char buf[1024] = {0};
				_snprintf(buf,1024,"ptr_%s_%d",name,i);
				message_refs_name.resize(0);
				message_refs_name.append(buf);
				if(set_name(start,message_refs_name.c_str())){
					break;
				}
			}
		}
	}
	void ObjcRestore::ClsRefsSeg(){
		segment_t* ea = get_segm_by_name("__cls_refs");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			get_name(BADADDR,start,name,1024);
			std::string message_refs_name = std::string("cls_")+std::string(name);
			if(set_name(start,message_refs_name.c_str())){
				continue;
			}
			for(int i=0;i<100;i++){
				char buf[1024] = {0};
				_snprintf(buf,1024,"cls_%s_%d",name,i);
				message_refs_name.resize(0);
				message_refs_name.append(buf);
				if(set_name(start,message_refs_name.c_str())){
					break;
				}
			}
		}
	}
	void ObjcRestore::CategorySeg(){
		segment_t* ea = get_segm_by_name("__category");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char next_test[1024] = {0};
			if(get_name(BADADDR,start,next_test,1024)!=NULL){
				std::string category_name = ObjcString::GetString(get_original_long(start),get_str_type(get_original_long(start)));
				std::string class_name = ObjcString::GetString(get_original_long(start+4),get_str_type(get_original_long(start+4)));
				std::string cur_name = std::string(class_name)+std::string("_")+std::string(category_name);
				if(!set_name(start,cur_name.c_str())){
					RenameIncEA(start,"",cur_name.c_str());
				}
				ea_t str = get_original_long(start+0x8);
				std::string class_impl_name = std::string("method_impl_")+cur_name;
				if(!set_name(str,class_impl_name.c_str())){
					RenameIncEA(str,"",class_impl_name);
				}
				RenameMethodMemberName(get_original_long(start+0x8),cur_name);
			}
		}
	}
	void ObjcRestore::MessageRefsSeg(){
		segment_t* ea = get_segm_by_name("__message_refs");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			get_name(BADADDR,start,name,1024);
			std::string message_refs_name = std::string("msg_")+std::string(name);
			if(set_name(start,message_refs_name.c_str())){
				continue;
			}
			for(int i=0;i<100;i++){
				char buf[1024] = {0};
				_snprintf(buf,1024,"msg_%s_%d",name,i);
				message_refs_name.resize(0);
				message_refs_name.append(buf);
				if(set_name(start,message_refs_name.c_str())){
					break;
				}
			}
		}
	}
	void ObjcRestore::CFStringSeg(){
		segment_t* ea = get_segm_by_name("__cfstring");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			std::string cfstring = GuessType(start);
			if(!cfstring.find("__CFString")!=std::string::npos||!cfstring.find("__cfstring_struct")!=std::string::npos){
				char name[1024] = {0};
				if(get_name(BADADDR,start,name,1024)==NULL){
					continue;
				}
				std::string message_refs_name = std::string("cfs_")+std::string(name);
				if(set_name(start,message_refs_name.c_str())){
					continue;
				}
				for(int i=0;i<100;i++){
					char buf[1024] = {0};
					_snprintf(buf,1024,"cfs_%s_%d",name,i);
					message_refs_name.resize(0);
					message_refs_name.append(buf);
					if(set_name(start,message_refs_name.c_str())){
						break;
					}
				}
			}
		}
		analyze_area(ea->startEA,ea->endEA);
	}
	void ObjcRestore::ModuleInfoSeg(){
		segment_t* ea = get_segm_by_name("__module_info");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			std::string cfstring = GuessType(start);
			if(!cfstring.find("__objc_module_info_struct")!=std::string::npos||!cfstring.find("__module_info_struct")!=std::string::npos){
				uint32 orig = get_original_long(start+0xC);
				char buf[1024] = {0};
				_snprintf(buf,1024,"symtab_%x",orig);
				if(orig!=0&&set_name(start,buf)){
					continue;
				}
			}
		}
	}
	void ObjcRestore::SymbolsSeg(){
		segment_t* ea = get_segm_by_name("__symbols");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			std::string cfstring = GuessType(start);
			if(!cfstring.find("__objc_symtab_struct")!=std::string::npos||!cfstring.find("__symtab_struct")!=std::string::npos){
				ea_t symbols_addr = get_original_long(start+0xC);
				char name[1024] = {0};
				if(get_name(BADADDR,symbols_addr,name,1024)!=NULL){
					char buf[1024] = {0};
					_snprintf(buf,1024,"symtab_%s",name);
					if(set_name(start,buf)){
						continue;
					}
				}

			}
		}
	}
	void ObjcRestore::DataSegObjc2(){
		segment_t* ea = get_segm_by_name("__data");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			if(get_name(BADADDR,start,name,1024)!=NULL){//__objc2_prot
				const char prot_name[] = "_OBJC_PROTOCOL_$_";
				if(!strncmp(name,prot_name,sizeof(prot_name)-1)){
					std::string new_name(name+sizeof(prot_name)-1);
					set_name(start,new_name.c_str());
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0x8))){
						std::string inst_meths = new_name+std::string("_Protocol");
						set_name(get_original_long(start+0x8),inst_meths.c_str());
					}
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0xC))){
						std::string inst_meths = new_name+std::string("_InstanceMethod");
						set_name(get_original_long(start+0xC),inst_meths.c_str());
					}
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0x10))){
						std::string inst_meths = new_name+std::string("_ClassMethod");
						set_name(get_original_long(start+0x10),inst_meths.c_str());
					}
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0x14))){
						std::string opt_inst_meths = new_name+std::string("_OptInstanceMethod");
						set_name(get_original_long(start+0x14),opt_inst_meths.c_str());
					}
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0x18))){
						std::string opt_inst_meths = new_name+std::string("_OptClassMethod");
						set_name(get_original_long(start+0x18),opt_inst_meths.c_str());
					}
				}
			}
		}
	}
	void ObjcRestore::ObjcDataSegObjc2(){
		segment_t* ea = get_segm_by_name("__objc_data");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			if(get_name(BADADDR,start,name,1024)!=NULL){//__objc2_prot
				const char meta_class[] = "_OBJC_METACLASS_$_";
				const char objc_class[] = "_OBJC_CLASS_$_";
				if(!strncmp(name,meta_class,sizeof(meta_class)-1)){
					std::string meta_class_name(std::string("metaclass_")+std::string(name+sizeof(meta_class)-1));
					if(!set_name(start,meta_class_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",meta_class_name);
					}
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0x10))){
						std::string meta_data_name(std::string("metadata_")+std::string(name+sizeof(meta_class)-1));
						if(!set_name(get_original_long(start+0x10),meta_data_name.c_str(),SN_NOWARN|SN_CHECK)){
							RenameIncEA(get_original_long(start+0x10),"",meta_data_name);
						}
					}
				}
				else if(!strncmp(name,objc_class,sizeof(objc_class)-1)){
					std::string class_name(std::string(name+sizeof(objc_class)-1));
					if(!set_name(start,class_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",class_name);
					}
					if(ObjcValidEA::IsValidAddress(get_original_long(start+0x10))){
						std::string meta_data_name(std::string("classdata_")+std::string(name+sizeof(meta_class)-1));
						if(!set_name(get_original_long(start+0x10),meta_data_name.c_str(),SN_NOWARN|SN_CHECK)){
							RenameIncEA(get_original_long(start+0x10),"",meta_data_name);
						}
					}
				}
			}
		}
	}
	void ObjcRestore::ObjcConstSegObjc2(){
		segment_t* ea = get_segm_by_name("__objc_const");
		if(!ea){
			return;
		}
		ea_t start = ea->startEA;
		ea_t end = ea->endEA;
		for(;start!=BADADDR;start = next_head(start,end)){
			char name[1024] = {0};
			if(get_name(BADADDR,start,name,1024)!=NULL){
				const char objc_instance_methods[] = "_OBJC_INSTANCE_METHODS_";
				const char objc_instance_variables[] = "_OBJC_INSTANCE_VARIABLES_";
				const char objc_class_methods[] = "_OBJC_CLASS_METHODS_";
				const char objc_category_instance_methods[] = "_OBJC_CATEGORY_INSTANCE_METHODS_";
				const char objc_category_class_methods[] = "_OBJC_CATEGORY_CLASS_METHODS_";
				if(!strncmp(name,objc_instance_methods,sizeof(objc_instance_methods)-1)){
					std::string class_name = std::string(name+sizeof(objc_instance_methods)-1);
					RenameMethodMemberName(start,class_name);
					std::string method_name = std::string("instance_impl_")+class_name;
					if(set_name(start,method_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",method_name);
					}
				}
				else if(!strncmp(name,objc_class_methods,sizeof(objc_class_methods)-1)){
					std::string class_name = std::string(name+sizeof(objc_class_methods)-1);
					RenameMethodMemberName(start,class_name);
					std::string method_name = std::string("class_impl_")+class_name;
					if(set_name(start,method_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",method_name);
					}
				}
				else if(!strncmp(name,objc_category_instance_methods,sizeof(objc_category_instance_methods)-1)){
					std::string class_name = std::string(name+sizeof(objc_category_instance_methods)-1);
					RenameMethodMemberName(start,class_name);
					class_name = ObjcString::ReplaceAll(class_name,"_$_","::");
					std::string method_name = std::string("category_impl_")+class_name;
					if(set_name(start,method_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",method_name);
					}
				}
				else if(!strncmp(name,objc_category_class_methods,sizeof(objc_category_class_methods)-1)){
					std::string class_name = std::string(name+sizeof(objc_category_class_methods)-1);
					RenameMethodMemberName(start,class_name);
					class_name = ObjcString::ReplaceAll(class_name,"_$_","::");
					std::string method_name = std::string("category_impl_")+class_name;
					if(set_name(start,method_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",method_name);
					}
				}
				else if(!strncmp(name,objc_instance_variables,sizeof(objc_instance_variables)-1)){
					std::string ivars_name(std::string("ivars_")+std::string(name+sizeof(objc_instance_variables)-1));
					if(!set_name(start,ivars_name.c_str(),SN_NOWARN|SN_CHECK)){
						RenameIncEA(start,"",ivars_name);
					}
				}
			}
		}
	}
	std::string ObjcRestore::GuessType(uint32 ea){
		char buf[MAXSTR] = {0};
		print_type(ea,buf,MAXSTR,0);
		if(buf != NULL && *buf != '\0'){
			std::string result((const char*)buf);
			return result;
		}
		type_t * types = new type_t [MAXSTR];
		p_list * fields = new p_list [MAXSTR];
		guess_type(ea,types,MAXSTR,fields,MAXSTR);
		set_ti(ea,types,fields);
		std::string result((const char*)types);
		delete[] types;
		delete[] fields;
		return result;
	}
	
	void ObjcRestore::RenameMethodMemberName(uint32 ea,const std::string& class_name){
		//__objc2_meth
		uint32 method_number = get_original_long(ea+0x4);
		ea_t start = ea+0x8;
		//msg("method number:%d start offset:%x\r\n",method_number,start);
		if(method_number==-1||!ObjcValidEA::IsValidAddress(start)){
			return;
		}
		const std::string new_class_name = ObjcString::ReplaceAll(class_name,"_$_","::");
		for(uint32 index=0;index<method_number;index++){
			std::string func_name = ObjcString::GetString(get_original_long(start),get_str_type(get_original_long(start)));
			std::replace(func_name.begin(),func_name.end(),':','_');
			func_name = ObjcString::ReplaceAll(func_name,"_$_","::");
			std::string new_func_name = new_class_name+std::string("::")+func_name;
			func_t* func = get_func(get_original_long(start+0x8));
			if(func!=NULL){
				if(!set_name(func->startEA,new_func_name.c_str(),SN_NOWARN|SN_CHECK)){
					RenameIncEA(func->startEA,"",new_func_name);
				}
				patch_long(start+0x8,func->startEA);
			}
			start += (sizeof(ea_t)*3);
		}
	}
	void ObjcRestore::RenameIncEA(uint32 ea,const std::string& symb,const std::string& name){
		for(int i=0;;i++){
			char buf[1024] = {0};
			_snprintf(buf,1024,"%s%s_%d",symb.c_str(),name.c_str(),i);
			if(set_name(ea,buf,SN_NOWARN|SN_CHECK)){
				break;
			}
		}
	}
}