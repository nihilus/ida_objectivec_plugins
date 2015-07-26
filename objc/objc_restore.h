#ifndef OBJC_OBJC_RESTORE_H_
#define OBJC_OBJC_RESTORE_H_
//////////////////////////////////////////////////////////////////////////
#include "thirdparty/glog/basictypes.h"
#include <string>
#include "objc/objc_string.h"
#include "objc/obj_valid_ea.h"
//////////////////////////////////////////////////////////////////////////
namespace objc{
	class ObjcRestore:private ObjcString,ObjcValidEA
	{
	public:
		ObjcRestore(void);
		~ObjcRestore(void);
		void ClassSeg();
		void MetaClassSeg();
		void NlSymbolPtrSeg();
		void ClsRefsSeg();
		void CategorySeg();
		void MessageRefsSeg();
		void CFStringSeg();
		void ModuleInfoSeg();
		void SymbolsSeg();
		void DataSegObjc2();
		void ObjcDataSegObjc2();
		void ObjcConstSegObjc2();
	protected:
		std::string GuessType(uint32 ea);
	private:
		void RenameMethodMemberName(uint32 ea,const std::string& class_name);
		void RenameIncEA(uint32 ea,const std::string& symb,const std::string& name);
		DISALLOW_EVIL_CONSTRUCTORS(ObjcRestore);
	};
}

#endif
