#ifndef OBJC_OBJC_STRING_H_
#define OBJC_OBJC_STRING_H_
//////////////////////////////////////////////////////////////////////////
#include "thirdparty/glog/basictypes.h"
#include <string>
#include "objc/obj_valid_ea.h"
//////////////////////////////////////////////////////////////////////////
namespace objc{
	class ObjcString:private ObjcValidEA
	{
	public:
		ObjcString(){}
		~ObjcString(){}
		void Platform386String();
	protected:
		bool IsStringType(uint32 ea);
		std::string GetString(uint32 address,uint32 type);
		std::string  ReplaceAll(const std::string& str,const std::string& old_value,const std::string& new_value);
		void AddComment(uint32 to_ea,uint32 ea);
	private:
		DISALLOW_EVIL_CONSTRUCTORS(ObjcString);
	};
}
//////////////////////////////////////////////////////////////////////////
#endif