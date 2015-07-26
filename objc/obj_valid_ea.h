#ifndef OBJC_OBJCVALIDEA_H_
#define OBJC_OBJCVALIDEA_H_
//////////////////////////////////////////////////////////////////////////
#include "thirdparty/glog/basictypes.h"
//////////////////////////////////////////////////////////////////////////
namespace objc{
	class ObjcValidEA
	{
	public:
		ObjcValidEA(void);
		~ObjcValidEA(void);
	protected:
		bool IsValidAddress(uint32 ea);
	private:
		DISALLOW_EVIL_CONSTRUCTORS(ObjcValidEA);
	};
}
#endif