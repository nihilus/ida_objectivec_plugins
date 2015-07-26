#include "objc/obj_valid_ea.h"
#include <ida.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>

namespace objc{
	const unsigned long kMaxBuferLength = 1024;
	ObjcValidEA::ObjcValidEA(void){
	}
	ObjcValidEA::~ObjcValidEA(void){
	}
	bool ObjcValidEA::IsValidAddress(uint32 ea){
		if(inf.minEA <= ea && ea < inf.maxEA){
			return true;
		}
		else{
			return false;
		}
	}
}
