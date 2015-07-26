// various workarounds/fixes for MS Visual C++ (so far)
// this file should be included once in module (exe or dll) where std::stable_sort() is used
#ifndef _MSC_FIXES_H
#define _MSC_FIXES_H

#ifdef _MSC_VER
#if (_MSC_VER < 1700) // before VS2012
// the following fixes unneeded exports caused by use
// of std::stable_sort, which uses new(std::nothrow)
// reference: http://social.msdn.microsoft.com/Forums/vstudio/en-US/4692205a-0296-4f41-adbb-fa8339597f5c/unwanted-exports

namespace std { extern const __declspec(selectany) nothrow_t nothrow = nothrow_t(); }

// explanation by Javier Blazquez:

/*
The reason why this eliminates the _Init_locks export is because the linker
no longer has to go find and use the nothrow.obj file (part of msvcprt.lib)
during linking for the definition of std::nothrow, it can just use the
definition you provided. That nothrow.obj file not only contains the
definition of std::nothrow, it also contains a dllexport definition of
std::_Init_locks::operator= (in fact, the only such definition of this
function anywhere in the standard libraries), so preventing the linker from
using the standard nothrow.obj at all has the effect of removing this ugly
export altogether.
*/
#endif (_MSC_VER < 1700)
#endif // _MSC_VER
#endif // _MSC_FIXES_H
