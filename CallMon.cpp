// Figure 1:  CallMon hook implementation (CallMon.cpp)
// Copyright (c) 1998 John Panzer.  Permission is granted to
// use, copy, modify, distribute, and sell this source code as 
// long as this copyright notice appears in all source files.
#include <windows.h>
#include <imagehlp.h>
#include <stdio.h>
#include <regex>
#include <iostream>
#include "CallMon.h"

using namespace std;

typedef CallMonitor::ADDR ADDR;

// Processor-specific offset from
// _penter return address to start of
// caller.
static const unsigned OFFSET_CALL_BYTES=5;

// Start of MSVC-specific code

// _pexit is called upon return from
// an instrumented function.
static void _pexit()
{
    CallMonitor::TICKS endTime;
    CallMonitor::queryTicks(&endTime);
    ADDR framePtr,parentFramePtr;

    // Retrieve parent stack frame to pass
    // to exitProcedure
    __asm mov DWORD PTR [framePtr], ebp
    parentFramePtr = ((ADDR *)framePtr)[0];

    CallMonitor::threadObj().exitProcedure(
            parentFramePtr,
            &((ADDR*)framePtr)[3],endTime);
}

// An entry point to which all instrumented
// function returns are redirected.  
static void __declspec(naked) _pexitThunk()
{
    // Push placeholder return address
    __asm push 0     
    // Protect original return value
    __asm push eax   
    _pexit();
    // Restore original return value
    __asm pop eax    
    // Return using new address set by _pexit
    __asm ret        
}

#if 0 // Causes problems with (at least) msdev 6.0 sp 5, because it clobbers registers
// _penter is called on entry to each client function
extern "C" __declspec(dllexport)
void _penter()
{
    CallMonitor::TICKS entryTime;
    CallMonitor::queryTicks(&entryTime); // Track entry time

    ADDR framePtr;
    __asm mov DWORD PTR [framePtr], ebp

    CallMonitor::threadObj().enterProcedure(
        (ADDR)((unsigned *)framePtr)[0],
        (ADDR)((unsigned *)framePtr)[1]-OFFSET_CALL_BYTES,
        (ADDR*)&((unsigned *)framePtr)[2],
        entryTime);
}

#else // Patch due to Derek Young:

// _penter is called on entry to each client function
extern "C" __declspec(dllexport) __declspec(naked)
void _penter()
{
    // The function prolog.
    __asm
    {
        PUSH EBP                    // Set up the standard stack frame.
        MOV  EBP , ESP
 
        PUSH EAX                    // Save off EAX as I need to use it
                                    // before saving all registers.
        MOV  EAX , ESP              // Get the current stack value into
                                    //  EAX.
 
        SUB  ESP , __LOCAL_SIZE     // Save off the space needed by the
                                    // local variables.
 
        PUSHAD                      // Save off all general register
                                    // values.
    }
 
    CallMonitor::TICKS entryTime;
    CallMonitor::queryTicks(&entryTime); // Track entry time
 
    ADDR framePtr;
    __asm mov DWORD PTR [framePtr], ebp
 
    CallMonitor::threadObj().enterProcedure(
        (ADDR)((unsigned *)framePtr)[0],
        (ADDR)((unsigned *)framePtr)[1]-OFFSET_CALL_BYTES,
        (ADDR*)&((unsigned *)framePtr)[2],
        entryTime);
 
  // prolog
    __asm
    {
        POPAD                       // Restore all general purpose
                                    // values.
 
        ADD ESP , __LOCAL_SIZE      // Remove space needed for locals.
 
        POP EAX                     // Restore EAX
 
        MOV ESP , EBP               // Restore the standard stack frame.
        POP EBP
        RET                         // Return to caller.
    }
}
#endif


#ifdef PENTIUM
void CallMonitor::queryTickFreq(TICKS *t) 
{
    static TICKS ticksPerSec=0;
    if (!ticksPerSec)
    {
        static const int NUM_LOOPS=100;
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);

        TICKS qpf1,qpf2,qc1,qc2;
        QueryPerformanceCounter((LARGE_INTEGER*)&qpf1);
        RDTSC(((LARGE_INTEGER&)qc1).LowPart,((LARGE_INTEGER&)qc1).HighPart);
        for(int i=0;i<NUM_LOOPS;i++)
            Sleep(1);
        QueryPerformanceCounter((LARGE_INTEGER*)&qpf2);
        RDTSC(((LARGE_INTEGER&)qc2).LowPart,((LARGE_INTEGER&)qc2).HighPart);
        __int64 qpcTicks = qpf2-qpf1;
        __int64 qcTicks = qc2-qc1;
        long double ratio = ((long double)qcTicks)/((long double)qpcTicks);
        ticksPerSec = ratio * (long double)freq.QuadPart;
    }
    *t = ticksPerSec;
}
#endif
// End of MSVC-specific code

// Figure 2:  CallMonitor class implementation (CallMon.cpp)
// Copyright (c) 1998 John Panzer.  Permission is granted to
// use, copy, modify, distribute, and sell this source code as 
// long as this copyright notice appears in all source files.

// Utility functions
void indent(int level) 
{
    for (int i = 0; i < level; i++) { 
        //putchar('\t'); //xiuxi
        putchar(' ');
        putchar(' ');
        putchar(' ');
        putchar(' ');
    }
}

//
// class CallMonitor
//
DWORD CallMonitor::tlsSlot=0xFFFFFFFF;

CallMonitor::CallMonitor() {queryTicks(&threadStartTime);}

CallMonitor::~CallMonitor() {}

void CallMonitor::threadAttach(CallMonitor *newObj)
{
    if (tlsSlot==0xFFFFFFFF) tlsSlot = TlsAlloc();
    TlsSetValue(tlsSlot,newObj);
}   

void CallMonitor::threadDetach()
{
    delete &threadObj();
}


CallMonitor &CallMonitor::threadObj()
{
    CallMonitor *self = (CallMonitor *)
        TlsGetValue(tlsSlot);
    return *self;
}

// Performs standard entry processing
void CallMonitor::enterProcedure(ADDR parentFramePtr,
                                 ADDR funcAddr,
                                 ADDR *retAddrPtr,
                                 const TICKS &entryTime)
{
    // Record procedure entry on shadow stack
    callInfoStack.push_back(CallInfo());
   
    CallInfo &ci = callInfoStack.back();
    ci.funcAddr = funcAddr;
    ci.parentFrame = parentFramePtr;
    ci.origRetAddr = *retAddrPtr,
    ci.entryTime = entryTime;

    logEntry(ci);  // Log procedure entry event

    // Redirect eventual return to local thunk
    *retAddrPtr = (ADDR)_pexitThunk;

    queryTicks(&ci.startTime); // Track approx. start time
}

// Performs standard exit processing
void CallMonitor::exitProcedure(ADDR parentFramePtr,
                                ADDR *retAddrPtr,
                                const TICKS &endTime)
{
    // Pops shadow stack until finding a call record
    // that matches the current stack layout.
    bool inSync=false;
    while(1)
    {
        // Retrieve original call record
        CallInfo &ci = callInfoStack.back();
        ci.endTime = endTime;
        *retAddrPtr = ci.origRetAddr;
        if (ci.parentFrame==parentFramePtr)
        {
            logExit(ci,true); // Record normal exit
            callInfoStack.pop_back();
            return;
        } 
        logExit(ci,false);    // Record exceptional exit
        callInfoStack.pop_back();
    }
}

int time_end_id = 1;
int callInfoStack_enter;
// Default entry logging procedure
string get_indent(int level, bool is_std) {
    string text = "";
    for (int i = 0; i < level; i++) {
        //putchar('\t'); //xiuxi
        if (is_std) {
            text += "    ";
        }
        else {
            text += "____";
        }
        
    }
    return text;
}
void CallMonitor::logEntry(CallInfo &ci)
{
    int maxLength1 = 90;
    string module,name;
    getFuncInfo(ci.funcAddr,module,name);
    bool is_std = false;
    string name1 = std::regex_replace(name, std::regex("std::"), "");
    if (name1.length() != name.length()) {
        is_std = true;
        //return;

    }
    name = name1;
    name = std::regex_replace(name, std::regex("::"), ".");
    name = std::regex_replace(name, std::regex("> >"), ">>");
    name = std::regex_replace(name, std::regex("<"), "(");
    name = std::regex_replace(name, std::regex(">"), ")");
    if (is_std && true) {
        auto fnd = name.find('(');
        if (fnd >= 0) {
            if (1 != 1) {
                //max 显示完整调用
                //max(basic_string(char,char_traits(char),allocator(char)) ) 
                name = name.substr(0, fnd);
            }
        }
    }
    if (is_std && false) {
        name = std::regex_replace(name, std::regex("\\("), " ");
        name = std::regex_replace(name, std::regex("\\)"), " ");
        name = std::regex_replace(name, std::regex("\\."), " ");
        name = std::regex_replace(name, std::regex("\\,"), " ");
        name = std::regex_replace(name, std::regex("  "), " ");
        name = std::regex_replace(name, std::regex("  "), " ");
        name = std::regex_replace(name, std::regex("  "), " ");
        //name = "__" + name;
    }

    if (!is_std) {
        //name = "__" + name;
        int length = name.length();
        if (length + callInfoStack.size()*4 < maxLength1) {
            length = maxLength1 - length - callInfoStack.size()*4;
            for (int i = 0; i < length; i++) {
                name += "_";
            }
        }
    }
    if (is_std) {
        if (name == "basic_ostream" || 
            name == "endl" ||
            name == "operator" ||
            name == "_Narrow_char_traits"
            ) {
            cout << flush;
            cout << "\n";
            int j = 0;
            //return;
        }
        //return;
    }
    
    if (1 != 1) {
        return;
    }
    if (!is_std) {
        cout << "\n";
    }
    string indent1 = get_indent(callInfoStack.size(), is_std);
    //printf("//%s", indent1.c_str());
    std::cout << "                    //" << indent1;
    //string indent1 = get_indent(callInfoStack.size());
    //callInfoStack_enter = callInfoStack.size();
    //indent(callInfoStack.size() - 1);
    //printf("{\n");
    //indent(callInfoStack.size() );
    if (name.length() + indent1.length() < 100) {
        int len = maxLength1 - name.length() - indent1.length();
        for (int i = 0; i < len; i++) {
            name += " ";
        }
    }
    std::cout << name << time_end_id << "\n";
    if (!is_std) {
        cout << "\n";
    }
    //printf("%s { // %d \n",
    //    name.c_str(), time_end_id);
    time_end_id++;
    /*
    printf("%s!%s (%08X)\n",module.c_str(),
            name.c_str(),ci.funcAddr);
    */
}
// Default exit logging procedure
void CallMonitor::logExit(CallInfo &ci,bool normalRet)
{
    if (1==1) {
        return;
    }
    auto callInfoStack_exit = callInfoStack.size();
    //xiuxi
    indent(callInfoStack.size()-1);
    if (!normalRet) printf("exception ");
    TICKS ticksPerSecond;
    queryTickFreq(&ticksPerSecond);
    string module, name;
    getFuncInfo(ci.funcAddr, module, name);
    //printf("}");
    //printf("}");
    //printf("enter=%d exit=%d", callInfoStack_enter, callInfoStack_exit);
    name = std::regex_replace(name, std::regex("std::"), "");
    /**/
    name = std::regex_replace(name, std::regex("::"), ".");
    name = std::regex_replace(name, std::regex("> >"), ">>");
    name = std::regex_replace(name, std::regex("<"), "(");
    name = std::regex_replace(name, std::regex(">"), ")");
    /*
    printf(name.c_str());
    printf(" %d ",time_end_id);
    time_end_id++;
    printf("\n\n");
    
    printf("exit %08X, elapsed time=%I64d ms (%I64d ticks)\n",ci.funcAddr,
           (ci.endTime-ci.startTime)/(ticksPerSecond/1000),
           (ci.endTime-ci.startTime));
    */
    
}

void DumpLastError()
{
    LPVOID lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                  FORMAT_MESSAGE_FROM_SYSTEM |     
                  FORMAT_MESSAGE_IGNORE_INSERTS,    
                  NULL,
                  GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                  (LPTSTR) &lpMsgBuf,    0,    NULL );
    OutputDebugString((LPCTSTR)lpMsgBuf);
    LocalFree( lpMsgBuf );
}

void CallMonitor::getFuncInfo(ADDR addr,
                              string &module,
                              string &funcName)
{
    SymInitialize(GetCurrentProcess(),NULL,FALSE);
    TCHAR moduleName[MAX_PATH];
    TCHAR modShortNameBuf[MAX_PATH];
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery((void*)addr,&mbi,sizeof(mbi));
    GetModuleFileName((HMODULE)mbi.AllocationBase, 
                      moduleName, MAX_PATH );

    _splitpath(moduleName,NULL,NULL,modShortNameBuf,NULL);

    BYTE symbolBuffer[ sizeof(IMAGEHLP_SYMBOL) + 1024 ];
    PIMAGEHLP_SYMBOL pSymbol = 
            (PIMAGEHLP_SYMBOL)&symbolBuffer[0];
    // Following not per docs, but per example...
    pSymbol->SizeOfStruct = sizeof(symbolBuffer); 
    pSymbol->MaxNameLength = 1023;
    pSymbol->Address = 0;
    pSymbol->Flags = 0;
    pSymbol->Size =0;
                        
    DWORD symDisplacement = 0;
    if (!SymLoadModule(GetCurrentProcess(),
                  NULL,
                  moduleName,
                  NULL,
                  (DWORD)mbi.AllocationBase,
                  0))
        DumpLastError();

    SymSetOptions( SymGetOptions() & ~SYMOPT_UNDNAME );
    char undName[1024];
    if (! SymGetSymFromAddr(GetCurrentProcess(), addr,
                            &symDisplacement, pSymbol) )
    {
        DumpLastError();
        // Couldn't retrieve symbol (no debug info?)
        strcpy(undName,"<unknown symbol>");
    }
    else
    {
        // Unmangle name, throwing away decorations
        // that don't affect uniqueness:
        if ( 0 == UnDecorateSymbolName( 
                pSymbol->Name, undName,
                sizeof(undName),
                UNDNAME_NO_MS_KEYWORDS |
                UNDNAME_NO_ACCESS_SPECIFIERS |
                UNDNAME_NO_FUNCTION_RETURNS |
                UNDNAME_NO_ALLOCATION_MODEL |
                UNDNAME_NO_ALLOCATION_LANGUAGE |
                UNDNAME_NO_MEMBER_TYPE))
            strcpy(undName,pSymbol->Name);
    }
    SymUnloadModule(GetCurrentProcess(),
                    (DWORD)mbi.AllocationBase);
    SymCleanup(GetCurrentProcess());
    module = modShortNameBuf;
    funcName = undName;
}
//End of file
