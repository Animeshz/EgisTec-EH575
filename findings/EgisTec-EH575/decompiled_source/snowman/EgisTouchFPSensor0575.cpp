
int64_t RegOpenKeyA = 0x16436;

int64_t RegQueryValueExA = 0x16444;

int64_t RegCloseKey = 0x16428;

int32_t g180018660 = 0;

int64_t fun_180001000() {
    int64_t rax1;
    int64_t v2;
    int32_t eax3;
    int32_t ebx4;
    int64_t v5;
    int32_t eax6;
    int64_t v7;

    rax1 = reinterpret_cast<int64_t>(RegOpenKeyA(0xffffffff80000002, "SOFTWARE\\EgisSDKDBG", reinterpret_cast<int64_t>(__zero_stack_offset()) - 56 + 80));
    if (!*reinterpret_cast<int32_t*>(&rax1)) {
        eax3 = reinterpret_cast<int32_t>(RegQueryValueExA(v2, "EnableBlock"));
        ebx4 = 4;
        if (!eax3) {
            ebx4 = 1;
        }
        eax6 = reinterpret_cast<int32_t>(RegQueryValueExA(v5, "DisplayFlag "));
        if (!eax6) {
            ebx4 = 1;
        }
        RegCloseKey(v7, "DisplayFlag ");
        g180018660 = 1;
        *reinterpret_cast<int32_t*>(&rax1) = ebx4;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax1) + 4) = 0;
    }
    return rax1;
}

struct s0 {
    signed char[8] pad8;
    int32_t f8;
};

uint64_t g1800170a0 = 0x2b992ddfa232;

void** fun_180002c40(void** rcx, void* rdx, void** r8, void** r9);

uint32_t fun_180002d10(unsigned char* rcx, void* rdx, void* r8, void* r9, ...);

int64_t CreateFileA = 0x162b8;

int64_t SetFilePointer = 0x162c6;

int64_t lstrlenA = 0x1635a;

int64_t WriteFile = 0x162d8;

int64_t OutputDebugStringA = 0x162e4;

int64_t CloseHandle = 0x16310;

struct s0* fun_180002f40(uint64_t rcx, ...);

struct s0* fun_180001290(uint32_t ecx, void* rdx, void* r8, void** r9) {
    void* rsp5;
    uint64_t rax6;
    void** r8_7;
    void* rsp8;
    unsigned char* rcx9;
    void* rsp10;
    int64_t rax11;
    void* rsp12;
    int32_t eax13;
    void* rsp14;
    void* r9_15;
    int64_t r8_16;
    int32_t eax17;
    void* rsp18;
    uint64_t rcx19;
    struct s0* rax20;

    if (rdx) {
        rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x190);
        rax6 = g1800170a0;
        if (ecx != 1) {
            r8_7 = reinterpret_cast<void**>("SensorAdapter");
            if (ecx != 2) {
                r8_7 = reinterpret_cast<void**>("WBF");
            }
        } else {
            r8_7 = reinterpret_cast<void**>("EngineAdapter");
        }
        fun_180002c40(reinterpret_cast<uint64_t>(rsp5) + 72, 30, r8_7, r9);
        rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8);
        rcx9 = reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(rsp8) + 0x70);
        fun_180002d10(rcx9, 0x104, "%s\\%s.txt", "C:\\Temp2\\WBF", rcx9, 0x104, "%s\\%s.txt", "C:\\Temp2\\WBF");
        rsp10 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
        rax11 = reinterpret_cast<int64_t>(CreateFileA(reinterpret_cast<uint64_t>(rsp10) + 0x70, 0x40000000, 3));
        rsp12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp10) - 8 + 8);
        if (rax11 != -1) {
            SetFilePointer(rax11);
            eax13 = reinterpret_cast<int32_t>(lstrlenA(rdx));
            rsp14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp12) - 8 + 8 - 8 + 8);
            r9_15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp14) + 64);
            *reinterpret_cast<int32_t*>(&r8_16) = eax13;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_16) + 4) = 0;
            eax17 = reinterpret_cast<int32_t>(WriteFile(rax11, rdx, r8_16, r9_15));
            rsp18 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp14) - 8 + 8);
            if (!eax17) {
                OutputDebugStringA("=SDK-DBG= Write File fail\r\n", rdx, r8_16, r9_15);
                rsp18 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp18) - 8 + 8);
            }
            CloseHandle(rax11, rdx, r8_16, r9_15);
            rsp12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp18) - 8 + 8);
        }
        rcx19 = rax6 ^ reinterpret_cast<uint64_t>(rsp5) ^ reinterpret_cast<uint64_t>(rsp12);
        rax20 = fun_180002f40(rcx19, rcx19);
    }
    return rax20;
}

uint32_t g180018664 = 0;

int64_t GetLocalTime = 0x1634a;

int64_t GetCurrentThreadId = 0x16334;

int64_t GetCurrentProcessId = 0x1631e;

uint32_t fun_180002e8c(unsigned char* rcx, void* rdx, void* r8, void** r9);

uint16_t g18000f37c = 0xa0d;

unsigned char g18000f37e = 0;

int32_t g180018668 = 0;

struct s0* fun_1800010e0(uint32_t ecx, int64_t rdx, void** r8, void** r9, int64_t a5, ...) {
    void* rsp6;
    uint64_t rax7;
    uint64_t v8;
    int1_t zf9;
    int1_t zf10;
    void* rsp11;
    void** r8_12;
    void** rcx13;
    void* rsp14;
    unsigned char* rcx15;
    void* r9_16;
    void* rsp17;
    void** r9_18;
    void* r8_19;
    uint32_t eax20;
    void* rcx21;
    uint32_t eax22;
    uint32_t eax23;
    int32_t eax24;
    uint64_t rcx25;
    struct s0* rax26;

    rsp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x370);
    rax7 = g1800170a0;
    v8 = rax7 ^ reinterpret_cast<uint64_t>(rsp6);
    zf9 = g180018660 == 0;
    if (zf9) {
        fun_180001000();
        rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
        rdx = rdx;
    }
    zf10 = (g180018664 & ecx) == 0;
    if (!zf10 && rdx) {
        GetLocalTime(reinterpret_cast<uint64_t>(rsp6) + 96);
        rsp11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
        if (ecx != 1) {
            r8_12 = reinterpret_cast<void**>("SensorAdapter");
            if (ecx != 2) {
                r8_12 = reinterpret_cast<void**>("WBF");
            }
        } else {
            r8_12 = reinterpret_cast<void**>("EngineAdapter");
        }
        rcx13 = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rsp11) + 0x70);
        fun_180002c40(rcx13, 30, r8_12, r9);
        GetCurrentThreadId(rcx13, 30, r8_12);
        GetCurrentProcessId(rcx13, 30, r8_12);
        rsp14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp11) - 8 + 8 - 8 + 8 - 8 + 8);
        rcx15 = reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(rsp14) + 0x1f0);
        r9_16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp14) + 0x70);
        fun_180002d10(rcx15, 0x15e, "[%s] %02d:%02d:%02d:%03d [%04d] [%04d] %s", r9_16, rcx15, 0x15e, "[%s] %02d:%02d:%02d:%03d [%04d] [%04d] %s", r9_16);
        rsp17 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp14) - 8 + 8);
        r9_18 = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rsp17) + 0x390);
        r8_19 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp17) + 0x1f0);
        eax20 = fun_180002e8c(reinterpret_cast<uint64_t>(rsp17) + 0x90, 0x15e, r8_19, r9_18);
        rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp17) - 8 + 8);
        rcx21 = reinterpret_cast<void*>(static_cast<int64_t>(reinterpret_cast<int32_t>(eax20)));
        if (*reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rsp6) + reinterpret_cast<uint64_t>(rcx21) + 0x8f) != 10) {
            eax22 = g18000f37c;
            *reinterpret_cast<int16_t*>(reinterpret_cast<uint64_t>(rsp6) + reinterpret_cast<uint64_t>(rcx21) + 0x90) = *reinterpret_cast<int16_t*>(&eax22);
            eax23 = g18000f37e;
            *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rsp6) + reinterpret_cast<uint64_t>(rcx21) + 0x92) = *reinterpret_cast<signed char*>(&eax23);
        }
        eax24 = g180018668;
        if (eax24 >= 1) {
            OutputDebugStringA(reinterpret_cast<uint64_t>(rsp6) + 0x90, 0x15e, r8_19, r9_18);
            rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
            eax24 = g180018668;
        }
        if (eax24 >= 2) {
            fun_180001290(ecx, reinterpret_cast<uint64_t>(rsp6) + 0x90, r8_19, r9_18);
            rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
        }
    }
    rcx25 = v8 ^ reinterpret_cast<uint64_t>(rsp6);
    rax26 = fun_180002f40(rcx25, rcx25);
    return rax26;
}

int32_t fun_18000e730(int64_t rcx);

struct s1 {
    signed char[248] pad248;
    int64_t f248;
};

void fun_180006150(struct s1* rcx);

int64_t g18001cf08;

void* g18001cea8;

int64_t g18001cd80;

uint64_t g18001ce90;

int32_t g18001cd70;

int32_t g18001cd74;

int32_t g18001cd88;

int64_t g18001cd90;

struct s0* fun_180004a04(void* rcx);

struct s0* fun_180002f40(uint64_t rcx, ...) {
    int1_t zf2;
    struct s0* rax3;
    int32_t eax4;
    int64_t rax5;
    struct s0* rax6;

    zf2 = rcx == g1800170a0;
    if (zf2) {
        __asm__("rol rcx, 0x10");
        if (*reinterpret_cast<uint16_t*>(&rcx) & 0xffff) {
            __asm__("ror rcx, 0x10");
        } else {
            return rax3;
        }
    }
    eax4 = fun_18000e730(23);
    if (eax4) {
        __asm__("int 0x29");
    }
    fun_180006150(0x18001ce10);
    g18001cf08 = reinterpret_cast<int64_t>(__return_address());
    g18001cea8 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 56 - 8 + 8 - 8 + 8 + 56 + 8);
    rax5 = g18001cf08;
    g18001cd80 = rax5;
    g18001ce90 = rcx;
    g18001cd70 = 0xc0000409;
    g18001cd74 = 1;
    g18001cd88 = 1;
    g18001cd90 = 2;
    rax6 = fun_180004a04(0x180010360);
    return rax6;
}

struct s3 {
    signed char[56] pad56;
    int64_t f56;
};

struct s4 {
    int64_t f0;
    void** f8;
    signed char[23] pad32;
    int64_t f32;
    void** f40;
    signed char[7] pad48;
    void** f48;
    signed char[7] pad56;
    void** f56;
    signed char[7] pad64;
    uint32_t f64;
    signed char[4] pad72;
    int32_t f72;
    uint16_t f76;
    uint16_t f78;
};

struct WINBIO_PIPELINE {
    int64_t f0;            // SensorHandle
    signed char[24] pad32; // EngineHandle + StorageHandle + SensorInterface
    struct s3* f32;        // EngineInterface
    signed char[8] pad48;  // StorageInterface
    struct s4* f48;        // SensorContext
    // Two structs missing?
};

int64_t CreateEventA = 0x1640a;

int64_t DeviceIoControl = 0x163dc;

int64_t GetLastError = 0x1637c;

int64_t SetLastError = 0x1638c;

int64_t GetOverlappedResult = 0x163c6;

uint32_t fun_180001640(struct WINBIO_PIPELINE* rcx, int32_t* rdx, void** r8, void** r9) {
    void* rsp5;
    uint64_t rax6;
    int64_t v7;
    void* rsp8;
    int64_t rbx9;
    struct s4* v10;
    void* rdx11;
    void* r8_12;
    int64_t rcx13;
    struct s4* rax14;
    void* rsp15;
    int64_t rcx16;
    void** r8_17;
    int64_t rdx18;
    int32_t eax19;
    void* rsp20;
    int32_t eax21;
    int64_t v22;
    int64_t v23;
    int32_t eax24;
    void* rsp25;
    int32_t eax26;
    int32_t eax27;
    void* rsp28;
    uint16_t ax29;
    uint32_t eax30;
    void** r8_31;
    int64_t v32;
    int64_t v33;
    uint64_t rcx34;
    struct s0* rax35;
    int64_t v36;
    int64_t v37;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x90);
    rax6 = g1800170a0;
    fun_1800010e0(2, ">>> SensorAdapterQueryStatus", r8, r9, v7);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8);
    *reinterpret_cast<uint32_t*>(&rbx9) = 0;
    v10 = reinterpret_cast<struct s4*>(0);
    if (!rcx || !rdx) {
        *reinterpret_cast<uint32_t*>(&rbx9) = 0x80004003;
    } else {
        if (!rcx->f48 || rcx->f0 == -1) {
            *reinterpret_cast<uint32_t*>(&rbx9) = 0x8009800f;
        } else {
            *reinterpret_cast<int32_t*>(&rdx11) = 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx11) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r9) = 0;
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_12) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_12) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rcx13) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx13) + 4) = 0;
            rax14 = reinterpret_cast<struct s4*>(CreateEventA());
            rsp15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
            v10 = rax14;
            if (rax14) {
                rcx16 = rcx->f0;
                *reinterpret_cast<int32_t*>(&r9) = 0;
                *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                *reinterpret_cast<int32_t*>(&r8_17) = 0;
                *reinterpret_cast<int32_t*>(&r8_17 + 4) = 0;
                *reinterpret_cast<int32_t*>(&rdx18) = 0x440010;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx18) + 4) = 0;
                eax19 = reinterpret_cast<int32_t>(DeviceIoControl(rcx16, 0x440010));
                rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
                if (eax19) {
                    addr_18000179d_7:
                    if (1) {
                        addr_1800017d0_8:
                        eax21 = reinterpret_cast<int32_t>(GetLastError(rcx16, rdx18, r8_17));
                        rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                        if (eax21 == 0x4c7 || eax21 == 0x3e3) {
                            *reinterpret_cast<uint32_t*>(&rbx9) = 0x80098004;
                        } else {
                            *reinterpret_cast<uint32_t*>(&rbx9) = 0x80098036;
                        }
                    } else {
                        *rdx = 0;
                        fun_1800010e0(2, "SensorAdapterQueryStatus : Sensor Status = %d", 0, r9, v22, 2, "SensorAdapterQueryStatus : Sensor Status = %d", 0, r9, v23);
                        rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                    }
                } else {
                    eax24 = reinterpret_cast<int32_t>(GetLastError(rcx16, 0x440010));
                    rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                    if (eax24 != 0x3e5) 
                        goto addr_1800017d0_8;
                    SetLastError();
                    rsp25 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                    rcx13 = rcx->f0;
                    r8_12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) + 64);
                    rdx11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) + 72);
                    *reinterpret_cast<int32_t*>(&r9) = 1;
                    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                    eax26 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx13, rdx11, r8_12, 1));
                    rsp15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) - 8 + 8);
                    if (!eax26) 
                        goto addr_1800016e6_14;
                    if (1) 
                        goto addr_1800016e6_14; else 
                        goto addr_180001784_16;
                }
            } else {
                addr_1800016e6_14:
                eax27 = reinterpret_cast<int32_t>(GetLastError(rcx13, rdx11, r8_12, r9));
                rsp28 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
                if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax27 < 0) | reinterpret_cast<uint1_t>(eax27 == 0))) {
                    ax29 = reinterpret_cast<uint16_t>(GetLastError(rcx13, rdx11, r8_12, r9));
                    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp28) - 8 + 8);
                    *reinterpret_cast<uint32_t*>(&rbx9) = static_cast<uint32_t>(ax29) | 0x80070000;
                } else {
                    eax30 = reinterpret_cast<uint32_t>(GetLastError(rcx13, rdx11, r8_12, r9));
                    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp28) - 8 + 8);
                    *reinterpret_cast<uint32_t*>(&rbx9) = eax30;
                }
            }
        }
    }
    if (v10) {
        CloseHandle();
        rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
    }
    *reinterpret_cast<uint32_t*>(&r8_31) = *reinterpret_cast<uint32_t*>(&rbx9);
    *reinterpret_cast<int32_t*>(&r8_31 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterQueryStatus : ErrorCode [0x%08X]", r8_31, r9, v32, 2, "<<< SensorAdapterQueryStatus : ErrorCode [0x%08X]", r8_31, r9, v33);
    rcx34 = rax6 ^ reinterpret_cast<uint64_t>(rsp5) ^ reinterpret_cast<uint64_t>(rsp8) - 8 + 8;
    rax35 = fun_180002f40(rcx34, rcx34);
    return *reinterpret_cast<uint32_t*>(&rax35);
    addr_180001784_16:
    *reinterpret_cast<int32_t*>(&r9) = 20;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    rdx18 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_SENSOR_STATUS GetOverlappedResult result = [%d], bytesReturned = [%d]");
    *reinterpret_cast<int32_t*>(&r8_17) = eax26;
    *reinterpret_cast<int32_t*>(&r8_17 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&rcx16) = 2;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx16) + 4) = 0;
    fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_SENSOR_STATUS GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_17, 20, v36, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_SENSOR_STATUS GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_17, 20, v37);
    rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
    goto addr_18000179d_7;
}

int64_t GetProcessHeap = 0x163b4;

int64_t HeapAlloc = 0x1639c;

void** fun_180002bb0(void** rcx, int64_t rdx, void** r8, void** r9) {
    GetProcessHeap();
    goto HeapAlloc;
}

void** fun_18000503c();

void** fun_1800039c8() {
    void** rax1;
    void** rax2;

    rax1 = fun_18000503c();
    if (rax1) {
        rax2 = rax1 + 16;
    } else {
        rax2 = reinterpret_cast<void**>(0x180017218);
    }
    return rax2;
}

void** fun_180003894(int64_t rcx, int64_t rdx, int64_t r8, int32_t r9d);

void** fun_1800038fc() {
    void** rax1;

    rax1 = fun_180003894(0, 0, 0, 0);
    return rax1;
}

void** fun_180003c80(void** rcx, unsigned char dl, void** r8, ...);

uint32_t fun_180003a38(int32_t ecx, void** rdx, void** r8, void** r9);

uint32_t fun_180002d34(int64_t rcx, unsigned char* rdx, void* r8, void* r9) {
    void* rbp5;
    int64_t rbx6;
    void* r14_7;
    void** rax8;
    uint32_t eax9;
    int32_t eax10;
    int32_t v11;
    void** v12;
    void** v13;
    uint32_t eax14;

    rbp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8);
    *reinterpret_cast<int32_t*>(&rbx6) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx6) + 4) = 0;
    r14_7 = r8;
    fun_180003c80(reinterpret_cast<int64_t>(rbp5) + 0xffffffffffffffd8, 0, 40);
    if (!r9 || r14_7 && !rdx) {
        rax8 = fun_1800039c8();
        *reinterpret_cast<void***>(rax8) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        eax9 = 0xffffffff;
    } else {
        eax10 = *reinterpret_cast<int32_t*>(&r14_7);
        if (reinterpret_cast<uint64_t>(r14_7) > 0x7fffffff) {
            eax10 = 0x7fffffff;
        }
        v11 = eax10;
        eax9 = reinterpret_cast<uint32_t>(rcx(reinterpret_cast<int64_t>(rbp5) - 48, r9, v12, v13));
        if (rdx) 
            goto addr_180002dcd_6;
    }
    addr_180002e00_7:
    return eax9;
    addr_180002dcd_6:
    if (reinterpret_cast<int32_t>(eax9) < reinterpret_cast<int32_t>(0)) 
        goto addr_180002df2_8;
    --v11;
    if (v11 < 0) {
        eax14 = fun_180003a38(0, reinterpret_cast<int64_t>(rbp5) + 0xffffffffffffffd0, v12, v13);
        if (eax14 == 0xffffffff) {
            addr_180002df2_8:
            *reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(rdx) + reinterpret_cast<uint64_t>(r14_7) - 1) = 0;
            *reinterpret_cast<unsigned char*>(&rbx6) = reinterpret_cast<uint1_t>(v11 >= 0);
            eax9 = static_cast<uint32_t>(rbx6 - 2);
            goto addr_180002e00_7;
        } else {
            addr_180002dee_11:
            eax9 = eax9;
            goto addr_180002e00_7;
        }
    } else {
        *rdx = 0;
        goto addr_180002dee_11;
    }
}

uint64_t g18001d340;

int32_t fun_180005740() {
    uint64_t rax1;
    int32_t ecx2;

    rax1 = reinterpret_cast<uint64_t>(GetProcessHeap());
    ecx2 = 0;
    g18001d340 = rax1;
    *reinterpret_cast<unsigned char*>(&ecx2) = reinterpret_cast<uint1_t>(!!rax1);
    return ecx2;
}

void fun_180005760() {
    g18001d340 = 0;
    return;
}

uint32_t g180017238 = 0xffffffff;

int32_t fun_1800061e0();

struct s5 {
    void** f0;
    signed char[7] pad8;
    int32_t f8;
};

int64_t DeleteCriticalSection = 0x16532;

void** fun_180005f00(void** rcx, ...);

int32_t fun_180005204() {
    uint32_t ecx1;
    void** rax2;
    int64_t rdi3;
    struct s5* rbx4;
    int64_t rbp5;
    void** rsi6;
    int32_t* rbx7;

    ecx1 = g180017238;
    if (ecx1 != 0xffffffff) {
        *reinterpret_cast<int32_t*>(&rax2) = fun_1800061e0();
        g180017238 = 0xffffffff;
    }
    *reinterpret_cast<int32_t*>(&rdi3) = 36;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
    rbx4 = reinterpret_cast<struct s5*>(0x180018030);
    *reinterpret_cast<int32_t*>(&rbp5) = 36;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbp5) + 4) = 0;
    do {
        rsi6 = rbx4->f0;
        if (rsi6 && rbx4->f8 != 1) {
            DeleteCriticalSection(rsi6);
            rax2 = fun_180005f00(rsi6);
            rbx4->f0 = reinterpret_cast<void**>(0);
        }
        rbx4 = reinterpret_cast<struct s5*>(reinterpret_cast<int64_t>(rbx4) + 16);
        --rbp5;
    } while (rbp5);
    rbx7 = reinterpret_cast<int32_t*>(0x180018038);
    do {
        if (*reinterpret_cast<int64_t*>(rbx7 - 2) && *rbx7 == 1) {
            *reinterpret_cast<int32_t*>(&rax2) = reinterpret_cast<int32_t>(DeleteCriticalSection());
        }
        rbx7 = rbx7 + 4;
        --rdi3;
    } while (rdi3);
    return *reinterpret_cast<int32_t*>(&rax2);
}

int32_t g18001f108;

uint32_t fun_180007b7c();

void** g18001cd58;

void* fun_1800084f0(void** rcx, ...);

void** fun_1800066f0(void* rcx, void** rdx, void** r8);

void** g18001d300;

int32_t g18001f10c;

void fun_18000391c();

int64_t HeapFree = 0x163a8;

void** fun_1800039e8(int64_t rcx, ...);

uint32_t fun_180005dcc() {
    int1_t zf1;
    void** rbx2;
    int64_t rdi3;
    void* rax4;
    void** r8_5;
    void** rax6;
    void** rdi7;
    uint32_t eax8;
    void** rbx9;
    void* rax10;
    int32_t esi11;
    void* rbp12;
    void** r8_13;
    void** rax14;
    void** r9_15;
    void** eax16;
    void** rcx17;
    uint64_t rcx18;
    void** rax19;
    void** rax20;
    int32_t eax21;
    int64_t rcx22;
    void** rax23;
    int64_t v24;

    zf1 = g18001f108 == 0;
    if (zf1) {
        fun_180007b7c();
    }
    rbx2 = g18001cd58;
    *reinterpret_cast<int32_t*>(&rdi3) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
    if (rbx2) {
        while (*reinterpret_cast<void***>(rbx2)) {
            if (*reinterpret_cast<void***>(rbx2) != 61) {
                *reinterpret_cast<int32_t*>(&rdi3) = *reinterpret_cast<int32_t*>(&rdi3) + 1;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
            }
            rax4 = fun_1800084f0(rbx2);
            rbx2 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rbx2 + 1) + reinterpret_cast<uint64_t>(rax4));
        }
        rax6 = fun_1800066f0(static_cast<int64_t>(static_cast<int32_t>(rdi3 + 1)), 8, r8_5);
        rdi7 = rax6;
        g18001d300 = rax6;
        if (!rax6) 
            goto addr_180005dfc_9;
    } else {
        addr_180005dfc_9:
        eax8 = 0xffffffff;
        goto addr_180005eb9_10;
    }
    rbx9 = g18001cd58;
    if (!*reinterpret_cast<void***>(rbx9)) {
        addr_180005e99_12:
        fun_180005f00(rbx9, rbx9);
        g18001cd58 = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rdi7) = reinterpret_cast<void**>(0);
        g18001f10c = 1;
        eax8 = 0;
    } else {
        do {
            rax10 = fun_1800084f0(rbx9, rbx9);
            esi11 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rax10) + 1);
            if (*reinterpret_cast<void***>(rbx9) != 61) {
                rbp12 = reinterpret_cast<void*>(static_cast<int64_t>(esi11));
                rax14 = fun_1800066f0(rbp12, 1, r8_13);
                *reinterpret_cast<void***>(rdi7) = rax14;
                if (!rax14) 
                    goto addr_180005ece_15;
                r8_13 = rbx9;
                eax16 = fun_180002c40(rax14, rbp12, r8_13, r9_15);
                if (eax16) 
                    goto addr_180005ee7_17;
                rdi7 = rdi7 + 8;
            }
            rbx9 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rbx9) + reinterpret_cast<uint64_t>(static_cast<int64_t>(esi11)));
        } while (*reinterpret_cast<void***>(rbx9));
        goto addr_180005e92_20;
    }
    addr_180005eb9_10:
    return eax8;
    addr_180005e92_20:
    rbx9 = g18001cd58;
    goto addr_180005e99_12;
    addr_180005ece_15:
    rcx17 = g18001d300;
    fun_180005f00(rcx17, rcx17);
    g18001d300 = reinterpret_cast<void**>(0);
    goto addr_180005dfc_9;
    addr_180005ee7_17:
    fun_18000391c();
    if (!1) {
        rcx18 = g18001d340;
        rax19 = reinterpret_cast<void**>(HeapFree(rcx18));
        if (!*reinterpret_cast<int32_t*>(&rax19)) {
            rax20 = fun_1800039c8();
            eax21 = reinterpret_cast<int32_t>(GetLastError(rcx18));
            *reinterpret_cast<int32_t*>(&rcx22) = eax21;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx22) + 4) = 0;
            rax23 = fun_1800039e8(rcx22);
            *reinterpret_cast<void***>(rax20) = rax23;
        }
    }
    goto v24;
}

struct s6 {
    int64_t f0;
    void* f8;
    signed char[16] pad32;
    int64_t f32;
    signed char[16] pad56;
    uint32_t* f56;
    signed char[8] pad72;
    uint32_t f72;
};

int64_t g180015350 = 0x18000b410;

uint32_t fun_180008e30(int64_t rcx, void** rdx, void** r8, struct s6* r9);

void fun_180008750(int64_t rcx);

int32_t fun_180005554(int64_t* rcx, int64_t* rdx);

int64_t fun_180009000(int64_t rcx, int64_t* rdx);

void fun_1800068a8();

void fun_1800054f4(void** rcx, void** rdx);

int64_t g18001f0f0;

int32_t fun_180005404(int32_t ecx, void** rdx, void** r8, struct s6* r9) {
    int64_t rcx1;
    int1_t zf5;
    int32_t ebx6;
    uint32_t eax7;
    int32_t eax8;
    int1_t zf9;
    uint32_t eax10;

    *reinterpret_cast<int32_t*>(&rcx1) = ecx;
    zf5 = g180015350 == 0;
    ebx6 = *reinterpret_cast<int32_t*>(&rcx1);
    if (!zf5 && (rcx1 = 0x180015350, eax7 = fun_180008e30(0x180015350, rdx, r8, r9), !!eax7)) {
        *reinterpret_cast<int32_t*>(&rcx1) = ebx6;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx1) + 4) = 0;
        g180015350(rcx1);
    }
    fun_180008750(rcx1);
    eax8 = fun_180005554(0x18000f280, 0x18000f2a8);
    if (!eax8) {
        fun_180009000(fun_1800068a8, 0x18000f2a8);
        fun_1800054f4(0x18000f270, 0x18000f278);
        zf9 = g18001f0f0 == 0;
        if (!zf9 && (eax10 = fun_180008e30(0x18001f0f0, 0x18000f278, r8, r9), !!eax10)) {
            g18001f0f0();
        }
        eax8 = 0;
    }
    return eax8;
}

void fun_1800088e8(int32_t ecx, void** rdx, void** r8);

int32_t g18001d2e8;

int32_t g18001d328;

signed char g18001d324;

void** g18001f100;

int64_t DecodePointer = 0x1649c;

void** g18001f0f8;

int64_t EncodePointer = 0x1648c;

void fun_180008ad8(int32_t ecx, ...);

void fun_180005228(int32_t ecx, void** rdx);

int64_t ExitProcess = 0x164c8;

void fun_1800053f4() {
    void** rdx1;
    int1_t zf2;
    void** rcx3;
    int64_t* rax4;
    int64_t* rsi5;
    void** rcx6;
    int64_t* rax7;
    int64_t* rdi8;
    int64_t* r12_9;
    int64_t* r15_10;
    int64_t rax11;
    int64_t rcx12;
    int64_t rax13;
    int64_t rax14;
    void** rcx15;
    int64_t* rax16;
    void** rcx17;
    int64_t* rax18;

    *reinterpret_cast<int32_t*>(&rdx1) = 0;
    *reinterpret_cast<int32_t*>(&rdx1 + 4) = 0;
    fun_1800088e8(8, 0, 1);
    zf2 = g18001d2e8 == 1;
    if (!zf2) {
        g18001d328 = 1;
        g18001d324 = 1;
        if (!0) {
            rcx3 = g18001f100;
            rax4 = reinterpret_cast<int64_t*>(DecodePointer(rcx3));
            rsi5 = rax4;
            if (rax4) {
                rcx6 = g18001f0f8;
                rax7 = reinterpret_cast<int64_t*>(DecodePointer(rcx6));
                rdi8 = rax7;
                r12_9 = rsi5;
                r15_10 = rax7;
                while (--rdi8, reinterpret_cast<uint64_t>(rdi8) >= reinterpret_cast<uint64_t>(rsi5)) {
                    rax11 = reinterpret_cast<int64_t>(EncodePointer());
                    if (*rdi8 != rax11) {
                        if (reinterpret_cast<uint64_t>(rdi8) < reinterpret_cast<uint64_t>(rsi5)) 
                            break;
                        rcx12 = *rdi8;
                        rax13 = reinterpret_cast<int64_t>(DecodePointer(rcx12));
                        rax14 = reinterpret_cast<int64_t>(EncodePointer());
                        *rdi8 = rax14;
                        rax13();
                        rcx15 = g18001f100;
                        rax16 = reinterpret_cast<int64_t*>(DecodePointer(rcx15));
                        rcx17 = g18001f0f8;
                        rax18 = reinterpret_cast<int64_t*>(DecodePointer(rcx17));
                        if (r12_9 != rax16) 
                            goto addr_1800056a2_10;
                        if (r15_10 == rax18) 
                            goto addr_18000565b_12;
                    } else {
                        addr_18000565b_12:
                        continue;
                    }
                    addr_1800056a2_10:
                    r12_9 = rax16;
                    rsi5 = rax16;
                    r15_10 = rax18;
                    rdi8 = rax18;
                    goto addr_18000565b_12;
                }
            }
            fun_1800054f4(0x18000f2b0, 0x18000f2d0);
        }
        rdx1 = reinterpret_cast<void**>(0x18000f2e0);
        fun_1800054f4(0x18000f2d8, 0x18000f2e0);
    }
    if (static_cast<int1_t>(fun_180008ad8(8, 8), !1)) {
        g18001d2e8 = 1;
        fun_180008ad8(8, 8);
        fun_180005228(0, rdx1);
        ExitProcess(0, rdx1);
    }
    return;
}

void** fun_180005a9c() {
    void*** rdi1;
    int64_t rsi2;
    void** rbx3;
    void** rax4;
    void** rcx5;
    void** rax6;

    rdi1 = reinterpret_cast<void***>(0x18001d350);
    *reinterpret_cast<int32_t*>(&rsi2) = 64;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi2) + 4) = 0;
    do {
        rbx3 = *rdi1;
        if (rbx3) {
            rax4 = rbx3 + 0xb00;
            while (reinterpret_cast<unsigned char>(rbx3) < reinterpret_cast<unsigned char>(rax4)) {
                if (*reinterpret_cast<void***>(rbx3 + 12)) {
                    DeleteCriticalSection(rbx3 + 16);
                }
                rbx3 = rbx3 + 88;
                rax4 = *rdi1 + 0xb00;
            }
            rcx5 = *rdi1;
            rax6 = fun_180005f00(rcx5);
            *rdi1 = reinterpret_cast<void**>(0);
        }
        rdi1 = rdi1 + 8;
        --rsi2;
    } while (rsi2);
    return rax6;
}

uint64_t g18001eff0;

int64_t TlsGetValue = 0x166ba;

void** fun_1800061fc() {
    uint64_t rax1;
    uint64_t rax2;

    rax1 = g18001eff0;
    rax2 = rax1 ^ g1800170a0;
    if (!rax2) {
        goto TlsGetValue;
    } else {
        goto rax2;
    }
}

void** fun_1800095a0(void* rcx, void** rdx, int32_t* r8);

uint32_t g18001d658;

void fun_1800066a8(int64_t rcx, void** rdx);

void** fun_1800066f0(void* rcx, void** rdx, void** r8) {
    int64_t rbx4;
    void** rsi5;
    void* rbp6;
    void** rax7;
    int1_t below_or_equal8;
    int64_t rcx9;
    uint32_t ecx10;
    int1_t below_or_equal11;

    *reinterpret_cast<uint32_t*>(&rbx4) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx4) + 4) = 0;
    rsi5 = rdx;
    rbp6 = rcx;
    do {
        rax7 = fun_1800095a0(rbp6, rsi5, 0);
        if (rax7) 
            break;
        below_or_equal8 = g18001d658 <= *reinterpret_cast<uint32_t*>(&rax7);
        if (below_or_equal8) 
            break;
        *reinterpret_cast<uint32_t*>(&rcx9) = *reinterpret_cast<uint32_t*>(&rbx4);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx9) + 4) = 0;
        fun_1800066a8(rcx9, rsi5);
        ecx10 = static_cast<uint32_t>(rbx4 + 0x3e8);
        below_or_equal11 = ecx10 <= g18001d658;
        *reinterpret_cast<uint32_t*>(&rbx4) = ecx10;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx4) + 4) = 0;
        if (!below_or_equal11) {
            *reinterpret_cast<uint32_t*>(&rbx4) = 0xffffffff;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx4) + 4) = 0;
        }
    } while (*reinterpret_cast<uint32_t*>(&rbx4) != 0xffffffff);
    return rax7;
}

uint64_t g18001eff8;

int64_t TlsSetValue = 0x166c8;

int32_t fun_180006218(int64_t rcx, ...) {
    uint64_t rax2;
    uint64_t rax3;

    rax2 = g18001eff8;
    rax3 = rax2 ^ g1800170a0;
    if (!rax3) {
        goto TlsSetValue;
    } else {
        goto rax3;
    }
}

void** g180017e70 = reinterpret_cast<void**>(0x80);

void fun_1800077d8(void** rcx);

void fun_1800050c0(void** rcx, void** rdx, void** r8) {
    void** rax4;
    void** rcx5;

    *reinterpret_cast<void***>(rcx + 0xa0) = reinterpret_cast<void**>(0x180010370);
    *reinterpret_cast<void***>(rcx + 16) = reinterpret_cast<void**>(0);
    *reinterpret_cast<void***>(rcx + 28) = reinterpret_cast<void**>(1);
    *reinterpret_cast<void***>(rcx + 0xc8) = reinterpret_cast<void**>(1);
    *reinterpret_cast<int16_t*>(rcx + 0x164) = 67;
    *reinterpret_cast<int16_t*>(rcx + 0x26a) = 67;
    *reinterpret_cast<void***>(rcx + 0xb8) = reinterpret_cast<void**>(0x180017870);
    *reinterpret_cast<uint64_t*>(rcx + 0x470) = 0;
    fun_1800088e8(13, rdx, r8);
    *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xb8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xb8)) + 1;
    fun_180008ad8(13);
    fun_1800088e8(12, rdx, r8);
    *reinterpret_cast<void***>(rcx + 0xc0) = rdx;
    if (!rdx) {
        rax4 = g180017e70;
        *reinterpret_cast<void***>(rcx + 0xc0) = rax4;
    }
    rcx5 = *reinterpret_cast<void***>(rcx + 0xc0);
    fun_1800077d8(rcx5);
    fun_180008ad8(12);
    return;
}

int32_t fun_180004ea8(void** rcx, void** rdx, void** r8);

int32_t fun_180004fdc(void** rcx) {
    void** rbx2;
    int64_t rcx3;
    void** rax4;
    void** r8_5;
    int32_t eax6;

    rbx2 = rcx;
    *reinterpret_cast<uint32_t*>(&rcx3) = g180017238;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx3) + 4) = 0;
    if (*reinterpret_cast<uint32_t*>(&rcx3) != 0xffffffff) {
        if (!rbx2) {
            rax4 = fun_1800061fc();
            *reinterpret_cast<uint32_t*>(&rcx3) = g180017238;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx3) + 4) = 0;
            rbx2 = rax4;
        }
        fun_180006218(rcx3);
        eax6 = fun_180004ea8(rbx2, 0, r8_5);
    }
    return eax6;
}

int64_t GetSystemTimeAsFileTime = 0x1658c;

int64_t QueryPerformanceCounter = 0x16572;

int64_t g1800170a8 = 0xffffd466d2205dcd;

void fun_180005f40() {
    void* rbp1;
    uint64_t rax2;
    void* rcx3;
    int32_t eax4;
    uint64_t rax5;
    int32_t eax6;
    uint64_t rax7;
    uint64_t rax8;
    int32_t v9;
    uint64_t v10;

    rbp1 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8);
    rax2 = g1800170a0;
    if (rax2 == 0x2b992ddfa232) {
        rcx3 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp1) + 24);
        GetSystemTimeAsFileTime(rcx3);
        eax4 = reinterpret_cast<int32_t>(GetCurrentThreadId(rcx3));
        *reinterpret_cast<int32_t*>(&rax5) = eax4;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax5) + 4) = 0;
        eax6 = reinterpret_cast<int32_t>(GetCurrentProcessId(rcx3));
        *reinterpret_cast<int32_t*>(&rax7) = eax6;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax7) + 4) = 0;
        QueryPerformanceCounter(reinterpret_cast<int64_t>(rbp1) + 32);
        *reinterpret_cast<int32_t*>(&rax8) = v9;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax8) + 4) = 0;
        rax2 = (rax8 << 32 ^ v10 ^ (rax5 ^ rax7) ^ reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(rbp1) + 16)) & 0xffffffffffff;
        if (rax2 == 0x2b992ddfa232) {
            rax2 = 0x2b992ddfa233;
        }
        g1800170a0 = rax2;
    }
    g1800170a8 = reinterpret_cast<int64_t>(~rax2);
    return;
}

int32_t g18001cd50;

void** fun_180005284();

int32_t fun_180005184();

void fun_180006870();

int64_t GetCommandLineA = 0x16466;

void*** g18001f110;

void** fun_180005fec();

uint32_t fun_18000576c();

uint32_t fun_180005b10();

int32_t fun_1800034d8(int64_t rcx, void** rdx, void** r8, struct s6* r9) {
    void** rax5;
    int32_t eax6;
    void* rcx7;
    void** rax8;
    int64_t rcx9;
    int32_t eax10;
    void** eax11;
    int32_t eax12;
    int1_t zf13;
    int1_t zf14;
    int32_t eax15;
    int32_t eax16;
    void*** rax17;
    void** rax18;
    uint32_t eax19;
    uint32_t eax20;
    uint32_t eax21;
    int32_t eax22;

    if (*reinterpret_cast<int32_t*>(&rdx) != 1) {
        if (*reinterpret_cast<int32_t*>(&rdx)) {
            if (*reinterpret_cast<int32_t*>(&rdx) != 2) {
                if (*reinterpret_cast<int32_t*>(&rdx) == 3) {
                    fun_180004fdc(0);
                    goto addr_18000362c_6;
                }
            } else {
                rax5 = fun_1800061fc();
                if (rax5) {
                    addr_18000362c_6:
                    eax6 = 1;
                } else {
                    *reinterpret_cast<int32_t*>(&rcx7) = static_cast<int32_t>(reinterpret_cast<uint64_t>(rax5 + 1));
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
                    rax8 = fun_1800066f0(rcx7, 0x478, r8);
                    if (!rax8) {
                        addr_1800034f3_9:
                        eax6 = 0;
                    } else {
                        *reinterpret_cast<uint32_t*>(&rcx9) = g180017238;
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx9) + 4) = 0;
                        eax10 = fun_180006218(rcx9, rcx9);
                        if (!eax10) {
                            fun_180005f00(rax8, rax8);
                            goto addr_1800034f3_9;
                        } else {
                            fun_1800050c0(rax8, 0, r8);
                            eax11 = reinterpret_cast<void**>(GetCurrentThreadId(rax8));
                            *reinterpret_cast<void***>(rax8) = eax11;
                            *reinterpret_cast<void***>(rax8 + 8) = reinterpret_cast<void**>(0xffffffffffffffff);
                            goto addr_18000362c_6;
                        }
                    }
                }
                return eax6;
            }
        } else {
            eax12 = g18001cd50;
            if (reinterpret_cast<uint1_t>(eax12 < 0) | reinterpret_cast<uint1_t>(eax12 == 0)) 
                goto addr_1800034f3_9;
            g18001cd50 = eax12 - 1;
            zf13 = g18001d328 == *reinterpret_cast<int32_t*>(&rdx);
            if (zf13) {
                fun_1800053f4();
            }
            fun_180005284();
            if (!r8) {
                fun_180005a9c();
                fun_180005204();
                fun_180005760();
            }
            if (!r8 && (zf14 = g180017238 == 0xffffffff, !zf14)) {
                fun_180005204();
                goto addr_18000362c_6;
            }
        }
    }
    eax15 = fun_180005740();
    if (!eax15) 
        goto addr_1800034f3_9;
    eax16 = fun_180005184();
    if (!eax16) 
        goto addr_180003503_23;
    fun_180006870();
    rax17 = reinterpret_cast<void***>(GetCommandLineA());
    g18001f110 = rax17;
    rax18 = fun_180005fec();
    g18001cd58 = rax18;
    eax19 = fun_18000576c();
    if (reinterpret_cast<int32_t>(eax19) >= reinterpret_cast<int32_t>(0)) {
        eax20 = fun_180005b10();
        if (reinterpret_cast<int32_t>(eax20) < reinterpret_cast<int32_t>(0) || ((eax21 = fun_180005dcc(), reinterpret_cast<int32_t>(eax21) < reinterpret_cast<int32_t>(0)) || (eax22 = fun_180005404(0, rdx, r8, r9), !!eax22))) {
            fun_180005a9c();
        } else {
            ++g18001cd50;
            goto addr_18000362c_6;
        }
    }
    fun_180005204();
    addr_180003503_23:
    fun_180005760();
    goto addr_1800034f3_9;
}

uint32_t fun_180002be0(int64_t rcx, ...) {
    return 1;
}

uint32_t g18001efc0;

void fun_180006ac4(int64_t rcx) {
    g18001efc0 = 0;
    return;
}

uint32_t g18001d2e4;

void** fun_180003c80(void** rcx, unsigned char dl, void** r8, ...) {
    void** r11_4;
    int64_t rdx5;
    int64_t rax6;
    int1_t cf7;
    void** rdx8;
    int1_t cf9;
    void* rax10;
    uint64_t r9_11;
    uint64_t r9_12;
    void** rax13;
    int64_t rcx14;
    void* rcx15;
    void** r9_16;
    uint64_t r9_17;
    uint64_t r8_18;
    uint64_t r9_19;
    void** rdi20;
    uint32_t eax21;
    void** rcx22;
    void** rax23;

    r11_4 = rcx;
    *reinterpret_cast<uint32_t*>(&rdx5) = dl;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx5) + 4) = 0;
    if (reinterpret_cast<unsigned char>(r8) < reinterpret_cast<unsigned char>(16)) {
        *reinterpret_cast<int32_t*>(&rax6) = *reinterpret_cast<int32_t*>(0x180000000 + reinterpret_cast<unsigned char>(r8) * 4 + 0x3e15);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax6) + 4) = 0;
        goto 0x180000000 + rax6;
    } else {
        cf7 = static_cast<int1_t>(g18001d2e4 >> 1);
        if (!cf7) {
            rdx8 = reinterpret_cast<void**>(rdx5 * 0x101010101010101);
            cf9 = static_cast<int1_t>(g18001d2e4 >> 2);
            if (cf9) {
                __asm__("movd xmm0, rdx");
                __asm__("punpcklbw xmm0, xmm0");
                if (*reinterpret_cast<unsigned char*>(&rcx) & 15) {
                    __asm__("movups [rcx], xmm0");
                    rax10 = reinterpret_cast<void*>(reinterpret_cast<unsigned char>(rcx) & 15);
                    r8 = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rax10) + reinterpret_cast<unsigned char>(r8) + 0xfffffffffffffff0);
                }
                r9_11 = reinterpret_cast<unsigned char>(r8) >> 7;
                if (r9_11) {
                    do {
                        __asm__("movaps [rcx], xmm0");
                        __asm__("movaps [rcx+0x10], xmm0");
                        __asm__("movaps [rcx-0x60], xmm0");
                        __asm__("movaps [rcx-0x50], xmm0");
                        --r9_11;
                        __asm__("movaps [rcx-0x40], xmm0");
                        __asm__("movaps [rcx-0x30], xmm0");
                        __asm__("movaps [rcx-0x20], xmm0");
                        __asm__("movaps [rcx-0x10], xmm0");
                    } while (r9_11);
                    r8 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r8) & 0x7f);
                }
                r9_12 = reinterpret_cast<unsigned char>(r8) >> 4;
                if (r9_12) {
                    do {
                        __asm__("movaps [rcx], xmm0");
                        --r9_12;
                    } while (r9_12);
                }
                if (reinterpret_cast<unsigned char>(r8) & 15) {
                    __asm__("movups [r8+rcx-0x10], xmm0");
                }
                rax13 = r11_4;
                return rax13;
            } else {
                if (reinterpret_cast<unsigned char>(r8) >= reinterpret_cast<unsigned char>(64)) {
                    rcx14 = reinterpret_cast<int64_t>(-reinterpret_cast<unsigned char>(rcx));
                    *reinterpret_cast<uint32_t*>(&rcx15) = *reinterpret_cast<uint32_t*>(&rcx14) & 7;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx15) + 4) = 0;
                    if (*reinterpret_cast<uint32_t*>(&rcx15)) {
                        r8 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r8) - reinterpret_cast<uint64_t>(rcx15));
                        *reinterpret_cast<void***>(r11_4) = rdx8;
                    }
                    rcx = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rcx15) + reinterpret_cast<unsigned char>(r11_4));
                    r9_16 = r8;
                    r8 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r8) & 63);
                    r9_17 = reinterpret_cast<unsigned char>(r9_16) >> 6;
                    if (r9_17) {
                        do {
                            *reinterpret_cast<void***>(rcx) = rdx8;
                            *reinterpret_cast<void***>(rcx + 8) = rdx8;
                            *reinterpret_cast<void***>(rcx + 16) = rdx8;
                            rcx = rcx + 64;
                            *reinterpret_cast<void***>(rcx + 0xffffffffffffffd8) = rdx8;
                            *reinterpret_cast<void***>(rcx + 0xffffffffffffffe0) = rdx8;
                            --r9_17;
                            *reinterpret_cast<void***>(rcx + 0xffffffffffffffe8) = rdx8;
                            *reinterpret_cast<void***>(rcx + 0xfffffffffffffff0) = rdx8;
                            *reinterpret_cast<void***>(rcx + 0xfffffffffffffff8) = rdx8;
                        } while (r9_17);
                    }
                }
                r8_18 = reinterpret_cast<unsigned char>(r8) & 7;
                r9_19 = reinterpret_cast<unsigned char>(r8) >> 3;
                if (r9_19) {
                    do {
                        *reinterpret_cast<void***>(rcx) = rdx8;
                        rcx = rcx + 8;
                        --r9_19;
                    } while (r9_19);
                }
                if (r8_18) {
                    do {
                        *reinterpret_cast<void***>(rcx) = rdx8;
                        ++rcx;
                        --r8_18;
                    } while (r8_18);
                }
            }
        } else {
            rdi20 = rcx;
            eax21 = *reinterpret_cast<uint32_t*>(&rdx5);
            rcx22 = r8;
            while (*reinterpret_cast<int32_t*>(&rcx22)) {
                *reinterpret_cast<int32_t*>(&rcx22) = *reinterpret_cast<int32_t*>(&rcx22) - 1;
                *reinterpret_cast<void***>(rdi20) = *reinterpret_cast<void***>(&eax21);
                ++rdi20;
            }
        }
        rax23 = r11_4;
        return rax23;
    }
}

struct s7 {
    signed char[248] pad248;
    int64_t f248;
};

int64_t RtlCaptureContext = 0x165da;

int64_t RtlLookupFunctionEntry = 0x165ee;

int64_t RtlVirtualUnwind = 0x16608;

void fun_1800060e0(struct s7* rcx) {
    int64_t rcx2;
    int64_t rax3;

    RtlCaptureContext();
    rcx2 = rcx->f248;
    rax3 = reinterpret_cast<int64_t>(RtlLookupFunctionEntry(rcx2, reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 - 8 + 8 + 80));
    if (rax3) {
        RtlVirtualUnwind();
    }
    return;
}

int64_t SetUnhandledExceptionFilter = 0x16638;

int64_t UnhandledExceptionFilter = 0x1661c;

int32_t fun_1800066d0(void* rcx) {
    SetUnhandledExceptionFilter();
    goto UnhandledExceptionFilter;
}

int64_t IsDebuggerPresent = 0x16478;

struct s0* fun_180003798(int64_t rcx, int32_t edx, int32_t r8d) {
    void* rsp4;
    uint64_t rax5;
    uint64_t v6;
    struct s7* rcx7;
    int32_t eax8;
    void* rsp9;
    int32_t eax10;
    void* rsp11;
    int64_t rcx12;
    uint64_t rcx13;
    struct s0* rax14;

    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x5b0);
    rax5 = g1800170a0;
    v6 = rax5 ^ reinterpret_cast<uint64_t>(rsp4);
    if (*reinterpret_cast<int32_t*>(&rcx) != -1) {
        fun_180006ac4(rcx);
        rsp4 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp4) - 8 + 8);
    }
    fun_180003c80(reinterpret_cast<uint64_t>(rsp4) + 52, 0, 0x94);
    rcx7 = reinterpret_cast<struct s7*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 0x4b8 - 48);
    fun_1800060e0(rcx7);
    eax8 = reinterpret_cast<int32_t>(IsDebuggerPresent(rcx7));
    rsp9 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp4) - 8 + 8 - 8 + 8 - 8 + 8);
    eax10 = fun_1800066d0(reinterpret_cast<uint64_t>(rsp9) + 32);
    rsp11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp9) - 8 + 8);
    if (!eax10 && (!eax8 && *reinterpret_cast<int32_t*>(&rcx) != -1)) {
        *reinterpret_cast<int32_t*>(&rcx12) = *reinterpret_cast<int32_t*>(&rcx);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx12) + 4) = 0;
        fun_180006ac4(rcx12);
        rsp11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp11) - 8 + 8);
    }
    rcx13 = v6 ^ reinterpret_cast<uint64_t>(rsp11);
    rax14 = fun_180002f40(rcx13, rcx13);
    return rax14;
}

void** fun_1800039e8(int64_t rcx, ...) {
    int64_t rdx2;
    int32_t* r8_3;
    void** rax4;
    void** rax5;

    *reinterpret_cast<int32_t*>(&rdx2) = 0;
    r8_3 = reinterpret_cast<int32_t*>(0x1800170b0);
    do {
        if (*reinterpret_cast<int32_t*>(&rcx) == *r8_3) 
            break;
        *reinterpret_cast<int32_t*>(&rdx2) = *reinterpret_cast<int32_t*>(&rdx2) + 1;
        r8_3 = r8_3 + 2;
    } while (reinterpret_cast<uint64_t>(static_cast<int64_t>(*reinterpret_cast<int32_t*>(&rdx2))) < 45);
    goto addr_180003a0b_4;
    *reinterpret_cast<int32_t*>(&rax4) = *reinterpret_cast<int32_t*>(0x1800170b0 + *reinterpret_cast<int32_t*>(&rdx2) * 8 + 4);
    *reinterpret_cast<int32_t*>(&rax4 + 4) = 0;
    return rax4;
    addr_180003a0b_4:
    if (static_cast<uint32_t>(rcx - 19) > 17) {
        *reinterpret_cast<int32_t*>(&rax5) = 22;
        *reinterpret_cast<int32_t*>(&rax5 + 4) = 0;
        if (reinterpret_cast<uint32_t>(*reinterpret_cast<int32_t*>(&rcx) - 0xbc) <= 14) {
            *reinterpret_cast<int32_t*>(&rax5) = 8;
            *reinterpret_cast<int32_t*>(&rax5 + 4) = 0;
        }
        return rax5;
    } else {
        return 13;
    }
}

struct s8 {
    signed char[48] pad48;
    void** f48;
    signed char[47] pad96;
    void** f96;
};

struct s8* fun_180006b94() {
    return 0x1800172a0;
}

void** g18001f0e8;

uint32_t fun_180006cd0(void** ecx) {
    int1_t cf2;
    void** rax3;
    int64_t rcx4;
    int64_t rcx5;
    uint32_t eax6;
    void** rax7;

    if (!reinterpret_cast<int1_t>(ecx == 0xfffffffe)) {
        if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || (cf2 = reinterpret_cast<unsigned char>(ecx) < reinterpret_cast<unsigned char>(g18001f0e8), !cf2)) {
            rax3 = fun_1800039c8();
            *reinterpret_cast<void***>(rax3) = reinterpret_cast<void**>(9);
            fun_1800038fc();
        } else {
            rcx4 = reinterpret_cast<int32_t>(ecx);
            *reinterpret_cast<uint32_t*>(&rcx5) = *reinterpret_cast<uint32_t*>(&rcx4) & 31;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx5) + 4) = 0;
            eax6 = reinterpret_cast<uint32_t>(static_cast<int32_t>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + (rcx4 >> 5) * 8)) + rcx5 * 88 + 8))) & 64;
            goto addr_180006d2a_5;
        }
    } else {
        rax7 = fun_1800039c8();
        *reinterpret_cast<void***>(rax7) = reinterpret_cast<void**>(9);
    }
    eax6 = 0;
    addr_180006d2a_5:
    return eax6;
}

int32_t g18001d65c;

void** fun_180006770(void** rcx, void** rdx, ...);

void fun_180007784(void** rcx, void** rdx) {
    void** rax3;
    void** rax4;

    ++g18001d65c;
    rax3 = fun_180006770(0x1000, rdx);
    *reinterpret_cast<void***>(rcx + 16) = rax3;
    if (!rax3) {
        *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) | 4);
        *reinterpret_cast<void**>(rcx + 36) = reinterpret_cast<void*>(2);
        *reinterpret_cast<void***>(rcx + 16) = rcx + 32;
    } else {
        *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) | 8);
        *reinterpret_cast<void**>(rcx + 36) = reinterpret_cast<void*>(0x1000);
    }
    rax4 = *reinterpret_cast<void***>(rcx + 16);
    *reinterpret_cast<void***>(rcx + 8) = reinterpret_cast<void**>(0);
    *reinterpret_cast<void***>(rcx) = rax4;
    return;
}

void** fun_180003958();

int64_t fun_1800098a0(void** ecx, void** rdx, void** r8);

void** fun_180006e14(void** ecx, void** rdx, void** r8d);

void fun_180009a58(void** ecx, void** rdx, void** r8);

void** fun_180006d30(void** ecx, void** rdx, void** r8) {
    int64_t rbx4;
    int1_t cf5;
    int64_t rax6;
    int64_t rdi7;
    int64_t rax8;
    int64_t r15_9;
    void** rax10;
    void** rax11;
    void** rax12;
    void** rax13;
    void** edi14;
    void** eax15;
    void** eax16;
    void** rax17;
    void** rax18;

    rbx4 = reinterpret_cast<int32_t>(ecx);
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rbx4) == 0xfffffffe)) {
        if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || ((cf5 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rbx4)) < reinterpret_cast<unsigned char>(g18001f0e8), !cf5) || (rax6 = rbx4, rdi7 = rbx4 >> 5, *reinterpret_cast<uint32_t*>(&rax8) = *reinterpret_cast<uint32_t*>(&rax6) & 31, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax8) + 4) = 0, r15_9 = rax8 * 88, (reinterpret_cast<uint32_t>(static_cast<int32_t>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi7 * 8)) + r15_9 + 8))) & 1) == 0))) {
            rax10 = fun_180003958();
            *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(0);
            rax11 = fun_1800039c8();
            *reinterpret_cast<void***>(rax11) = reinterpret_cast<void**>(9);
            fun_1800038fc();
        } else {
            fun_1800098a0(*reinterpret_cast<void***>(&rbx4), rdx, r8);
            if (!(*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi7 * 8)) + r15_9 + 8) & 1)) {
                rax12 = fun_1800039c8();
                *reinterpret_cast<void***>(rax12) = reinterpret_cast<void**>(9);
                rax13 = fun_180003958();
                *reinterpret_cast<void***>(rax13) = reinterpret_cast<void**>(0);
                edi14 = reinterpret_cast<void**>(0xffffffff);
            } else {
                r8 = r8;
                *reinterpret_cast<int32_t*>(&r8 + 4) = 0;
                rdx = rdx;
                eax15 = fun_180006e14(*reinterpret_cast<void***>(&rbx4), rdx, r8);
                edi14 = eax15;
            }
            fun_180009a58(*reinterpret_cast<void***>(&rbx4), rdx, r8);
            eax16 = edi14;
            goto addr_180006dff_8;
        }
    } else {
        rax17 = fun_180003958();
        *reinterpret_cast<void***>(rax17) = reinterpret_cast<void**>(0);
        rax18 = fun_1800039c8();
        *reinterpret_cast<void***>(rax18) = reinterpret_cast<void**>(9);
    }
    eax16 = reinterpret_cast<void**>(0xffffffff);
    addr_180006dff_8:
    return eax16;
}

void** fun_1800076f0(void** ecx, void** rdx, void** r8d);

void** fun_180007608(void** ecx, void** rdx, void** r8) {
    int64_t rbx4;
    int1_t cf5;
    int64_t rax6;
    uint64_t rdi7;
    int64_t rax8;
    int64_t r15_9;
    void** rax10;
    void** rax11;
    void** rax12;
    void** rax13;
    void** rdi14;
    void** rax15;
    void** rax16;
    void** rax17;
    void** rax18;

    rbx4 = reinterpret_cast<int32_t>(ecx);
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rbx4) == 0xfffffffe)) {
        if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || ((cf5 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rbx4)) < reinterpret_cast<unsigned char>(g18001f0e8), !cf5) || (rax6 = rbx4, rdi7 = reinterpret_cast<uint64_t>(rbx4 >> 5), *reinterpret_cast<uint32_t*>(&rax8) = *reinterpret_cast<uint32_t*>(&rax6) & 31, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax8) + 4) = 0, r15_9 = rax8 * 88, (reinterpret_cast<uint32_t>(static_cast<int32_t>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi7 * 8)) + r15_9 + 8))) & 1) == 0))) {
            rax10 = fun_180003958();
            *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(0);
            rax11 = fun_1800039c8();
            *reinterpret_cast<void***>(rax11) = reinterpret_cast<void**>(9);
            fun_1800038fc();
        } else {
            fun_1800098a0(*reinterpret_cast<void***>(&rbx4), rdx, r8);
            if (!(*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi7 * 8)) + r15_9 + 8) & 1)) {
                rax12 = fun_1800039c8();
                *reinterpret_cast<void***>(rax12) = reinterpret_cast<void**>(9);
                rax13 = fun_180003958();
                *reinterpret_cast<void***>(rax13) = reinterpret_cast<void**>(0);
                rdi14 = reinterpret_cast<void**>(0xffffffffffffffff);
            } else {
                r8 = r8;
                *reinterpret_cast<int32_t*>(&r8 + 4) = 0;
                rdx = rdx;
                rax15 = fun_1800076f0(*reinterpret_cast<void***>(&rbx4), rdx, r8);
                rdi14 = rax15;
            }
            fun_180009a58(*reinterpret_cast<void***>(&rbx4), rdx, r8);
            rax16 = rdi14;
            goto addr_1800076db_8;
        }
    } else {
        rax17 = fun_180003958();
        *reinterpret_cast<void***>(rax17) = reinterpret_cast<void**>(0);
        rax18 = fun_1800039c8();
        *reinterpret_cast<void***>(rax18) = reinterpret_cast<void**>(9);
    }
    rax16 = reinterpret_cast<void**>(0xffffffffffffffff);
    addr_1800076db_8:
    return rax16;
}

void fun_1800053cc(int32_t ecx, void** rdx);

void** fun_180005018() {
    void** rax1;
    void** rdx2;

    rax1 = fun_18000503c();
    if (!rax1) {
        fun_1800053cc(static_cast<int32_t>(reinterpret_cast<uint64_t>(rax1 + 16)), rdx2);
    }
    return rax1;
}

uint32_t g180017fd8 = 0xfffffffe;

void** fun_180007b18(void*** rcx, void** rdx);

void** fun_180007aa0() {
    void** rax1;
    uint32_t ecx2;
    void** rdx3;
    void** r8_4;
    void** rdx5;
    void** rax6;
    void** rbx7;
    void** rax8;

    rax1 = fun_180005018();
    ecx2 = g180017fd8;
    if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rax1 + 0xc8)) & ecx2) || !*reinterpret_cast<void***>(rax1 + 0xc0)) {
        fun_1800088e8(12, rdx3, r8_4);
        rdx5 = g180017e70;
        rax6 = fun_180007b18(rax1 + 0xc0, rdx5);
        rbx7 = rax6;
        fun_180008ad8(12, 12);
    } else {
        rax8 = fun_180005018();
        rbx7 = *reinterpret_cast<void***>(rax8 + 0xc0);
    }
    if (!rbx7) {
        fun_1800053cc(static_cast<int32_t>(reinterpret_cast<uint64_t>(rbx7 + 32)), rdx5);
    }
    return rbx7;
}

void** g180017b90 = reinterpret_cast<void**>(0x70);

void** fun_180007e98() {
    void** rax1;
    uint32_t ecx2;
    void** rdx3;
    void** r8_4;
    void** rbx5;
    int1_t zf6;
    void** rax7;
    void** rax8;
    void** rdx9;

    rax1 = fun_180005018();
    ecx2 = g180017fd8;
    if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rax1 + 0xc8)) & ecx2) || !*reinterpret_cast<void***>(rax1 + 0xc0)) {
        fun_1800088e8(13, rdx3, r8_4);
        rbx5 = *reinterpret_cast<void***>(rax1 + 0xb8);
        zf6 = rbx5 == g180017b90;
        if (!zf6) {
            if (rbx5 && ((*reinterpret_cast<void***>(rbx5) = *reinterpret_cast<void***>(rbx5) - 1, !*reinterpret_cast<void***>(rbx5)) && rbx5 != 0x180017870)) {
                fun_180005f00(rbx5);
            }
            rax7 = g180017b90;
            *reinterpret_cast<void***>(rax1 + 0xb8) = rax7;
            rax8 = g180017b90;
            *reinterpret_cast<void***>(rax8) = *reinterpret_cast<void***>(rax8) + 1;
            rbx5 = rax8;
        }
        fun_180008ad8(13);
    } else {
        rbx5 = *reinterpret_cast<void***>(rax1 + 0xb8);
    }
    if (!rbx5) {
        fun_1800053cc(static_cast<int32_t>(reinterpret_cast<uint64_t>(rbx5 + 32)), rdx9);
    }
    return rbx5;
}

void** fun_180006ca8(void** rcx, void** rdx) {
    void** eax3;
    void** rax4;

    if (rcx) {
        eax3 = *reinterpret_cast<void***>(rcx + 28);
    } else {
        rax4 = fun_1800039c8();
        *reinterpret_cast<void***>(rax4) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        eax3 = reinterpret_cast<void**>(0xffffffff);
    }
    return eax3;
}

void** fun_1800085b0(uint32_t* rcx, void** rdx, void** r8, uint16_t r9w);

void** fun_18000873c(uint32_t* rcx, void** rdx, void** r8, uint16_t r9w) {
    void** eax5;

    eax5 = fun_1800085b0(rcx, rdx, r8, r9w);
    return eax5;
}

void** fun_180009414(void** rcx, ...);

void** fun_180006770(void** rcx, void** rdx, ...) {
    uint32_t esi3;
    int64_t rbx4;
    void** rbp5;
    void** rax6;
    int64_t rcx7;
    uint32_t ecx8;

    esi3 = g18001d658;
    *reinterpret_cast<uint32_t*>(&rbx4) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx4) + 4) = 0;
    rbp5 = rcx;
    do {
        rax6 = fun_180009414(rbp5);
        if (rax6) 
            break;
        if (!esi3) 
            break;
        *reinterpret_cast<uint32_t*>(&rcx7) = *reinterpret_cast<uint32_t*>(&rbx4);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
        fun_1800066a8(rcx7, rdx);
        esi3 = g18001d658;
        ecx8 = static_cast<uint32_t>(rbx4 + 0x3e8);
        *reinterpret_cast<uint32_t*>(&rbx4) = ecx8;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx4) + 4) = 0;
        if (ecx8 > esi3) {
            *reinterpret_cast<uint32_t*>(&rbx4) = 0xffffffff;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx4) + 4) = 0;
        }
    } while (*reinterpret_cast<uint32_t*>(&rbx4) != 0xffffffff);
    return rax6;
}

void* fun_1800084f0(void** rcx, ...) {
    void** rax2;
    void* rcx3;
    void** rdx4;
    uint64_t rdx5;
    uint64_t rdx6;
    uint32_t edx7;

    rax2 = rcx;
    rcx3 = reinterpret_cast<void*>(-reinterpret_cast<unsigned char>(rcx));
    if (!(reinterpret_cast<unsigned char>(rax2) & 7)) {
        addr_18000850d_2:
    } else {
        do {
            ++rax2;
            if (!*reinterpret_cast<void***>(rax2)) 
                goto addr_180008568_5;
        } while (*reinterpret_cast<unsigned char*>(&rax2) & 7);
        goto addr_18000850d_2;
    }
    do {
        addr_180008521_7:
        rax2 = rax2 + 8;
        if (!((reinterpret_cast<uint64_t>(~reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rax2))) ^ reinterpret_cast<uint64_t>(*reinterpret_cast<void***>(rax2) + 0x7efefefefefefeff)) & 0x8101010101010100)) 
            goto addr_180008521_7;
        rdx4 = *reinterpret_cast<void***>(rax2 + 0xfffffffffffffff8);
        if (!*reinterpret_cast<signed char*>(&rdx4)) 
            break;
        if (!*reinterpret_cast<signed char*>(&rdx4 + 1)) 
            goto addr_18000858c_10;
        rdx5 = reinterpret_cast<unsigned char>(rdx4) >> 16;
        if (!*reinterpret_cast<signed char*>(&rdx5)) 
            goto addr_180008586_12;
        if (1) 
            goto addr_180008580_14;
        rdx6 = rdx5 >> 16;
        if (!*reinterpret_cast<signed char*>(&rdx6)) 
            goto addr_18000857a_16;
        if (1) 
            goto addr_180008574_18;
        edx7 = *reinterpret_cast<uint32_t*>(&rdx6) >> 16;
        if (!*reinterpret_cast<signed char*>(&edx7)) 
            goto addr_18000856e_20;
    } while (*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&edx7) + 1));
    goto addr_180008568_5;
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffff8;
    addr_18000858c_10:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffff9;
    addr_180008586_12:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffffa;
    addr_180008580_14:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffffb;
    addr_18000857a_16:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffffc;
    addr_180008574_18:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffffd;
    addr_18000856e_20:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xfffffffffffffffe;
    addr_180008568_5:
    return reinterpret_cast<int64_t>(rcx3) + reinterpret_cast<unsigned char>(rax2) + 0xffffffffffffffff;
}

void fun_1800048d4(void** cl, void** rdx, void** r8, void** r9);

void fun_18000491c(void** cl, void* edx, void** r8, void** r9) {
    void** rdi5;
    void** rsi6;
    void* ebx7;
    void** bpl8;

    if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(edx) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(edx == 0))) {
        rdi5 = r9;
        rsi6 = r8;
        ebx7 = edx;
        bpl8 = cl;
        do {
            ebx7 = reinterpret_cast<void*>(reinterpret_cast<uint32_t>(ebx7) - 1);
            fun_1800048d4(bpl8, rsi6, rdi5, r9);
            if (*reinterpret_cast<void***>(rdi5) == 0xffffffff) 
                break;
        } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(ebx7) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(ebx7 == 0)));
    }
    return;
}

void fun_180004970(void** rcx, void** edx, void** r8, void** r9) {
    uint32_t* rbx5;
    uint32_t* v6;
    void** rdi7;
    uint32_t r15d8;
    void** rbp9;
    void** esi10;
    void** r14_11;
    void** cl12;

    rbx5 = v6;
    rdi7 = r9;
    r15d8 = *rbx5;
    rbp9 = r8;
    esi10 = edx;
    r14_11 = rcx;
    if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(r8 + 24)) & 64) || *reinterpret_cast<void***>(r8 + 16)) {
        *rbx5 = 0;
        if (reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(edx) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(edx == 0)) {
            addr_1800049e8_3:
            *rbx5 = r15d8;
        } else {
            do {
                cl12 = *reinterpret_cast<void***>(r14_11);
                --esi10;
                fun_1800048d4(cl12, rbp9, rdi7, r9);
                ++r14_11;
                if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rdi7) == 0xffffffff)) {
                    if (*rbx5 != 42) 
                        break;
                    fun_1800048d4(63, rbp9, rdi7, r9);
                }
            } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(esi10) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(esi10 == 0)));
            if (!*rbx5) 
                goto addr_1800049e8_3;
        }
    } else {
        *reinterpret_cast<void***>(r9) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(r9)) + reinterpret_cast<unsigned char>(edx));
    }
    return;
}

void** fun_180005f00(void** rcx, ...) {
    uint64_t rcx2;
    void** rax3;
    void** rax4;
    int32_t eax5;
    int64_t rcx6;

    if (rcx) {
        rcx2 = g18001d340;
        rax3 = reinterpret_cast<void**>(HeapFree(rcx2));
        if (!rax3) {
            rax4 = fun_1800039c8();
            eax5 = reinterpret_cast<int32_t>(GetLastError(rcx2));
            *reinterpret_cast<int32_t*>(&rcx6) = eax5;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx6) + 4) = 0;
            rax3 = fun_1800039e8(rcx6);
            *reinterpret_cast<void***>(rax4) = rax3;
        }
    }
    return rax3;
}

void fun_1800048d4(void** cl, void** rdx, void** r8, void** r9) {
    uint32_t eax5;

    if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx + 24)) & 64) || *reinterpret_cast<void***>(rdx + 16)) {
        *reinterpret_cast<void***>(rdx + 8) = *reinterpret_cast<void***>(rdx + 8) - 1;
        if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(rdx + 8)) < reinterpret_cast<signed char>(0)) {
            eax5 = fun_180003a38(static_cast<int32_t>(reinterpret_cast<signed char>(cl)), rdx, r8, r9);
        } else {
            *reinterpret_cast<void***>(*reinterpret_cast<void***>(rdx)) = cl;
            *reinterpret_cast<void***>(rdx) = *reinterpret_cast<void***>(rdx) + 1;
            eax5 = reinterpret_cast<unsigned char>(cl);
        }
        if (eax5 != 0xffffffff) {
            *reinterpret_cast<void***>(r8) = *reinterpret_cast<void***>(r8) + 1;
        } else {
            *reinterpret_cast<void***>(r8) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(r8)) | eax5);
        }
    } else {
        *reinterpret_cast<void***>(r8) = *reinterpret_cast<void***>(r8) + 1;
    }
    return;
}

void fun_180006150(struct s1* rcx) {
    void* rsp2;
    int64_t rsi3;
    int32_t edi4;
    int64_t rax5;

    RtlCaptureContext();
    rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 64 - 8 + 8);
    rsi3 = rcx->f248;
    edi4 = 0;
    do {
        rax5 = reinterpret_cast<int64_t>(RtlLookupFunctionEntry(rsi3, reinterpret_cast<int64_t>(rsp2) + 96));
        rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp2) - 8 + 8);
        if (!rax5) 
            break;
        RtlVirtualUnwind();
        rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp2) - 8 + 8);
        ++edi4;
    } while (edi4 < 2);
    return;
}

int32_t g18001d2e0;

int64_t GetCurrentProcess = 0x16686;

int64_t TerminateProcess = 0x1669a;

struct s0* fun_180004a04(void* rcx) {
    int32_t eax2;
    int1_t zf3;

    eax2 = reinterpret_cast<int32_t>(IsDebuggerPresent());
    g18001d2e0 = eax2;
    fun_180006ac4(1);
    fun_1800066d0(rcx);
    zf3 = g18001d2e0 == 0;
    if (zf3) {
        fun_180006ac4(1);
    }
    GetCurrentProcess();
    goto TerminateProcess;
}

int64_t fun_1800089b4(int32_t ecx, void** rdx, void** r8);

int64_t EnterCriticalSection = 0x16702;

void fun_1800088e8(int32_t ecx, void** rdx, void** r8) {
    int64_t rbx4;
    int64_t rax5;

    rbx4 = ecx;
    if (!*reinterpret_cast<int64_t*>(0x180018030 + (rbx4 + rbx4) * 8) && (rax5 = fun_1800089b4(ecx, rdx, r8), !*reinterpret_cast<int32_t*>(&rax5))) {
        fun_1800053cc(static_cast<int32_t>(rax5 + 17), rdx);
    }
    goto EnterCriticalSection;
}

void** fun_1800079fc(void** rcx) {
    void*** rax2;
    int64_t r8_3;

    if (rcx) {
        *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(rcx) + 0xffffffff;
        if (*reinterpret_cast<void***>(rcx + 0xd8)) {
            *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xd8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xd8)) + 0xffffffff;
        }
        if (*reinterpret_cast<void***>(rcx + 0xe8)) {
            *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe8)) + 0xffffffff;
        }
        if (*reinterpret_cast<void***>(rcx + 0xe0)) {
            *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe0)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe0)) + 0xffffffff;
        }
        if (*reinterpret_cast<void***>(rcx + 0xf8)) {
            *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xf8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xf8)) + 0xffffffff;
        }
        rax2 = reinterpret_cast<void***>(rcx + 40);
        *reinterpret_cast<int32_t*>(&r8_3) = 6;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
        do {
            if (*(rax2 - 16) != "C" && *rax2) {
                *reinterpret_cast<void***>(*rax2) = *reinterpret_cast<void***>(*rax2) + 0xffffffff;
            }
            if (*reinterpret_cast<int64_t*>(rax2 - 24) && *(rax2 - 8)) {
                *reinterpret_cast<void***>(*(rax2 - 8)) = *reinterpret_cast<void***>(*(rax2 - 8)) + 0xffffffff;
            }
            rax2 = rax2 + 32;
            --r8_3;
        } while (r8_3);
        *reinterpret_cast<uint32_t*>(*reinterpret_cast<void***>(rcx + 0x120) + 0x15c) = *reinterpret_cast<uint32_t*>(*reinterpret_cast<void***>(rcx + 0x120) + 0x15c) + 0xffffffff;
    }
    return rcx;
}

void** fun_180009b40(void** rcx);

void** fun_180009c4c(void** rcx);

void** fun_180009cb8(void** rcx);

void** fun_180007864(void** rcx) {
    void** rbx2;
    void** rcx3;
    void** rcx4;
    void** rcx5;
    void** rcx6;
    void** rcx7;
    void** rcx8;
    void** rcx9;
    void** rcx10;
    void** rcx11;
    void** rcx12;
    void** rcx13;
    void** rcx14;
    void*** rsi15;
    void*** rdi16;
    int64_t rbp17;
    void** rax18;
    void** rcx19;
    void** rcx20;
    void** rcx21;
    uint64_t rcx22;
    void** rax23;
    int32_t eax24;
    int64_t rcx25;

    rbx2 = rcx;
    if (*reinterpret_cast<void***>(rcx + 0xf0) && (*reinterpret_cast<void***>(rcx + 0xf0) != 0x180018270 && (*reinterpret_cast<void***>(rbx2 + 0xd8) && !*reinterpret_cast<void***>(*reinterpret_cast<void***>(rbx2 + 0xd8))))) {
        rcx3 = *reinterpret_cast<void***>(rbx2 + 0xe8);
        if (rcx3 && !*reinterpret_cast<void***>(rcx3)) {
            fun_180005f00(rcx3);
            rcx4 = *reinterpret_cast<void***>(rbx2 + 0xf0);
            fun_180009b40(rcx4);
        }
        rcx5 = *reinterpret_cast<void***>(rbx2 + 0xe0);
        if (rcx5 && !*reinterpret_cast<void***>(rcx5)) {
            fun_180005f00(rcx5);
            rcx6 = *reinterpret_cast<void***>(rbx2 + 0xf0);
            fun_180009c4c(rcx6);
        }
        rcx7 = *reinterpret_cast<void***>(rbx2 + 0xd8);
        fun_180005f00(rcx7);
        rcx8 = *reinterpret_cast<void***>(rbx2 + 0xf0);
        fun_180005f00(rcx8);
    }
    if (*reinterpret_cast<void***>(rbx2 + 0xf8) && !*reinterpret_cast<void***>(*reinterpret_cast<void***>(rbx2 + 0xf8))) {
        rcx9 = *reinterpret_cast<void***>(rbx2 + 0x100) - 0xfe;
        fun_180005f00(rcx9);
        rcx10 = *reinterpret_cast<void***>(rbx2 + 0x110) - 0x80;
        fun_180005f00(rcx10);
        rcx11 = *reinterpret_cast<void***>(rbx2 + 0x118) - 0x80;
        fun_180005f00(rcx11);
        rcx12 = *reinterpret_cast<void***>(rbx2 + 0xf8);
        fun_180005f00(rcx12);
    }
    rcx13 = *reinterpret_cast<void***>(rbx2 + 0x120);
    if (rcx13 != 0x180017bb0 && !*reinterpret_cast<uint32_t*>(rcx13 + 0x15c)) {
        fun_180009cb8(rcx13);
        rcx14 = *reinterpret_cast<void***>(rbx2 + 0x120);
        fun_180005f00(rcx14);
    }
    rsi15 = reinterpret_cast<void***>(rbx2 + 0x128);
    rdi16 = reinterpret_cast<void***>(rbx2 + 40);
    *reinterpret_cast<int32_t*>(&rbp17) = 6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbp17) + 4) = 0;
    do {
        rax18 = reinterpret_cast<void**>("C");
        if (*(rdi16 - 16) != "C" && ((rcx19 = *rdi16, !!rcx19) && !*reinterpret_cast<void***>(rcx19))) {
            fun_180005f00(rcx19);
            rcx20 = *rsi15;
            rax18 = fun_180005f00(rcx20);
        }
        if (*reinterpret_cast<int64_t*>(rdi16 - 24) && ((rcx21 = *(rdi16 - 8), !!rcx21) && !*reinterpret_cast<void***>(rcx21))) {
            rax18 = fun_180005f00(rcx21);
        }
        rsi15 = rsi15 + 8;
        rdi16 = rdi16 + 32;
        --rbp17;
    } while (rbp17);
    if (rbx2) {
        rcx22 = g18001d340;
        rax18 = reinterpret_cast<void**>(HeapFree(rcx22));
        if (!rax18) {
            rax23 = fun_1800039c8();
            eax24 = reinterpret_cast<int32_t>(GetLastError(rcx22));
            *reinterpret_cast<int32_t*>(&rcx25) = eax24;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx25) + 4) = 0;
            rax18 = fun_1800039e8(rcx25);
            *reinterpret_cast<void***>(rax23) = rax18;
        }
    }
    return rax18;
}

uint32_t fun_180008af0();

uint32_t fun_180008b64(int32_t ecx);

void fun_1800055a8(int32_t ecx, void** rdx, void** r8);

void fun_1800053cc(int32_t ecx, void** rdx) {
    void** rdx3;
    int1_t zf4;
    void** rcx5;
    int64_t* rax6;
    int64_t* rsi7;
    void** rcx8;
    int64_t* rax9;
    int64_t* rdi10;
    int64_t* r12_11;
    int64_t* r15_12;
    int64_t rax13;
    int64_t rcx14;
    int64_t rax15;
    int64_t rax16;
    void** rcx17;
    int64_t* rax18;
    void** rcx19;
    int64_t* rax20;
    int64_t v21;

    fun_180008af0();
    fun_180008b64(ecx);
    fun_1800055a8(0xff, 1, 0);
    *reinterpret_cast<int32_t*>(&rdx3) = 0;
    *reinterpret_cast<int32_t*>(&rdx3 + 4) = 0;
    fun_1800088e8(8, 0, 1);
    zf4 = g18001d2e8 == 1;
    if (!zf4) {
        g18001d328 = 1;
        g18001d324 = 1;
        if (!0) {
            rcx5 = g18001f100;
            rax6 = reinterpret_cast<int64_t*>(DecodePointer(rcx5));
            rsi7 = rax6;
            if (rax6) {
                rcx8 = g18001f0f8;
                rax9 = reinterpret_cast<int64_t*>(DecodePointer(rcx8));
                rdi10 = rax9;
                r12_11 = rsi7;
                r15_12 = rax9;
                while (--rdi10, reinterpret_cast<uint64_t>(rdi10) >= reinterpret_cast<uint64_t>(rsi7)) {
                    rax13 = reinterpret_cast<int64_t>(EncodePointer());
                    if (*rdi10 != rax13) {
                        if (reinterpret_cast<uint64_t>(rdi10) < reinterpret_cast<uint64_t>(rsi7)) 
                            break;
                        rcx14 = *rdi10;
                        rax15 = reinterpret_cast<int64_t>(DecodePointer(rcx14));
                        rax16 = reinterpret_cast<int64_t>(EncodePointer());
                        *rdi10 = rax16;
                        rax15();
                        rcx17 = g18001f100;
                        rax18 = reinterpret_cast<int64_t*>(DecodePointer(rcx17));
                        rcx19 = g18001f0f8;
                        rax20 = reinterpret_cast<int64_t*>(DecodePointer(rcx19));
                        if (r12_11 != rax18) 
                            goto addr_1800056a2_11;
                        if (r15_12 == rax20) 
                            goto addr_18000565b_13;
                    } else {
                        addr_18000565b_13:
                        continue;
                    }
                    addr_1800056a2_11:
                    r12_11 = rax18;
                    rsi7 = rax18;
                    r15_12 = rax20;
                    rdi10 = rax20;
                    goto addr_18000565b_13;
                }
            }
            fun_1800054f4(0x18000f2b0, 0x18000f2d0);
        }
        rdx3 = reinterpret_cast<void**>(0x18000f2e0);
        fun_1800054f4(0x18000f2d8, 0x18000f2e0);
    }
    if (static_cast<int1_t>(fun_180008ad8(8, 8), !1)) {
        g18001d2e8 = 1;
        fun_180008ad8(8, 8);
        fun_180005228(0, rdx3);
        ExitProcess(0, rdx3);
    }
    goto v21;
}

void** fun_18000503c() {
    int32_t eax1;
    void** rax2;
    void** rbx3;
    void* rcx4;
    void** rdx5;
    void** r8_6;
    void** rax7;
    int64_t rcx8;
    int32_t eax9;
    void** r8_10;
    void** eax11;
    int64_t rcx12;

    eax1 = reinterpret_cast<int32_t>(GetLastError());
    rax2 = fun_1800061fc();
    rbx3 = rax2;
    if (!rax2 && (*reinterpret_cast<int32_t*>(&rcx4) = static_cast<int32_t>(reinterpret_cast<uint64_t>(rax2 + 1)), *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx4) + 4) = 0, *reinterpret_cast<int32_t*>(&rdx5) = 0x478, *reinterpret_cast<int32_t*>(&rdx5 + 4) = 0, rax7 = fun_1800066f0(rcx4, 0x478, r8_6), rbx3 = rax7, !!rax7)) {
        *reinterpret_cast<uint32_t*>(&rcx8) = g180017238;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx8) + 4) = 0;
        rdx5 = rax7;
        eax9 = fun_180006218(rcx8, rcx8);
        if (!eax9) {
            fun_180005f00(rbx3, rbx3);
            *reinterpret_cast<int32_t*>(&rbx3) = 0;
            *reinterpret_cast<int32_t*>(&rbx3 + 4) = 0;
        } else {
            *reinterpret_cast<int32_t*>(&rdx5) = 0;
            *reinterpret_cast<int32_t*>(&rdx5 + 4) = 0;
            fun_1800050c0(rbx3, 0, r8_10);
            eax11 = reinterpret_cast<void**>(GetCurrentThreadId(rbx3));
            *reinterpret_cast<void***>(rbx3 + 8) = reinterpret_cast<void**>(0xffffffffffffffff);
            *reinterpret_cast<void***>(rbx3) = eax11;
        }
    }
    *reinterpret_cast<int32_t*>(&rcx12) = eax1;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx12) + 4) = 0;
    SetLastError(rcx12, rdx5);
    return rbx3;
}

void fun_1800077d8(void** rcx) {
    void*** rax2;
    int64_t r8_3;

    *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(rcx) + 1;
    if (*reinterpret_cast<void***>(rcx + 0xd8)) {
        *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xd8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xd8)) + 1;
    }
    if (*reinterpret_cast<void***>(rcx + 0xe8)) {
        *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe8)) + 1;
    }
    if (*reinterpret_cast<void***>(rcx + 0xe0)) {
        *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe0)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xe0)) + 1;
    }
    if (*reinterpret_cast<void***>(rcx + 0xf8)) {
        *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xf8)) = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx + 0xf8)) + 1;
    }
    rax2 = reinterpret_cast<void***>(rcx + 40);
    *reinterpret_cast<int32_t*>(&r8_3) = 6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
    do {
        if (*(rax2 - 16) != "C" && *rax2) {
            *reinterpret_cast<void***>(*rax2) = *reinterpret_cast<void***>(*rax2) + 1;
        }
        if (*reinterpret_cast<int64_t*>(rax2 - 24) && *(rax2 - 8)) {
            *reinterpret_cast<void***>(*(rax2 - 8)) = *reinterpret_cast<void***>(*(rax2 - 8)) + 1;
        }
        rax2 = rax2 + 32;
        --r8_3;
    } while (r8_3);
    *reinterpret_cast<uint32_t*>(*reinterpret_cast<void***>(rcx + 0x120) + 0x15c) = *reinterpret_cast<uint32_t*>(*reinterpret_cast<void***>(rcx + 0x120) + 0x15c) + 1;
    return;
}

int64_t LeaveCriticalSection = 0x1671a;

void fun_180008ad8(int32_t ecx, ...) {
    goto LeaveCriticalSection;
}

uint64_t g18001efe0;

int64_t TlsAlloc = 0x166ae;

uint32_t fun_1800061c4(int64_t rcx) {
    uint64_t rax2;
    uint64_t rax3;

    rax2 = g18001efe0;
    rax3 = rax2 ^ g1800170a0;
    if (!rax3) {
        goto TlsAlloc;
    } else {
        goto rax3;
    }
}

uint64_t g18001efe8;

int64_t TlsFree = 0x166d6;

int32_t fun_1800061e0() {
    uint64_t rax1;
    uint64_t rax2;

    rax1 = g18001efe8;
    rax2 = rax1 ^ g1800170a0;
    if (!rax2) {
        goto TlsFree;
    } else {
        goto rax2;
    }
}

int64_t GetModuleHandleExW = 0x164d6;

int64_t GetProcAddress = 0x164ec;

void fun_180005228(int32_t ecx, void** rdx) {
    void* r8_3;
    int32_t eax4;
    int64_t v5;
    int64_t rax6;
    int64_t rcx7;

    r8_3 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 32 + 56);
    eax4 = reinterpret_cast<int32_t>(GetModuleHandleExW());
    if (eax4 && (rax6 = reinterpret_cast<int64_t>(GetProcAddress(v5, "CorExitProcess", r8_3)), !!rax6)) {
        *reinterpret_cast<int32_t*>(&rcx7) = ecx;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
        rax6(rcx7, "CorExitProcess", r8_3);
    }
    return;
}

struct s9 {
    int16_t f0;
    signed char[58] pad60;
    int32_t f60;
};

uint32_t fun_180008e80(struct s9* rcx);

struct s10 {
    signed char[8] pad8;
    int32_t f8;
    int32_t f12;
    signed char[20] pad36;
    uint32_t f36;
};

struct s11 {
    signed char[60] pad60;
    int32_t f60;
};

struct s10* fun_180008de0(struct s11* rcx, uint64_t rdx);

uint32_t fun_180008e30(int64_t rcx, void** rdx, void** r8, struct s6* r9) {
    struct s10* rax5;

    *reinterpret_cast<uint32_t*>(&rax5) = fun_180008e80(0x180000000);
    if (*reinterpret_cast<uint32_t*>(&rax5) && (rax5 = fun_180008de0(0x180000000, rcx - 0x180000000), !!rax5)) {
        *reinterpret_cast<uint32_t*>(&rax5) = ~(rax5->f36 >> 31) & 1;
    }
    return *reinterpret_cast<uint32_t*>(&rax5);
}

int64_t fun_180008ef4(int64_t rcx);

int64_t fun_180009000(int64_t rcx, int64_t* rdx) {
    int64_t rax3;
    int64_t rax4;
    int64_t rax5;

    rax3 = fun_180008ef4(rcx);
    rax4 = -rax3;
    *reinterpret_cast<int32_t*>(&rax5) = reinterpret_cast<int32_t>(-(*reinterpret_cast<uint32_t*>(&rax4) - (*reinterpret_cast<uint32_t*>(&rax4) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax4) < *reinterpret_cast<uint32_t*>(&rax4) + reinterpret_cast<uint1_t>(!!rax3))))) - 1;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax5) + 4) = 0;
    return rax5;
}

void fun_1800054f4(void** rcx, void** rdx) {
    void** rdi3;
    uint64_t rsi4;
    uint64_t rbx5;
    void** rax6;

    rdi3 = rcx;
    *reinterpret_cast<int32_t*>(&rsi4) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi4) + 4) = 0;
    rbx5 = reinterpret_cast<unsigned char>(rdx) - reinterpret_cast<unsigned char>(rcx) + 7 >> 3;
    if (reinterpret_cast<unsigned char>(rcx) > reinterpret_cast<unsigned char>(rdx)) {
        rbx5 = 0;
    }
    if (rbx5) {
        do {
            rax6 = *reinterpret_cast<void***>(rdi3);
            if (rax6) {
                rax6();
            }
            ++rsi4;
            rdi3 = rdi3 + 8;
        } while (rsi4 < rbx5);
    }
    return;
}

int32_t fun_180005554(int64_t* rcx, int64_t* rdx) {
    int32_t eax3;
    int64_t* rdi4;
    int64_t* rbx5;
    int64_t rcx6;

    eax3 = 0;
    rdi4 = rdx;
    rbx5 = rcx;
    if (reinterpret_cast<uint64_t>(rcx) < reinterpret_cast<uint64_t>(rdx)) {
        do {
            if (eax3) 
                break;
            rcx6 = *rbx5;
            if (rcx6) {
                eax3 = reinterpret_cast<int32_t>(rcx6());
            }
            ++rbx5;
        } while (reinterpret_cast<uint64_t>(rbx5) < reinterpret_cast<uint64_t>(rdi4));
    }
    return eax3;
}

uint32_t fun_18000e736();

uint32_t fun_180009320(void* rcx, int64_t rdx) {
    uint32_t eax3;

    eax3 = fun_18000e736();
    return eax3;
}

uint64_t g18001f000;

int64_t InitializeCriticalSectionAndSpinCount = 0x16656;

int64_t fun_180006234(void** rcx, void** rdx) {
    uint64_t rax3;
    uint64_t rax4;

    rax3 = g18001f000;
    rax4 = rax3 ^ g1800170a0;
    if (!rax4) {
        InitializeCriticalSectionAndSpinCount();
        return 1;
    } else {
        goto rax4;
    }
}

int64_t fun_180007f54(void** ecx, void** rdx);

uint32_t fun_180007b7c() {
    int1_t zf1;
    void** rdx2;

    zf1 = g18001f108 == 0;
    if (zf1) {
        fun_180007f54(0xfffffffd, rdx2);
        g18001f108 = 1;
    }
    return 0;
}

uint32_t fun_180009400(uint32_t ecx);

uint32_t fun_180005c04(void*** rcx, void** rdx, void** r8, int32_t* r9) {
    uint32_t* r14_5;
    uint32_t* v6;
    int32_t* r12_7;
    void** rdi8;
    void** r15_9;
    void*** rbx10;
    uint32_t ebp11;
    uint32_t esi12;
    void*** rax13;
    uint32_t esi14;
    int32_t edx15;
    uint32_t ecx16;

    r14_5 = v6;
    r12_7 = r9;
    rdi8 = r8;
    *r14_5 = 0;
    r15_9 = rdx;
    rbx10 = rcx;
    *r9 = 1;
    if (rdx) {
        *reinterpret_cast<void***>(rdx) = r8;
        r15_9 = r15_9 + 8;
    }
    ebp11 = 0;
    do {
        if (!reinterpret_cast<int1_t>(*rbx10 == 34)) {
            *r14_5 = *r14_5 + 1;
            if (rdi8) {
                *reinterpret_cast<void***>(rdi8) = *rbx10;
                ++rdi8;
            }
            esi12 = reinterpret_cast<unsigned char>(*rbx10);
            ++rbx10;
            *reinterpret_cast<uint32_t*>(&rax13) = fun_180009400(esi12);
            if (*reinterpret_cast<uint32_t*>(&rax13)) {
                *r14_5 = *r14_5 + 1;
                if (rdi8) {
                    *reinterpret_cast<void***>(&rax13) = *rbx10;
                    *reinterpret_cast<void***>(rdi8) = *reinterpret_cast<void***>(&rax13);
                    ++rdi8;
                }
                ++rbx10;
            }
            if (!*reinterpret_cast<signed char*>(&esi12)) 
                break;
        } else {
            *reinterpret_cast<uint32_t*>(&rax13) = 0;
            *reinterpret_cast<signed char*>(&esi12) = 34;
            *reinterpret_cast<void***>(&rax13) = reinterpret_cast<void**>(static_cast<unsigned char>(reinterpret_cast<uint1_t>(ebp11 == 0)));
            ++rbx10;
            ebp11 = *reinterpret_cast<uint32_t*>(&rax13);
        }
    } while (ebp11 || *reinterpret_cast<signed char*>(&esi12) != 32 && *reinterpret_cast<signed char*>(&esi12) != 9);
    goto addr_180005ca8_14;
    --rbx10;
    addr_180005cb6_16:
    esi14 = 0;
    while (*rbx10) {
        while (*rbx10 == 32 || reinterpret_cast<int1_t>(*rbx10 == 9)) {
            ++rbx10;
        }
        if (!*rbx10) 
            break;
        if (r15_9) {
            *reinterpret_cast<void***>(r15_9) = rdi8;
            r15_9 = r15_9 + 8;
        }
        *r12_7 = *r12_7 + 1;
        while (1) {
            edx15 = 1;
            ecx16 = 0;
            while (*rbx10 == 92) {
                ++rbx10;
                ++ecx16;
            }
            if (reinterpret_cast<int1_t>(*rbx10 == 34)) {
                if (!(1 & *reinterpret_cast<unsigned char*>(&ecx16))) {
                    if (!esi14 || (rax13 = rbx10 + 1, !reinterpret_cast<int1_t>(*rax13 == 34))) {
                        *reinterpret_cast<uint32_t*>(&rax13) = 0;
                        edx15 = 0;
                        *reinterpret_cast<void***>(&rax13) = reinterpret_cast<void**>(static_cast<unsigned char>(reinterpret_cast<uint1_t>(esi14 == 0)));
                        esi14 = *reinterpret_cast<uint32_t*>(&rax13);
                    } else {
                        rbx10 = rax13;
                    }
                }
                ecx16 = ecx16 >> 1;
            }
            while (ecx16) {
                --ecx16;
                if (rdi8) {
                    *reinterpret_cast<void***>(rdi8) = reinterpret_cast<void**>(92);
                    ++rdi8;
                }
                *r14_5 = *r14_5 + 1;
            }
            *reinterpret_cast<void***>(&rax13) = *rbx10;
            if (!*reinterpret_cast<void***>(&rax13)) 
                break;
            if (esi14) 
                goto addr_180005d4c_39;
            if (*reinterpret_cast<void***>(&rax13) == 32) 
                break;
            if (*reinterpret_cast<void***>(&rax13) == 9) 
                break;
            addr_180005d4c_39:
            if (edx15) {
                *reinterpret_cast<uint32_t*>(&rax13) = fun_180009400(static_cast<int32_t>(reinterpret_cast<signed char>(*reinterpret_cast<void***>(&rax13))));
                if (!rdi8) {
                    if (*reinterpret_cast<uint32_t*>(&rax13)) {
                        ++rbx10;
                        *r14_5 = *r14_5 + 1;
                    }
                } else {
                    if (*reinterpret_cast<uint32_t*>(&rax13)) {
                        ++rbx10;
                        *reinterpret_cast<void***>(rdi8) = *rbx10;
                        ++rdi8;
                        *r14_5 = *r14_5 + 1;
                    }
                    *reinterpret_cast<void***>(rdi8) = *rbx10;
                    ++rdi8;
                }
                *r14_5 = *r14_5 + 1;
            }
            ++rbx10;
        }
        if (rdi8) {
            *reinterpret_cast<void***>(rdi8) = reinterpret_cast<void**>(0);
            ++rdi8;
        }
        *r14_5 = *r14_5 + 1;
    }
    if (r15_9) {
        *reinterpret_cast<void***>(r15_9) = reinterpret_cast<void**>(0);
    }
    *r12_7 = *r12_7 + 1;
    return *reinterpret_cast<uint32_t*>(&rax13);
    addr_180005ca8_14:
    if (rdi8) {
        *reinterpret_cast<void***>(rdi8 + 0xffffffffffffffff) = reinterpret_cast<void**>(0);
        goto addr_180005cb6_16;
    }
}

struct s12 {
    void** f0;
    signed char[7] pad8;
    void** f8;
    signed char[7] pad16;
    void** f16;
    signed char[7] pad24;
    signed char f24;
};

struct s12* fun_180003bc4(struct s12* rcx, void** rdx);

struct s13 {
    signed char[200] pad200;
    uint32_t f200;
};

uint32_t fun_180009400(uint32_t ecx) {
    uint32_t ebx2;
    int64_t rdx3;
    int64_t v4;
    uint32_t eax5;
    signed char v6;
    struct s13* v7;

    ebx2 = ecx;
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 + 32, 0);
    *reinterpret_cast<uint32_t*>(&rdx3) = *reinterpret_cast<unsigned char*>(&ebx2);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx3) + 4) = 0;
    if (*reinterpret_cast<unsigned char*>(rdx3 + v4 + 25) & 4) {
        addr_1800093d5_3:
        eax5 = 1;
    } else {
        if (1) {
            eax5 = 0;
        } else {
            eax5 = 0;
        }
        if (!1) 
            goto addr_1800093d5_3;
    }
    if (v6) {
        v7->f200 = v7->f200 & 0xfffffffd;
    }
    return eax5;
}

void** fun_180002c40(void** rcx, void* rdx, void** r8, void** r9) {
    void** rax5;
    void** ebx6;
    void* r9_7;
    void** al8;
    void** eax9;

    if (!rcx || !rdx) {
        addr_180002c58_2:
        rax5 = fun_1800039c8();
        ebx6 = reinterpret_cast<void**>(22);
    } else {
        if (r8) {
            r9_7 = reinterpret_cast<void*>(reinterpret_cast<unsigned char>(rcx) - reinterpret_cast<unsigned char>(r8));
            do {
                al8 = *reinterpret_cast<void***>(r8);
                *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(r9_7) + reinterpret_cast<unsigned char>(r8)) = al8;
                ++r8;
                if (!al8) 
                    break;
                rdx = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx) - 1);
            } while (rdx);
            if (rdx) 
                goto addr_180002c9d_8; else 
                goto addr_180002c8f_9;
        } else {
            *reinterpret_cast<void***>(rcx) = r8;
            goto addr_180002c58_2;
        }
    }
    addr_180002c62_11:
    *reinterpret_cast<void***>(rax5) = ebx6;
    fun_1800038fc();
    eax9 = ebx6;
    addr_180002c6b_12:
    return eax9;
    addr_180002c9d_8:
    eax9 = reinterpret_cast<void**>(0);
    goto addr_180002c6b_12;
    addr_180002c8f_9:
    *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(&rdx);
    rax5 = fun_1800039c8();
    ebx6 = reinterpret_cast<void**>(34);
    goto addr_180002c62_11;
}

int64_t GetEnvironmentStringsW = 0x165a6;

int64_t WideCharToMultiByte = 0x16366;

int64_t FreeEnvironmentStringsW = 0x165c0;

void** fun_180005fec() {
    int16_t* rax1;
    int16_t* rdi2;
    void** rax3;
    int16_t* rbx4;
    int32_t eax5;
    void** rcx6;
    void** rax7;
    void** rsi8;
    int32_t eax9;

    rax1 = reinterpret_cast<int16_t*>(GetEnvironmentStringsW());
    rdi2 = rax1;
    if (!rax1) {
        addr_1800060c3_2:
        *reinterpret_cast<int32_t*>(&rax3) = 0;
        *reinterpret_cast<int32_t*>(&rax3 + 4) = 0;
    } else {
        rbx4 = rax1;
        if (*rax1) {
            addr_180006023_4:
            ++rbx4;
            if (*rbx4) 
                goto addr_180006023_4;
            ++rbx4;
            if (*rbx4) 
                goto addr_180006023_4;
        }
        eax5 = reinterpret_cast<int32_t>(WideCharToMultiByte());
        if (!eax5) 
            goto addr_1800060ba_7;
        rcx6 = reinterpret_cast<void**>(static_cast<int64_t>(eax5));
        rax7 = fun_180006770(rcx6, 0, rcx6, 0);
        rsi8 = rax7;
        if (!rax7) 
            goto addr_1800060ba_7; else 
            goto addr_180006079_9;
    }
    addr_1800060c5_10:
    return rax3;
    addr_1800060ba_7:
    FreeEnvironmentStringsW(rdi2);
    goto addr_1800060c3_2;
    addr_180006079_9:
    eax9 = reinterpret_cast<int32_t>(WideCharToMultiByte());
    if (!eax9) {
        fun_180005f00(rsi8, rsi8);
        rsi8 = reinterpret_cast<void**>(0);
    }
    FreeEnvironmentStringsW(rdi2);
    rax3 = rsi8;
    goto addr_1800060c5_10;
}

int64_t Sleep = 0x1667e;

void fun_1800066a8(int64_t rcx, void** rdx) {
    goto Sleep;
}

int32_t g18001dfa8;

void** g18001dfa0;

uint32_t fun_18000ae38(void** rcx, void** rdx, void** r8);

int64_t fun_18000963c() {
    int64_t rdi1;
    void** rdx2;
    void** r8_3;
    int32_t ebx4;
    int1_t less5;
    int64_t rsi6;
    void** rax7;
    void** rcx8;
    void** rdx9;
    void** r8_10;
    uint32_t eax11;
    void** rcx12;
    void** rcx13;
    void** rax14;
    int64_t rax15;

    *reinterpret_cast<int32_t*>(&rdi1) = 0;
    fun_1800088e8(1, rdx2, r8_3);
    ebx4 = 3;
    while (less5 = ebx4 < g18001dfa8, less5) {
        rsi6 = ebx4;
        rax7 = g18001dfa0;
        rcx8 = *reinterpret_cast<void***>(rax7 + rsi6 * 8);
        if (rcx8) {
            if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx8 + 24)) & 0x83 && (eax11 = fun_18000ae38(rcx8, rdx9, r8_10), eax11 != 0xffffffff)) {
                *reinterpret_cast<int32_t*>(&rdi1) = *reinterpret_cast<int32_t*>(&rdi1) + 1;
            }
            if (ebx4 >= 20) {
                DeleteCriticalSection();
                rcx12 = g18001dfa0;
                rcx13 = *reinterpret_cast<void***>(rcx12 + rsi6 * 8);
                fun_180005f00(rcx13, rcx13);
                rax14 = g18001dfa0;
                *reinterpret_cast<void***>(rax14 + rsi6 * 8) = reinterpret_cast<void**>(0);
            }
        }
        ++ebx4;
    }
    fun_180008ad8(1, 1);
    *reinterpret_cast<int32_t*>(&rax15) = *reinterpret_cast<int32_t*>(&rdi1);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax15) + 4) = 0;
    return rax15;
}

void** fun_180003958() {
    void** rax1;
    void** rax2;

    rax1 = fun_18000503c();
    if (rax1) {
        rax2 = rax1 + 20;
    } else {
        rax2 = reinterpret_cast<void**>(0x18001721c);
    }
    return rax2;
}

int64_t fun_1800098a0(void** ecx, void** rdx, void** r8) {
    int64_t rax4;
    int64_t rax5;
    void* rbx6;
    void* rdi7;

    rax4 = reinterpret_cast<int32_t>(ecx);
    *reinterpret_cast<uint32_t*>(&rax5) = *reinterpret_cast<uint32_t*>(&rax4) & 31;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax5) + 4) = 0;
    rbx6 = reinterpret_cast<void*>(rax5 * 88);
    rdi7 = *reinterpret_cast<void**>(0x18001d350 + (rax4 >> 5) * 8);
    if (!*reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbx6) + reinterpret_cast<uint64_t>(rdi7) + 12)) {
        fun_1800088e8(10, rdx, r8);
        if (!*reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbx6) + reinterpret_cast<uint64_t>(rdi7) + 12)) {
            fun_180006234(reinterpret_cast<int64_t>(rbx6) + 16 + reinterpret_cast<uint64_t>(rdi7), 0xfa0);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbx6) + reinterpret_cast<uint64_t>(rdi7) + 12) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbx6) + reinterpret_cast<uint64_t>(rdi7) + 12) + 1;
        }
        fun_180008ad8(10, 10);
    }
    EnterCriticalSection();
    return 1;
}

uint64_t fun_180009af0();

struct s14 {
    signed char[32] pad32;
    void** f32;
    signed char[7] pad40;
    int32_t f40;
    signed char[4] pad48;
    int64_t f48;
    int64_t f56;
    void** f64;
    signed char[3] pad68;
    void* f68;
    signed char[2] pad72;
    int64_t f72;
    void** f80;
    signed char[7] pad88;
    void* f88;
    void** f96;
    signed char[3] pad100;
    void** f100;
    signed char[3] pad104;
    int32_t f104;
    void** f108;
    void** f109;
};

void** fun_180003978(void** ecx, void** rdx, void** r8, void*** r9);

int64_t GetConsoleMode = 0x16742;

int64_t GetConsoleCP = 0x16732;

uint32_t fun_18000848c(int32_t ecx);

uint32_t fun_1800088e0(void** rcx, void** rdx, void** r8, void*** r9);

void* fun_180009a84(void* cx, void** rdx, void** r8, void*** r9);

void** fun_180006e14(void** ecx, void** rdx, void** r8d) {
    void** r8_3;
    void* rsp4;
    void* rbp5;
    uint64_t rax6;
    struct s14* rsp7;
    uint64_t rax8;
    uint64_t v9;
    int64_t r12_10;
    int64_t r15_11;
    void** r14_12;
    int64_t rdi13;
    void** ebx14;
    void** esi15;
    int64_t rax16;
    int64_t rcx17;
    int64_t rax18;
    void* rcx19;
    void* r13_20;
    signed char r12b21;
    int32_t eax22;
    int32_t eax23;
    int64_t* rsp24;
    int64_t* rsp25;
    uint32_t eax26;
    int64_t rdi27;
    int64_t* rsp28;
    void** rax29;
    struct s14* rsp30;
    int64_t* rsp31;
    void** rax32;
    void** rcx33;
    void*** r9_34;
    void** rdx35;
    int64_t* rsp36;
    int32_t eax37;
    int64_t* rsp38;
    void** eax39;
    void** r12_40;
    void* rcx41;
    void** rdx42;
    uint32_t eax43;
    void* rax44;
    int64_t rdi45;
    int64_t rcx46;
    int64_t* rsp47;
    void* eax48;
    void* r13d49;
    void* rcx50;
    int64_t rcx51;
    int64_t* rsp52;
    int32_t eax53;
    int64_t* rsp54;
    void** eax55;
    void** r13d56;
    void* rdi57;
    void** rcx58;
    uint32_t eax59;
    void* rax60;
    int64_t rcx61;
    int64_t* rsp62;
    int32_t eax63;
    void** r12_64;
    void** r13d65;
    void* rdi66;
    void** rcx67;
    void* rax68;
    int64_t* rsp69;
    int32_t eax70;
    int64_t* rsp71;
    void** rax72;
    int64_t* rsp73;
    void** rax74;
    int64_t* rsp75;
    int64_t* rsp76;
    void** rax77;
    int64_t* rsp78;
    uint64_t rcx79;
    int64_t* rsp80;
    int64_t* rsp81;
    void** eax82;
    int64_t* rsp83;
    void** eax84;
    int64_t* rsp85;
    void** rax86;
    struct s14* rsp87;
    int32_t edi88;
    int64_t rcx89;
    int64_t* rsp90;
    int32_t eax91;
    int64_t* rsp92;
    int32_t eax93;
    void** rdi94;
    void** eax95;
    void** r13d96;
    int32_t eax97;
    int32_t eax98;
    void** cl99;
    int64_t* rsp100;
    uint32_t eax101;
    int64_t* rsp102;
    uint32_t eax103;
    void** al104;
    int64_t* rsp105;
    void* ax106;
    int64_t* rsp107;
    void* ax108;
    int64_t* rsp109;
    uint32_t eax110;
    int64_t rcx111;
    int64_t* rsp112;
    void** eax113;
    void* rcx114;
    int64_t* rsp115;
    int32_t eax116;
    int64_t rax117;
    int64_t* rsp118;
    int32_t eax119;
    int64_t r15_120;
    int64_t* rsp121;
    void** rax122;
    int64_t* rsp123;

    *reinterpret_cast<void***>(&r8_3) = r8d;
    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 8 - 8);
    rbp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp4) - 0x1a40);
    rax6 = fun_180009af0();
    rsp7 = reinterpret_cast<struct s14*>(reinterpret_cast<int64_t>(rsp4) - 8 + 8 - rax6);
    rax8 = g1800170a0;
    v9 = rax8 ^ reinterpret_cast<uint64_t>(rsp7);
    *reinterpret_cast<void***>(&r12_10) = reinterpret_cast<void**>(0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_10) + 4) = 0;
    *reinterpret_cast<void***>(&r15_11) = *reinterpret_cast<void***>(&r8_3);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r15_11) + 4) = 0;
    r14_12 = rdx;
    rdi13 = reinterpret_cast<int32_t>(ecx);
    rsp7->f64 = reinterpret_cast<void**>(0);
    ebx14 = reinterpret_cast<void**>(0);
    esi15 = reinterpret_cast<void**>(0);
    if (!*reinterpret_cast<void***>(&r8_3)) 
        goto addr_180006e66_2;
    if (rdx) {
        rax16 = rdi13;
        rcx17 = rdi13 >> 5;
        *reinterpret_cast<uint32_t*>(&rax18) = *reinterpret_cast<uint32_t*>(&rax16) & 31;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax18) + 4) = 0;
        rsp7->f72 = rcx17;
        rcx19 = *reinterpret_cast<void**>(0x18001d350 + rcx17 * 8);
        r13_20 = reinterpret_cast<void*>(rax18 * 88);
        r12b21 = *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(rcx19) + 56);
        rsp7->f88 = r13_20;
        *reinterpret_cast<signed char*>(&r12_10) = reinterpret_cast<signed char>(reinterpret_cast<signed char>(r12b21 + r12b21) >> 1);
        eax22 = static_cast<int32_t>(r12_10 - 1);
        if (*reinterpret_cast<unsigned char*>(&eax22) > 1 || (eax23 = reinterpret_cast<int32_t>(~reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))), !!(*reinterpret_cast<unsigned char*>(&eax23) & 1))) {
            if (*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(rcx19) + 8) & 32) {
                *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(2);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                rsp24 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp24 = 0x180006ef5;
                fun_1800076f0(*reinterpret_cast<void***>(&rdi13), 0, 2);
                rsp7 = reinterpret_cast<struct s14*>(rsp24 + 1);
            }
            rsp25 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
            *rsp25 = 0x180006efc;
            eax26 = fun_180006cd0(*reinterpret_cast<void***>(&rdi13));
            rsp7 = reinterpret_cast<struct s14*>(rsp25 + 1);
            rdi27 = rsp7->f72;
            if (!eax26) 
                goto addr_180007249_8;
            if (*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi27 * 8)) + 8) & 0x80) 
                goto addr_180006f20_10;
        } else {
            rsp28 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
            *rsp28 = 0x180006eda;
            rax29 = fun_180003958();
            rsp30 = reinterpret_cast<struct s14*>(rsp28 + 1);
            *reinterpret_cast<void***>(rax29) = reinterpret_cast<void**>(0);
            goto addr_180006e7a_12;
        }
    } else {
        rsp31 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
        *rsp31 = 0x180006e77;
        rax32 = fun_180003958();
        rsp30 = reinterpret_cast<struct s14*>(rsp31 + 1);
        *reinterpret_cast<void***>(rax32) = reinterpret_cast<void**>(0);
        goto addr_180006e7a_12;
    }
    addr_180007249_8:
    addr_18000724b_14:
    if (!(*reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(0x18001d350 + rdi27 * 8))) + 8) & 0x80)) {
        rcx33 = *reinterpret_cast<void***>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(0x18001d350 + rdi27 * 8)));
        r9_34 = &rsp7->f80;
        *reinterpret_cast<void***>(&r8_3) = *reinterpret_cast<void***>(&r15_11);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
        rdx35 = r14_12;
        rsp7->f32 = reinterpret_cast<void**>(0);
        rsp36 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
        *rsp36 = 0x180007565;
        eax37 = reinterpret_cast<int32_t>(WriteFile(rcx33, rdx35, r8_3, r9_34));
        rsp7 = reinterpret_cast<struct s14*>(rsp36 + 1);
        if (!eax37) {
            rsp38 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
            *rsp38 = 0x18000757a;
            eax39 = reinterpret_cast<void**>(GetLastError(rcx33, rdx35, r8_3, r9_34));
            rsp7 = reinterpret_cast<struct s14*>(rsp38 + 1);
            esi15 = eax39;
        } else {
            ebx14 = rsp7->f80;
        }
    } else {
        esi15 = reinterpret_cast<void**>(0);
        if (*reinterpret_cast<signed char*>(&r12_10)) {
            r12_40 = r14_12;
            if (*reinterpret_cast<signed char*>(&r12_10) != 2) {
                if (!*reinterpret_cast<void***>(&r15_11)) 
                    goto addr_1800075a3_21;
                while (1) {
                    rcx41 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) - 0x80);
                    rdx42 = reinterpret_cast<void**>(0);
                    do {
                        if (reinterpret_cast<unsigned char>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&r12_40)) - *reinterpret_cast<uint32_t*>(&r14_12)) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                            break;
                        eax43 = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(r12_40));
                        r12_40 = r12_40 + 2;
                        if (*reinterpret_cast<int16_t*>(&eax43) == 10) {
                            rcx41 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rcx41) + 2);
                            rdx42 = rdx42 + 2;
                        }
                        rdx42 = rdx42 + 2;
                        rcx41 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rcx41) + 2);
                    } while (reinterpret_cast<unsigned char>(rdx42) < reinterpret_cast<unsigned char>(0x6a8));
                    rax44 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) - 0x80);
                    *reinterpret_cast<void**>(&rdi45) = reinterpret_cast<void*>(0);
                    r8_3 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0xffffffffffffff80);
                    rsp7->f56 = 0;
                    rsp7->f48 = 0;
                    *reinterpret_cast<uint32_t*>(&rcx46) = 0xfde9;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx46) + 4) = 0;
                    rsp7->f40 = 0xd55;
                    __asm__("cdq ");
                    *reinterpret_cast<int32_t*>(&rdx35) = 0;
                    *reinterpret_cast<int32_t*>(&rdx35 + 4) = 0;
                    *reinterpret_cast<int32_t*>(&r9_34) = reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rcx41)) - reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rax44)) - *reinterpret_cast<int32_t*>(&rdx42) >> 1;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_34) + 4) = 0;
                    rsp7->f32 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                    rsp47 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                    *rsp47 = 0x1800074c7;
                    eax48 = reinterpret_cast<void*>(WideCharToMultiByte(0xfde9));
                    rsp7 = reinterpret_cast<struct s14*>(rsp47 + 1);
                    r13d49 = eax48;
                    if (!eax48) 
                        goto addr_1800071f5_29;
                    do {
                        rdx35 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0x630 + reinterpret_cast<uint64_t>(static_cast<int64_t>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi45)))));
                        rcx50 = *reinterpret_cast<void**>(0x18001d350 + rsp7->f72 * 8);
                        r9_34 = &rsp7->f80;
                        rsp7->f32 = reinterpret_cast<void**>(0);
                        *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(reinterpret_cast<uint32_t>(r13d49) - reinterpret_cast<uint32_t>(*reinterpret_cast<void**>(&rdi45)));
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                        rcx51 = *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(rsp7->f88) + reinterpret_cast<int64_t>(rcx50));
                        rsp52 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                        *rsp52 = 0x180007510;
                        eax53 = reinterpret_cast<int32_t>(WriteFile(rcx51));
                        rsp7 = reinterpret_cast<struct s14*>(rsp52 + 1);
                        if (!eax53) 
                            break;
                        *reinterpret_cast<void**>(&rdi45) = reinterpret_cast<void*>(reinterpret_cast<uint32_t>(*reinterpret_cast<void**>(&rdi45)) + reinterpret_cast<unsigned char>(rsp7->f80));
                    } while (reinterpret_cast<int32_t>(r13d49) > reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi45)));
                    goto addr_18000751d_32;
                    rsp54 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                    *rsp54 = 0x180007525;
                    eax55 = reinterpret_cast<void**>(GetLastError(rcx51));
                    rsp7 = reinterpret_cast<struct s14*>(rsp54 + 1);
                    esi15 = eax55;
                    addr_180007527_34:
                    if (reinterpret_cast<int32_t>(r13d49) > reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi45))) 
                        goto addr_1800071fd_35;
                    *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(13);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                    ebx14 = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&r12_40)) - *reinterpret_cast<uint32_t*>(&r14_12));
                    if (reinterpret_cast<unsigned char>(ebx14) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                        goto addr_180007545_37;
                    continue;
                    addr_18000751d_32:
                    goto addr_180007527_34;
                }
            } else {
                if (!*reinterpret_cast<void***>(&r15_11)) 
                    goto addr_1800075a3_21;
                while (1) {
                    r13d56 = rsp7->f64;
                    rdi57 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                    rcx58 = reinterpret_cast<void**>(0);
                    do {
                        if (reinterpret_cast<unsigned char>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&r12_40)) - *reinterpret_cast<uint32_t*>(&r14_12)) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                            break;
                        eax59 = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(r12_40));
                        r12_40 = r12_40 + 2;
                        if (*reinterpret_cast<int16_t*>(&eax59) == 10) {
                            r13d56 = r13d56 + 2;
                            rdi57 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rdi57) + 2);
                            rcx58 = rcx58 + 2;
                        }
                        rcx58 = rcx58 + 2;
                        rdi57 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rdi57) + 2);
                    } while (reinterpret_cast<unsigned char>(rcx58) < reinterpret_cast<unsigned char>(0x13fe));
                    rax60 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                    rsp7->f64 = r13d56;
                    r13_20 = rsp7->f88;
                    *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi57)) - reinterpret_cast<uint32_t>(*reinterpret_cast<void**>(&rax60)));
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                    r9_34 = &rsp7->f80;
                    rcx61 = *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(0x18001d350 + rsp7->f72 * 8)));
                    rdx35 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                    rsp7->f32 = reinterpret_cast<void**>(0);
                    rsp62 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                    *rsp62 = 0x1800073ee;
                    eax63 = reinterpret_cast<int32_t>(WriteFile(rcx61, rdx35));
                    rsp7 = reinterpret_cast<struct s14*>(rsp62 + 1);
                    if (!eax63) 
                        goto addr_1800071eb_47;
                    ebx14 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(ebx14) + reinterpret_cast<unsigned char>(rsp7->f80));
                    if (static_cast<int64_t>(reinterpret_cast<int32_t>(rsp7->f80)) < reinterpret_cast<int64_t>(rdi57) - (reinterpret_cast<int64_t>(rbp5) + 0x630)) 
                        goto addr_180007202_49;
                    *reinterpret_cast<int32_t*>(&rdx35) = 13;
                    *reinterpret_cast<int32_t*>(&rdx35 + 4) = 0;
                    r9_34 = reinterpret_cast<void***>(0x18001d350);
                    if (reinterpret_cast<unsigned char>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&r12_40)) - *reinterpret_cast<uint32_t*>(&r14_12)) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                        goto addr_18000742d_51;
                }
            }
        } else {
            r12_64 = r14_12;
            if (!*reinterpret_cast<void***>(&r15_11)) 
                goto addr_1800075a3_21;
            while (1) {
                r13d65 = rsp7->f64;
                rdi66 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                rcx67 = reinterpret_cast<void**>(0);
                do {
                    if (reinterpret_cast<unsigned char>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&r12_64)) - *reinterpret_cast<uint32_t*>(&r14_12)) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                        break;
                    ++r12_64;
                    if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(r12_64) == 10)) {
                        ++r13d65;
                        rdi66 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rdi66) + 1);
                        ++rcx67;
                    }
                    ++rcx67;
                    rdi66 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rdi66) + 1);
                } while (reinterpret_cast<unsigned char>(rcx67) < reinterpret_cast<unsigned char>(0x13ff));
                rax68 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                rsp7->f64 = r13d65;
                r13_20 = rsp7->f88;
                *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi66)) - reinterpret_cast<uint32_t>(*reinterpret_cast<void**>(&rax68)));
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                r9_34 = &rsp7->f80;
                rcx61 = *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(0x18001d350 + rsp7->f72 * 8)));
                rdx35 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0x630);
                rsp7->f32 = reinterpret_cast<void**>(0);
                rsp69 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp69 = 0x180007301;
                eax70 = reinterpret_cast<int32_t>(WriteFile(rcx61, rdx35));
                rsp7 = reinterpret_cast<struct s14*>(rsp69 + 1);
                if (!eax70) 
                    goto addr_1800071eb_47;
                ebx14 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(ebx14) + reinterpret_cast<unsigned char>(rsp7->f80));
                if (static_cast<int64_t>(reinterpret_cast<int32_t>(rsp7->f80)) < reinterpret_cast<int64_t>(rdi66) - (reinterpret_cast<int64_t>(rbp5) + 0x630)) 
                    goto addr_180007202_49;
                *reinterpret_cast<int32_t*>(&rdx35) = 13;
                *reinterpret_cast<int32_t*>(&rdx35 + 4) = 0;
                r9_34 = reinterpret_cast<void***>(0x18001d350);
                if (reinterpret_cast<unsigned char>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&r12_64)) - *reinterpret_cast<uint32_t*>(&r14_12)) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                    goto addr_180007340_63;
            }
        }
    }
    addr_18000720b_65:
    if (!ebx14) {
        if (!esi15) {
            addr_1800075a3_21:
            if (!(*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi27 * 8)) + 8) & 64) || *reinterpret_cast<void***>(r14_12) != 26) {
                rsp71 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp71 = 0x1800075c5;
                rax72 = fun_1800039c8();
                *reinterpret_cast<void***>(rax72) = reinterpret_cast<void**>(28);
                rsp73 = rsp71 + 1 - 1;
                *rsp73 = 0x1800075d0;
                rax74 = fun_180003958();
                rsp7 = reinterpret_cast<struct s14*>(rsp73 + 1);
                *reinterpret_cast<void***>(rax74) = reinterpret_cast<void**>(0);
                goto addr_180006e8a_69;
            } else {
                addr_180006e66_2:
            }
        } else {
            if (!reinterpret_cast<int1_t>(esi15 == 5)) {
                rsp75 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp75 = 0x180007599;
                fun_180003978(esi15, rdx35, r8_3, r9_34);
                rsp7 = reinterpret_cast<struct s14*>(rsp75 + 1);
                goto addr_180006e8a_69;
            } else {
                rsp76 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp76 = 0x18000722b;
                rax77 = fun_1800039c8();
                *reinterpret_cast<void***>(rax77) = reinterpret_cast<void**>(9);
                rsp78 = rsp76 + 1 - 1;
                *rsp78 = 0x180007236;
                rax74 = fun_180003958();
                rsp7 = reinterpret_cast<struct s14*>(rsp78 + 1);
                *reinterpret_cast<void***>(rax74) = esi15;
                goto addr_180006e8a_69;
            }
        }
    }
    addr_1800075db_73:
    rcx79 = v9 ^ reinterpret_cast<uint64_t>(rsp7);
    rsp80 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
    *rsp80 = 0x1800075ea;
    fun_180002f40(rcx79, rcx79);
    goto (rsp80 + 1 + 0x368 + 1 + 1 + 1 + 1 + 1 + 1)[1];
    addr_180006e8a_69:
    goto addr_1800075db_73;
    addr_1800071f5_29:
    rsp81 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
    *rsp81 = 0x1800071fb;
    eax82 = reinterpret_cast<void**>(GetLastError(rcx46, rdx35, r8_3, r9_34));
    rsp7 = reinterpret_cast<struct s14*>(rsp81 + 1);
    esi15 = eax82;
    addr_1800071fd_35:
    r13_20 = rsp7->f88;
    addr_180007202_49:
    rdi27 = rsp7->f72;
    addr_180007207_74:
    goto addr_18000720b_65;
    addr_180007545_37:
    goto addr_1800071fd_35;
    addr_1800071eb_47:
    rsp83 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
    *rsp83 = 0x1800071f1;
    eax84 = reinterpret_cast<void**>(GetLastError(rcx61, rdx35, r8_3, r9_34));
    rsp7 = reinterpret_cast<struct s14*>(rsp83 + 1);
    esi15 = eax84;
    goto addr_180007202_49;
    addr_18000742d_51:
    goto addr_180007202_49;
    addr_180007340_63:
    goto addr_180007202_49;
    addr_180006f20_10:
    rsp85 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
    *rsp85 = 0x180006f25;
    rax86 = fun_180005018();
    rsp87 = reinterpret_cast<struct s14*>(rsp85 + 1);
    rdx35 = reinterpret_cast<void**>(&rsp87->f100);
    edi88 = 0;
    *reinterpret_cast<unsigned char*>(&edi88) = reinterpret_cast<uint1_t>(*reinterpret_cast<void***>(*reinterpret_cast<void***>(rax86 + 0xc0) + 0x138) == 0);
    rcx89 = *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(*reinterpret_cast<int64_t**>(0x18001d350 + rsp87->f72 * 8)));
    rsp90 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp87) - 8);
    *rsp90 = 0x180006f5b;
    eax91 = reinterpret_cast<int32_t>(GetConsoleMode(rcx89, rdx35, r8_3));
    rsp7 = reinterpret_cast<struct s14*>(rsp90 + 1);
    if (!eax91) {
        rdi27 = rsp7->f72;
        goto addr_180007249_8;
    } else {
        if (!edi88 || *reinterpret_cast<signed char*>(&r12_10)) {
            rsp92 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
            *rsp92 = 0x180006f7a;
            eax93 = reinterpret_cast<int32_t>(GetConsoleCP());
            rsp7 = reinterpret_cast<struct s14*>(rsp92 + 1);
            rdi94 = r14_12;
            rsp7->f104 = eax93;
            eax95 = reinterpret_cast<void**>(0);
            *reinterpret_cast<uint32_t*>(&rcx46) = 0;
            rsp7->f68 = reinterpret_cast<void*>(0);
            rsp7->f96 = reinterpret_cast<void**>(0);
            if (!*reinterpret_cast<void***>(&r15_11)) {
                rdi27 = rsp7->f72;
                goto addr_1800075a3_21;
            }
            while (1) {
                r13d96 = reinterpret_cast<void**>(0);
                if (*reinterpret_cast<signed char*>(&r12_10)) {
                    eax97 = static_cast<int32_t>(r12_10 - 1);
                    if (*reinterpret_cast<unsigned char*>(&eax97) <= 1) {
                        *reinterpret_cast<uint32_t*>(&rcx46) = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(rdi94));
                        r13d96 = reinterpret_cast<void**>(0);
                        rsp7->f68 = *reinterpret_cast<void**>(&rcx46);
                        *reinterpret_cast<unsigned char*>(&r13d96) = reinterpret_cast<uint1_t>(*reinterpret_cast<void**>(&rcx46) == 10);
                        rdi94 = rdi94 + 2;
                    }
                    eax98 = static_cast<int32_t>(r12_10 - 1);
                    if (*reinterpret_cast<unsigned char*>(&eax98) <= 1) 
                        goto addr_180007172_83;
                } else {
                    cl99 = *reinterpret_cast<void***>(rdi94);
                    r13_20 = rsp7->f88;
                    *reinterpret_cast<unsigned char*>(&eax95) = reinterpret_cast<uint1_t>(cl99 == 10);
                    *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(0);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                    *reinterpret_cast<void***>(&rsp7->f100) = eax95;
                    rdx35 = *reinterpret_cast<void***>(0x18001d350 + rsp7->f72 * 8);
                    if (!*reinterpret_cast<void***>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(rdx35)) + 80)) {
                        rsp100 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                        *rsp100 = 0x180006ff6;
                        eax101 = fun_18000848c(static_cast<int32_t>(reinterpret_cast<signed char>(cl99)));
                        rsp7 = reinterpret_cast<struct s14*>(rsp100 + 1);
                        if (!eax101) {
                            *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(1);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                            rdx35 = rdi94;
                            goto addr_180007037_87;
                        } else {
                            if (reinterpret_cast<int64_t>(reinterpret_cast<uint64_t>(r15_11 - reinterpret_cast<unsigned char>(rdi94)) + reinterpret_cast<unsigned char>(r14_12)) <= reinterpret_cast<int64_t>(1)) 
                                goto addr_1800071c0_89;
                            *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(2);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                            rdx35 = rdi94;
                            rsp102 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                            *rsp102 = 0x180007020;
                            eax103 = fun_1800088e0(&rsp7->f68, rdx35, 2, r9_34);
                            rsp7 = reinterpret_cast<struct s14*>(rsp102 + 1);
                            if (eax103 == 0xffffffff) 
                                goto addr_180007202_49;
                            ++rdi94;
                            goto addr_18000704a_92;
                        }
                    } else {
                        al104 = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(rdx35)) + 76);
                        rsp7->f109 = cl99;
                        *reinterpret_cast<void***>(&rsp7->f108) = al104;
                        *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<unsigned char>(rdx35)) + 80) = reinterpret_cast<void**>(0);
                        *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(2);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                        rdx35 = reinterpret_cast<void**>(&rsp7->f108);
                        goto addr_180007037_87;
                    }
                }
                addr_1800071aa_94:
                r13_20 = rsp7->f88;
                addr_1800071af_95:
                if (reinterpret_cast<unsigned char>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi94)) - *reinterpret_cast<uint32_t*>(&r14_12)) >= reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r15_11))) 
                    goto addr_180007202_49;
                eax95 = reinterpret_cast<void**>(0);
                continue;
                addr_180007172_83:
                rsp105 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp105 = 0x180007177;
                ax106 = fun_180009a84(*reinterpret_cast<void**>(&rcx46), rdx35, r8_3, r9_34);
                rsp7 = reinterpret_cast<struct s14*>(rsp105 + 1);
                *reinterpret_cast<uint32_t*>(&rcx46) = reinterpret_cast<uint16_t>(rsp7->f68);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx46) + 4) = 0;
                if (ax106 != *reinterpret_cast<void**>(&rcx46)) 
                    goto addr_1800071f5_29;
                ebx14 = ebx14 + 2;
                if (!r13d96) 
                    goto addr_1800071aa_94;
                rsp7->f68 = reinterpret_cast<void*>(13);
                rsp107 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp107 = 0x18000719a;
                ax108 = fun_180009a84(13, rdx35, r8_3, r9_34);
                rsp7 = reinterpret_cast<struct s14*>(rsp107 + 1);
                *reinterpret_cast<uint32_t*>(&rcx46) = reinterpret_cast<uint16_t>(rsp7->f68);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx46) + 4) = 0;
                if (ax108 != *reinterpret_cast<void**>(&rcx46)) 
                    goto addr_1800071f5_29;
                ++ebx14;
                rsp7->f64 = rsp7->f64 + 1;
                goto addr_1800071aa_94;
                addr_180007037_87:
                rsp109 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp109 = 0x180007041;
                eax110 = fun_1800088e0(&rsp7->f68, rdx35, r8_3, r9_34);
                rsp7 = reinterpret_cast<struct s14*>(rsp109 + 1);
                if (eax110 == 0xffffffff) 
                    goto addr_180007202_49;
                addr_18000704a_92:
                *reinterpret_cast<int32_t*>(&rcx111) = rsp7->f104;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx111) + 4) = 0;
                r8_3 = &rsp7->f68;
                rsp7->f56 = 0;
                rsp7->f48 = 0;
                *reinterpret_cast<int32_t*>(&r9_34) = 1;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_34) + 4) = 0;
                *reinterpret_cast<int32_t*>(&rdx35) = 0;
                *reinterpret_cast<int32_t*>(&rdx35 + 4) = 0;
                rsp7->f40 = 5;
                rsp7->f32 = reinterpret_cast<void**>(&rsp7->f108);
                ++rdi94;
                rsp112 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp112 = 0x180007082;
                eax113 = reinterpret_cast<void**>(WideCharToMultiByte(rcx111));
                rsp7 = reinterpret_cast<struct s14*>(rsp112 + 1);
                if (!eax113) 
                    goto addr_1800071fd_35;
                r9_34 = &rsp7->f96;
                rcx114 = *reinterpret_cast<void**>(0x18001d350 + rsp7->f72 * 8);
                rdx35 = reinterpret_cast<void**>(&rsp7->f108);
                rsp7->f32 = reinterpret_cast<void**>(0);
                *reinterpret_cast<void***>(&r8_3) = eax113;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                rcx46 = *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(rsp7->f88) + reinterpret_cast<int64_t>(rcx114));
                rsp115 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                *rsp115 = 0x1800070c0;
                eax116 = reinterpret_cast<int32_t>(WriteFile(rcx46, rdx35, r8_3, r9_34));
                rsp7 = reinterpret_cast<struct s14*>(rsp115 + 1);
                if (!eax116) 
                    goto addr_1800071f5_29;
                ebx14 = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rdi94)) - *reinterpret_cast<uint32_t*>(&r14_12) + reinterpret_cast<unsigned char>(rsp7->f64));
                if (reinterpret_cast<signed char>(rsp7->f96) < reinterpret_cast<signed char>(eax113)) 
                    break;
                if (!*reinterpret_cast<void***>(&rsp7->f100)) {
                    *reinterpret_cast<uint32_t*>(&rcx46) = reinterpret_cast<uint16_t>(rsp7->f68);
                    goto addr_1800071aa_94;
                } else {
                    rax117 = rsp7->f72;
                    *reinterpret_cast<void***>(&r8_3) = reinterpret_cast<void**>(1);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
                    *reinterpret_cast<void***>(&rsp7->f108) = reinterpret_cast<void**>(13);
                    rsp7->f32 = reinterpret_cast<void**>(0);
                    r13_20 = rsp7->f88;
                    r9_34 = &rsp7->f96;
                    rdx35 = reinterpret_cast<void**>(&rsp7->f108);
                    rcx61 = *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rax117 * 8)));
                    rsp118 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp7) - 8);
                    *rsp118 = 0x180007120;
                    eax119 = reinterpret_cast<int32_t>(WriteFile(rcx61, rdx35, 1, r9_34));
                    rsp7 = reinterpret_cast<struct s14*>(rsp118 + 1);
                    if (!eax119) 
                        goto addr_1800071eb_47;
                    if (reinterpret_cast<signed char>(rsp7->f96) < reinterpret_cast<signed char>(1)) 
                        goto addr_180007202_49;
                    rsp7->f64 = rsp7->f64 + 1;
                    *reinterpret_cast<uint32_t*>(&rcx46) = reinterpret_cast<uint16_t>(rsp7->f68);
                    ++ebx14;
                    goto addr_1800071af_95;
                }
            }
        } else {
            rdi27 = rsp7->f72;
            goto addr_18000724b_14;
        }
    }
    r13_20 = rsp7->f88;
    rdi27 = rsp7->f72;
    goto addr_18000720b_65;
    addr_1800071c0_89:
    r15_120 = rsp7->f72;
    ++ebx14;
    rdi27 = r15_120;
    *reinterpret_cast<void***>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + r15_120 * 8)) + 76) = *reinterpret_cast<void***>(rdi94);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(r13_20) + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + r15_120 * 8)) + 80) = 1;
    goto addr_180007207_74;
    addr_180006e7a_12:
    rsp121 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp30) - 8);
    *rsp121 = 0x180006e7f;
    rax122 = fun_1800039c8();
    *reinterpret_cast<void***>(rax122) = reinterpret_cast<void**>(22);
    rsp123 = rsp121 + 1 - 1;
    *rsp123 = 0x180006e8a;
    fun_1800038fc();
    rsp7 = reinterpret_cast<struct s14*>(rsp123 + 1);
    goto addr_180006e8a_69;
}

uint64_t fun_1800099e4(void** ecx);

int64_t SetFilePointerEx = 0x16754;

void** fun_1800076f0(void** ecx, void** rdx, void** r8d) {
    int64_t rbx4;
    uint64_t rax5;
    void** r8_6;
    void*** r9_7;
    int32_t eax8;
    int64_t rcx9;
    int64_t rcx10;
    int64_t rcx11;
    void** rax12;
    void** v13;
    void** eax14;
    void** rax15;

    rbx4 = reinterpret_cast<int32_t>(ecx);
    rax5 = fun_1800099e4(*reinterpret_cast<void***>(&rbx4));
    if (rax5 != 0xffffffffffffffff) {
        r8_6 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 32 - 8 + 8 + 72);
        *reinterpret_cast<void***>(&r9_7) = r8d;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_7) + 4) = 0;
        eax8 = reinterpret_cast<int32_t>(SetFilePointerEx(rax5, rdx, r8_6, r9_7));
        if (eax8) {
            rcx9 = rbx4;
            *reinterpret_cast<uint32_t*>(&rcx10) = *reinterpret_cast<uint32_t*>(&rcx9) & 31;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx10) + 4) = 0;
            rcx11 = rcx10 * 88;
            *reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + (rbx4 >> 5) * 8)) + rcx11 + 8) = reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + (rbx4 >> 5) * 8)) + rcx11 + 8) & 0xfd);
            rax12 = v13;
        } else {
            eax14 = reinterpret_cast<void**>(GetLastError(rax5, rdx, r8_6, r9_7));
            fun_180003978(eax14, rdx, r8_6, r9_7);
            goto addr_180007720_5;
        }
    } else {
        rax15 = fun_1800039c8();
        *reinterpret_cast<void***>(rax15) = reinterpret_cast<void**>(9);
        goto addr_180007720_5;
    }
    addr_180007773_7:
    return rax12;
    addr_180007720_5:
    rax12 = reinterpret_cast<void**>(0xffffffffffffffff);
    goto addr_180007773_7;
}

struct s15 {
    signed char[312] pad312;
    int64_t f312;
};

uint32_t fun_180008448(uint32_t ecx, void** rdx);

struct s16 {
    signed char[4] pad4;
    int32_t f4;
};

int64_t MultiByteToWideChar = 0x164fe;

struct s17 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s18 {
    signed char[4] pad4;
    int32_t f4;
    signed char[204] pad212;
    uint32_t f212;
};

uint32_t fun_1800088e0(void** rcx, void** rdx, void** r8, void*** r9) {
    void* rsp5;
    void** rbp6;
    uint32_t eax7;
    struct s15* v8;
    uint32_t ecx9;
    uint32_t eax10;
    int64_t rbx11;
    int64_t rcx12;
    struct s16* v13;
    int32_t eax14;
    void** v15;
    struct s17* v16;
    void** rax17;
    struct s18* rcx18;
    struct s18* v19;
    int64_t rcx20;
    int32_t eax21;
    struct s18* v22;
    uint32_t eax23;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 80);
    rbp6 = r8;
    if (!rdx || !r8) {
        addr_1800087c9_3:
        eax7 = 0;
    } else {
        if (*reinterpret_cast<void***>(rdx)) {
            fun_180003bc4(reinterpret_cast<int64_t>(rsp5) + 48, 0);
            rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8);
            if (v8->f312) {
                ecx9 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx));
                eax10 = fun_180008448(ecx9, reinterpret_cast<int64_t>(rsp5) + 48);
                *reinterpret_cast<uint32_t*>(&rbx11) = 1;
                if (!eax10) {
                    *reinterpret_cast<int32_t*>(&rcx12) = v13->f4;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx12) + 4) = 0;
                    eax14 = reinterpret_cast<int32_t>(MultiByteToWideChar(rcx12, 9, rdx, 1));
                    if (eax14) {
                        addr_1800088c3_8:
                        if (v15) {
                            v16->f200 = v16->f200 & 0xfffffffd;
                        }
                    } else {
                        addr_1800088b5_10:
                        rax17 = fun_1800039c8();
                        *reinterpret_cast<uint32_t*>(&rbx11) = 0xffffffff;
                        *reinterpret_cast<void***>(rax17) = reinterpret_cast<void**>(42);
                        goto addr_1800088c3_8;
                    }
                    eax7 = *reinterpret_cast<uint32_t*>(&rbx11);
                } else {
                    rcx18 = v19;
                    if (reinterpret_cast<int32_t>(rcx18->f212) <= reinterpret_cast<int32_t>(1)) 
                        goto addr_18000886c_13;
                    if (*reinterpret_cast<int32_t*>(&rbp6) < reinterpret_cast<int32_t>(rcx18->f212)) 
                        goto addr_18000886c_13;
                    *reinterpret_cast<int32_t*>(&rcx20) = rcx18->f4;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx20) + 4) = 0;
                    eax21 = reinterpret_cast<int32_t>(MultiByteToWideChar(rcx20, 9, rdx));
                    rcx18 = v22;
                    if (eax21) 
                        goto addr_18000887e_16;
                    addr_18000886c_13:
                    if (reinterpret_cast<uint64_t>(rbp6) < reinterpret_cast<uint64_t>(static_cast<int64_t>(reinterpret_cast<int32_t>(rcx18->f212)))) 
                        goto addr_1800088b5_10;
                    if (!*reinterpret_cast<void***>(rdx + 1)) 
                        goto addr_1800088b5_10;
                    addr_18000887e_16:
                    *reinterpret_cast<uint32_t*>(&rbx11) = rcx18->f212;
                    goto addr_1800088c3_8;
                }
            } else {
                if (rcx) {
                    eax23 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx));
                    *rcx = *reinterpret_cast<void**>(&eax23);
                }
                *reinterpret_cast<uint32_t*>(&rbx11) = 1;
                goto addr_1800088c3_8;
            }
        } else {
            if (rcx) {
                *rcx = reinterpret_cast<void*>(0);
                goto addr_1800087c9_3;
            }
        }
    }
    return eax7;
}

int64_t g180018338 = -2;

void fun_18000af98();

int64_t WriteConsoleW = 0x167e2;

void* fun_180009a84(void* cx, void** rdx, void** r8, void*** r9) {
    int64_t rcx5;
    int32_t eax6;
    uint32_t eax7;

    rcx5 = g180018338;
    if (rcx5 == -2) {
        fun_18000af98();
        rcx5 = g180018338;
    }
    if (rcx5 == -1 || (eax6 = reinterpret_cast<int32_t>(WriteConsoleW()), eax6 == 0)) {
        eax7 = 0xffff;
    } else {
        eax7 = reinterpret_cast<uint16_t>(cx);
    }
    return *reinterpret_cast<void**>(&eax7);
}

void** fun_180003978(void** ecx, void** rdx, void** r8, void*** r9) {
    void** rax5;
    void*** rax6;
    void** rax7;
    void*** rbx8;
    int64_t rcx9;
    void** rax10;

    rax5 = fun_18000503c();
    if (rax5) {
        rax6 = reinterpret_cast<void***>(rax5 + 20);
    } else {
        rax6 = reinterpret_cast<void***>(0x18001721c);
    }
    *rax6 = ecx;
    rax7 = fun_18000503c();
    rbx8 = reinterpret_cast<void***>(0x180017218);
    if (rax7) {
        rbx8 = reinterpret_cast<void***>(rax7 + 16);
    }
    *reinterpret_cast<void***>(&rcx9) = ecx;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx9) + 4) = 0;
    rax10 = fun_1800039e8(rcx9);
    *rbx8 = rax10;
    return rax10;
}

void** g180018288 = reinterpret_cast<void**>(80);

void** g180018290 = reinterpret_cast<void**>(80);

void** g180018298 = reinterpret_cast<void**>(80);

void** g1800182a0 = reinterpret_cast<void**>(80);

void** g1800182a8 = reinterpret_cast<void**>(80);

void** g1800182b0 = reinterpret_cast<void**>(80);

void** g1800182b8 = reinterpret_cast<void**>(80);

void** g1800182d8 = reinterpret_cast<void**>(84);

void** g1800182e0 = reinterpret_cast<void**>(84);

void** g1800182e8 = reinterpret_cast<void**>(84);

void** g1800182f0 = reinterpret_cast<void**>(84);

void** g1800182f8 = reinterpret_cast<void**>(84);

void** g180018300 = reinterpret_cast<void**>(84);

void** fun_180009b40(void** rcx) {
    void** rcx2;
    int1_t zf3;
    void** rax4;
    void** rcx5;
    int1_t zf6;
    void** rcx7;
    int1_t zf8;
    void** rcx9;
    int1_t zf10;
    void** rcx11;
    int1_t zf12;
    void** rcx13;
    int1_t zf14;
    void** rcx15;
    int1_t zf16;
    void** rcx17;
    int1_t zf18;
    void** rcx19;
    int1_t zf20;
    void** rcx21;
    int1_t zf22;
    void** rcx23;
    int1_t zf24;
    void** rcx25;
    int1_t zf26;
    void** rcx27;
    int1_t zf28;

    if (rcx) {
        rcx2 = *reinterpret_cast<void***>(rcx + 24);
        zf3 = rcx2 == g180018288;
        if (!zf3) {
            rax4 = fun_180005f00(rcx2);
        }
        rcx5 = *reinterpret_cast<void***>(rcx + 32);
        zf6 = rcx5 == g180018290;
        if (!zf6) {
            rax4 = fun_180005f00(rcx5);
        }
        rcx7 = *reinterpret_cast<void***>(rcx + 40);
        zf8 = rcx7 == g180018298;
        if (!zf8) {
            rax4 = fun_180005f00(rcx7);
        }
        rcx9 = *reinterpret_cast<void***>(rcx + 48);
        zf10 = rcx9 == g1800182a0;
        if (!zf10) {
            rax4 = fun_180005f00(rcx9);
        }
        rcx11 = *reinterpret_cast<void***>(rcx + 56);
        zf12 = rcx11 == g1800182a8;
        if (!zf12) {
            rax4 = fun_180005f00(rcx11);
        }
        rcx13 = *reinterpret_cast<void***>(rcx + 64);
        zf14 = rcx13 == g1800182b0;
        if (!zf14) {
            rax4 = fun_180005f00(rcx13);
        }
        rcx15 = *reinterpret_cast<void***>(rcx + 72);
        zf16 = rcx15 == g1800182b8;
        if (!zf16) {
            rax4 = fun_180005f00(rcx15);
        }
        rcx17 = *reinterpret_cast<void***>(rcx + 0x68);
        zf18 = rcx17 == g1800182d8;
        if (!zf18) {
            rax4 = fun_180005f00(rcx17);
        }
        rcx19 = *reinterpret_cast<void***>(rcx + 0x70);
        zf20 = rcx19 == g1800182e0;
        if (!zf20) {
            rax4 = fun_180005f00(rcx19);
        }
        rcx21 = *reinterpret_cast<void***>(rcx + 0x78);
        zf22 = rcx21 == g1800182e8;
        if (!zf22) {
            rax4 = fun_180005f00(rcx21);
        }
        rcx23 = *reinterpret_cast<void***>(rcx + 0x80);
        zf24 = rcx23 == g1800182f0;
        if (!zf24) {
            rax4 = fun_180005f00(rcx23);
        }
        rcx25 = *reinterpret_cast<void***>(rcx + 0x88);
        zf26 = rcx25 == g1800182f8;
        if (!zf26) {
            rax4 = fun_180005f00(rcx25);
        }
        rcx27 = *reinterpret_cast<void***>(rcx + 0x90);
        zf28 = rcx27 == g180018300;
        if (!zf28) {
            rax4 = fun_180005f00(rcx27);
        }
    }
    return rax4;
}

void** g180018270 = reinterpret_cast<void**>(8);

void** g180018278 = reinterpret_cast<void**>(80);

void** g180018280 = reinterpret_cast<void**>(80);

void** g1800182c8 = reinterpret_cast<void**>(12);

void** g1800182d0 = reinterpret_cast<void**>(84);

void** fun_180009c4c(void** rcx) {
    void** rcx2;
    int1_t zf3;
    void** rax4;
    void** rcx5;
    int1_t zf6;
    void** rcx7;
    int1_t zf8;
    void** rcx9;
    int1_t zf10;
    void** rcx11;
    int1_t zf12;

    if (rcx) {
        rcx2 = *reinterpret_cast<void***>(rcx);
        zf3 = rcx2 == g180018270;
        if (!zf3) {
            rax4 = fun_180005f00(rcx2);
        }
        rcx5 = *reinterpret_cast<void***>(rcx + 8);
        zf6 = rcx5 == g180018278;
        if (!zf6) {
            rax4 = fun_180005f00(rcx5);
        }
        rcx7 = *reinterpret_cast<void***>(rcx + 16);
        zf8 = rcx7 == g180018280;
        if (!zf8) {
            rax4 = fun_180005f00(rcx7);
        }
        rcx9 = *reinterpret_cast<void***>(rcx + 88);
        zf10 = rcx9 == g1800182c8;
        if (!zf10) {
            rax4 = fun_180005f00(rcx9);
        }
        rcx11 = *reinterpret_cast<void***>(rcx + 96);
        zf12 = rcx11 == g1800182d0;
        if (!zf12) {
            rax4 = fun_180005f00(rcx11);
        }
    }
    return rax4;
}

void** fun_180009cb8(void** rcx) {
    void** rcx2;
    void** rcx3;
    void** rcx4;
    void** rcx5;
    void** rcx6;
    void** rcx7;
    void** rcx8;
    void** rcx9;
    void** rcx10;
    void** rcx11;
    void** rcx12;
    void** rcx13;
    void** rcx14;
    void** rcx15;
    void** rcx16;
    void** rcx17;
    void** rcx18;
    void** rcx19;
    void** rcx20;
    void** rcx21;
    void** rcx22;
    void** rcx23;
    void** rcx24;
    void** rcx25;
    void** rcx26;
    void** rcx27;
    void** rcx28;
    void** rcx29;
    void** rcx30;
    void** rcx31;
    void** rcx32;
    void** rcx33;
    void** rcx34;
    void** rcx35;
    void** rcx36;
    void** rcx37;
    void** rcx38;
    void** rcx39;
    void** rcx40;
    void** rcx41;
    void** rcx42;
    void** rcx43;
    void** rcx44;
    void** rcx45;
    void** rcx46;
    void** rcx47;
    void** rcx48;
    void** rcx49;
    void** rcx50;
    void** rcx51;
    void** rcx52;
    void** rcx53;
    void** rcx54;
    void** rcx55;
    void** rcx56;
    void** rcx57;
    void** rcx58;
    void** rcx59;
    void** rcx60;
    void** rcx61;
    void** rcx62;
    void** rcx63;
    void** rcx64;
    void** rcx65;
    void** rcx66;
    void** rcx67;
    void** rcx68;
    void** rcx69;
    void** rcx70;
    void** rcx71;
    void** rcx72;
    void** rcx73;
    void** rcx74;
    void** rcx75;
    void** rcx76;
    void** rcx77;
    void** rcx78;
    void** rcx79;
    void** rcx80;
    void** rcx81;
    void** rcx82;
    void** rcx83;
    void** rcx84;
    void** rcx85;
    void** rcx86;
    void** rcx87;
    void** rcx88;
    void** rax89;

    if (rcx) {
        rcx2 = *reinterpret_cast<void***>(rcx + 8);
        fun_180005f00(rcx2);
        rcx3 = *reinterpret_cast<void***>(rcx + 16);
        fun_180005f00(rcx3);
        rcx4 = *reinterpret_cast<void***>(rcx + 24);
        fun_180005f00(rcx4);
        rcx5 = *reinterpret_cast<void***>(rcx + 32);
        fun_180005f00(rcx5);
        rcx6 = *reinterpret_cast<void***>(rcx + 40);
        fun_180005f00(rcx6);
        rcx7 = *reinterpret_cast<void***>(rcx + 48);
        fun_180005f00(rcx7);
        rcx8 = *reinterpret_cast<void***>(rcx);
        fun_180005f00(rcx8);
        rcx9 = *reinterpret_cast<void***>(rcx + 64);
        fun_180005f00(rcx9);
        rcx10 = *reinterpret_cast<void***>(rcx + 72);
        fun_180005f00(rcx10);
        rcx11 = *reinterpret_cast<void***>(rcx + 80);
        fun_180005f00(rcx11);
        rcx12 = *reinterpret_cast<void***>(rcx + 88);
        fun_180005f00(rcx12);
        rcx13 = *reinterpret_cast<void***>(rcx + 96);
        fun_180005f00(rcx13);
        rcx14 = *reinterpret_cast<void***>(rcx + 0x68);
        fun_180005f00(rcx14);
        rcx15 = *reinterpret_cast<void***>(rcx + 56);
        fun_180005f00(rcx15);
        rcx16 = *reinterpret_cast<void***>(rcx + 0x70);
        fun_180005f00(rcx16);
        rcx17 = *reinterpret_cast<void***>(rcx + 0x78);
        fun_180005f00(rcx17);
        rcx18 = *reinterpret_cast<void***>(rcx + 0x80);
        fun_180005f00(rcx18);
        rcx19 = *reinterpret_cast<void***>(rcx + 0x88);
        fun_180005f00(rcx19);
        rcx20 = *reinterpret_cast<void***>(rcx + 0x90);
        fun_180005f00(rcx20);
        rcx21 = *reinterpret_cast<void***>(rcx + 0x98);
        fun_180005f00(rcx21);
        rcx22 = *reinterpret_cast<void***>(rcx + 0xa0);
        fun_180005f00(rcx22);
        rcx23 = *reinterpret_cast<void***>(rcx + 0xa8);
        fun_180005f00(rcx23);
        rcx24 = *reinterpret_cast<void***>(rcx + 0xb0);
        fun_180005f00(rcx24);
        rcx25 = *reinterpret_cast<void***>(rcx + 0xb8);
        fun_180005f00(rcx25);
        rcx26 = *reinterpret_cast<void***>(rcx + 0xc0);
        fun_180005f00(rcx26);
        rcx27 = *reinterpret_cast<void***>(rcx + 0xc8);
        fun_180005f00(rcx27);
        rcx28 = *reinterpret_cast<void***>(rcx + 0xd0);
        fun_180005f00(rcx28);
        rcx29 = *reinterpret_cast<void***>(rcx + 0xd8);
        fun_180005f00(rcx29);
        rcx30 = *reinterpret_cast<void***>(rcx + 0xe0);
        fun_180005f00(rcx30);
        rcx31 = *reinterpret_cast<void***>(rcx + 0xe8);
        fun_180005f00(rcx31);
        rcx32 = *reinterpret_cast<void***>(rcx + 0xf0);
        fun_180005f00(rcx32);
        rcx33 = *reinterpret_cast<void***>(rcx + 0xf8);
        fun_180005f00(rcx33);
        rcx34 = *reinterpret_cast<void***>(rcx + 0x100);
        fun_180005f00(rcx34);
        rcx35 = *reinterpret_cast<void***>(rcx + 0x108);
        fun_180005f00(rcx35);
        rcx36 = *reinterpret_cast<void***>(rcx + 0x110);
        fun_180005f00(rcx36);
        rcx37 = *reinterpret_cast<void***>(rcx + 0x118);
        fun_180005f00(rcx37);
        rcx38 = *reinterpret_cast<void***>(rcx + 0x120);
        fun_180005f00(rcx38);
        rcx39 = *reinterpret_cast<void***>(rcx + 0x128);
        fun_180005f00(rcx39);
        rcx40 = *reinterpret_cast<void***>(rcx + 0x130);
        fun_180005f00(rcx40);
        rcx41 = *reinterpret_cast<void***>(rcx + 0x138);
        fun_180005f00(rcx41);
        rcx42 = *reinterpret_cast<void***>(rcx + 0x140);
        fun_180005f00(rcx42);
        rcx43 = *reinterpret_cast<void***>(rcx + 0x148);
        fun_180005f00(rcx43);
        rcx44 = *reinterpret_cast<void***>(rcx + 0x150);
        fun_180005f00(rcx44);
        rcx45 = *reinterpret_cast<void***>(rcx + 0x168);
        fun_180005f00(rcx45);
        rcx46 = *reinterpret_cast<void***>(rcx + 0x170);
        fun_180005f00(rcx46);
        rcx47 = *reinterpret_cast<void***>(rcx + 0x178);
        fun_180005f00(rcx47);
        rcx48 = *reinterpret_cast<void***>(rcx + 0x180);
        fun_180005f00(rcx48);
        rcx49 = *reinterpret_cast<void***>(rcx + 0x188);
        fun_180005f00(rcx49);
        rcx50 = *reinterpret_cast<void***>(rcx + 0x190);
        fun_180005f00(rcx50);
        rcx51 = *reinterpret_cast<void***>(rcx + 0x160);
        fun_180005f00(rcx51);
        rcx52 = *reinterpret_cast<void***>(rcx + 0x1a0);
        fun_180005f00(rcx52);
        rcx53 = *reinterpret_cast<void***>(rcx + 0x1a8);
        fun_180005f00(rcx53);
        rcx54 = *reinterpret_cast<void***>(rcx + 0x1b0);
        fun_180005f00(rcx54);
        rcx55 = *reinterpret_cast<void***>(rcx + 0x1b8);
        fun_180005f00(rcx55);
        rcx56 = *reinterpret_cast<void***>(rcx + 0x1c0);
        fun_180005f00(rcx56);
        rcx57 = *reinterpret_cast<void***>(rcx + 0x1c8);
        fun_180005f00(rcx57);
        rcx58 = *reinterpret_cast<void***>(rcx + 0x198);
        fun_180005f00(rcx58);
        rcx59 = *reinterpret_cast<void***>(rcx + 0x1d0);
        fun_180005f00(rcx59);
        rcx60 = *reinterpret_cast<void***>(rcx + 0x1d8);
        fun_180005f00(rcx60);
        rcx61 = *reinterpret_cast<void***>(rcx + 0x1e0);
        fun_180005f00(rcx61);
        rcx62 = *reinterpret_cast<void***>(rcx + 0x1e8);
        fun_180005f00(rcx62);
        rcx63 = *reinterpret_cast<void***>(rcx + 0x1f0);
        fun_180005f00(rcx63);
        rcx64 = *reinterpret_cast<void***>(rcx + 0x1f8);
        fun_180005f00(rcx64);
        rcx65 = *reinterpret_cast<void***>(rcx + 0x200);
        fun_180005f00(rcx65);
        rcx66 = *reinterpret_cast<void***>(rcx + 0x208);
        fun_180005f00(rcx66);
        rcx67 = *reinterpret_cast<void***>(rcx + 0x210);
        fun_180005f00(rcx67);
        rcx68 = *reinterpret_cast<void***>(rcx + 0x218);
        fun_180005f00(rcx68);
        rcx69 = *reinterpret_cast<void***>(rcx + 0x220);
        fun_180005f00(rcx69);
        rcx70 = *reinterpret_cast<void***>(rcx + 0x228);
        fun_180005f00(rcx70);
        rcx71 = *reinterpret_cast<void***>(rcx + 0x230);
        fun_180005f00(rcx71);
        rcx72 = *reinterpret_cast<void***>(rcx + 0x238);
        fun_180005f00(rcx72);
        rcx73 = *reinterpret_cast<void***>(rcx + 0x240);
        fun_180005f00(rcx73);
        rcx74 = *reinterpret_cast<void***>(rcx + 0x248);
        fun_180005f00(rcx74);
        rcx75 = *reinterpret_cast<void***>(rcx + 0x250);
        fun_180005f00(rcx75);
        rcx76 = *reinterpret_cast<void***>(rcx + 0x258);
        fun_180005f00(rcx76);
        rcx77 = *reinterpret_cast<void***>(rcx + 0x260);
        fun_180005f00(rcx77);
        rcx78 = *reinterpret_cast<void***>(rcx + 0x268);
        fun_180005f00(rcx78);
        rcx79 = *reinterpret_cast<void***>(rcx + 0x270);
        fun_180005f00(rcx79);
        rcx80 = *reinterpret_cast<void***>(rcx + 0x278);
        fun_180005f00(rcx80);
        rcx81 = *reinterpret_cast<void***>(rcx + 0x280);
        fun_180005f00(rcx81);
        rcx82 = *reinterpret_cast<void***>(rcx + 0x288);
        fun_180005f00(rcx82);
        rcx83 = *reinterpret_cast<void***>(rcx + 0x290);
        fun_180005f00(rcx83);
        rcx84 = *reinterpret_cast<void***>(rcx + 0x298);
        fun_180005f00(rcx84);
        rcx85 = *reinterpret_cast<void***>(rcx + 0x2a0);
        fun_180005f00(rcx85);
        rcx86 = *reinterpret_cast<void***>(rcx + 0x2a8);
        fun_180005f00(rcx86);
        rcx87 = *reinterpret_cast<void***>(rcx + 0x2b0);
        fun_180005f00(rcx87);
        rcx88 = *reinterpret_cast<void***>(rcx + 0x2b8);
        rax89 = fun_180005f00(rcx88);
    }
    return rax89;
}

void** fun_180007ba4(void** ecx);

uint32_t fun_180008198(void** ecx, void** rdx);

void** g18001d660;

void** g18001d664;

void** g18001d678;

int64_t fun_180007f54(void** ecx, void** rdx) {
    uint32_t r15d3;
    void** rax4;
    void** rsi5;
    void** rbx6;
    void** eax7;
    void** r14d8;
    void** rax9;
    void** rbx10;
    int64_t rdi11;
    void** rax12;
    void** rcx13;
    int64_t rdx14;
    uint32_t eax15;
    void** rax16;
    void** rcx17;
    void** rcx18;
    int1_t zf19;
    int64_t rax20;
    void** edx21;
    int64_t rcx22;
    void** rax23;
    void** edx24;
    void* rcx25;
    void* rcx26;
    void** rcx27;

    r15d3 = 0xffffffff;
    rax4 = fun_180005018();
    rsi5 = rax4;
    fun_180007e98();
    rbx6 = *reinterpret_cast<void***>(rsi5 + 0xb8);
    eax7 = fun_180007ba4(ecx);
    r14d8 = eax7;
    if (eax7 == *reinterpret_cast<void***>(rbx6 + 4)) {
        r15d3 = 0;
        goto addr_18000817a_3;
    }
    rax9 = fun_180006770(0x228, rdx);
    rbx10 = rax9;
    *reinterpret_cast<void***>(&rdi11) = reinterpret_cast<void**>(0);
    if (!rax9) 
        goto addr_18000817a_3;
    rax12 = *reinterpret_cast<void***>(rsi5 + 0xb8);
    rcx13 = rbx10;
    *reinterpret_cast<int32_t*>(&rdx14) = 4;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx14) + 4) = 0;
    do {
        __asm__("movups xmm0, [rax]");
        __asm__("movups [rcx], xmm0");
        __asm__("movups xmm1, [rax+0x10]");
        __asm__("movups [rcx+0x10], xmm1");
        __asm__("movups xmm0, [rax+0x20]");
        __asm__("movups [rcx+0x20], xmm0");
        __asm__("movups xmm1, [rax+0x30]");
        __asm__("movups [rcx+0x30], xmm1");
        __asm__("movups xmm0, [rax+0x40]");
        __asm__("movups [rcx+0x40], xmm0");
        __asm__("movups xmm1, [rax+0x50]");
        __asm__("movups [rcx+0x50], xmm1");
        __asm__("movups xmm0, [rax+0x60]");
        __asm__("movups [rcx+0x60], xmm0");
        rcx13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rcx13) + reinterpret_cast<unsigned char>(0x80));
        __asm__("movups xmm1, [rax+0x70]");
        __asm__("movups [rcx-0x10], xmm1");
        rax12 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rax12) + reinterpret_cast<unsigned char>(0x80));
        --rdx14;
    } while (rdx14);
    __asm__("movups xmm0, [rax]");
    __asm__("movups [rcx], xmm0");
    __asm__("movups xmm1, [rax+0x10]");
    __asm__("movups [rcx+0x10], xmm1");
    *reinterpret_cast<void***>(rcx13 + 32) = *reinterpret_cast<void***>(rax12 + 32);
    *reinterpret_cast<void***>(rbx10) = reinterpret_cast<void**>(0);
    eax15 = fun_180008198(r14d8, rbx10);
    r15d3 = eax15;
    if (!eax15) 
        goto addr_18000803a_8;
    if (eax15 == 0xffffffff) {
        if (rbx10 != 0x180017870) {
            fun_180005f00(rbx10, rbx10);
        }
        rax16 = fun_1800039c8();
        *reinterpret_cast<void***>(rax16) = reinterpret_cast<void**>(22);
        goto addr_18000817a_3;
    }
    addr_18000803a_8:
    rcx17 = *reinterpret_cast<void***>(rsi5 + 0xb8);
    *reinterpret_cast<void***>(rcx17) = *reinterpret_cast<void***>(rcx17) - 1;
    if (!*reinterpret_cast<void***>(rcx17) && (rcx18 = *reinterpret_cast<void***>(rsi5 + 0xb8), rcx18 != 0x180017870)) {
        fun_180005f00(rcx18, rcx18);
    }
    *reinterpret_cast<void***>(rsi5 + 0xb8) = rbx10;
    *reinterpret_cast<void***>(rbx10) = *reinterpret_cast<void***>(rbx10) + 1;
    if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rsi5 + 0xc8)) & 2 || (zf19 = (*reinterpret_cast<unsigned char*>(&g180017fd8) & 1) == 0, !zf19)) {
        addr_18000817a_3:
        *reinterpret_cast<uint32_t*>(&rax20) = r15d3;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax20) + 4) = 0;
        return rax20;
    } else {
        fun_1800088e8(13, rbx10, 0x80);
        g18001d660 = *reinterpret_cast<void***>(rbx10 + 4);
        g18001d664 = *reinterpret_cast<void***>(rbx10 + 8);
        g18001d678 = *reinterpret_cast<void***>(rbx10 + 0x220);
        edx21 = reinterpret_cast<void**>(0);
        while (reinterpret_cast<signed char>(edx21) < reinterpret_cast<signed char>(5)) {
            rcx22 = reinterpret_cast<int32_t>(edx21);
            *reinterpret_cast<uint32_t*>(&rax23) = *reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(rbx10 + rcx22 * 2) + 12);
            *reinterpret_cast<int16_t*>(0x180000000 + rcx22 * 2 + 0x1d668) = *reinterpret_cast<int16_t*>(&rax23);
            ++edx21;
        }
        edx24 = reinterpret_cast<void**>(0);
        while (reinterpret_cast<signed char>(edx24) < reinterpret_cast<signed char>(0x101)) {
            rcx25 = reinterpret_cast<void*>(static_cast<int64_t>(reinterpret_cast<int32_t>(edx24)));
            *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(rcx25) + 0x180000000 + 0x17660) = *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(rcx25) + reinterpret_cast<unsigned char>(rbx10) + 24);
            ++edx24;
        }
        while (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&rdi11)) < reinterpret_cast<signed char>(0x100)) {
            rcx26 = reinterpret_cast<void*>(static_cast<int64_t>(reinterpret_cast<int32_t>(*reinterpret_cast<void***>(&rdi11))));
            *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(rcx26) + 0x180000000 + 0x17770) = *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(rcx26) + reinterpret_cast<unsigned char>(rbx10) + 0x119);
            *reinterpret_cast<void***>(&rdi11) = *reinterpret_cast<void***>(&rdi11) + 1;
        }
        __asm__("lock xadd [rcx], eax");
        if (1) 
            goto addr_18000813c_24;
        rcx27 = g180017b90;
        if (rcx27 != 0x180017870) 
            goto addr_180008137_26;
    }
    addr_18000813c_24:
    g180017b90 = rbx10;
    *reinterpret_cast<void***>(rbx10) = *reinterpret_cast<void***>(rbx10) + 1;
    fun_180008ad8(13, 13);
    goto addr_18000817a_3;
    addr_180008137_26:
    fun_180005f00(rcx27, rcx27);
    goto addr_18000813c_24;
}

void** g18001d680;

struct s19 {
    signed char[4] pad4;
    void** f4;
};

int64_t GetACP = 0x1677a;

int64_t GetOEMCP = 0x16784;

struct s20 {
    signed char[200] pad200;
    uint32_t f200;
};

void** fun_180007ba4(void** ecx) {
    void** ebx2;
    struct s12* rcx3;
    struct s19* v4;
    void** eax5;
    signed char v6;
    struct s20* v7;

    ebx2 = ecx;
    rcx3 = reinterpret_cast<struct s12*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 + 32);
    fun_180003bc4(rcx3, 0);
    g18001d680 = reinterpret_cast<void**>(0);
    if (!reinterpret_cast<int1_t>(ebx2 == 0xfffffffe)) {
        if (!reinterpret_cast<int1_t>(ebx2 == 0xfffffffd)) {
            if (reinterpret_cast<int1_t>(ebx2 == 0xfffffffc)) {
                g18001d680 = reinterpret_cast<void**>(1);
                ebx2 = v4->f4;
            }
        } else {
            g18001d680 = reinterpret_cast<void**>(1);
            eax5 = reinterpret_cast<void**>(GetACP(rcx3));
            goto addr_180007beb_6;
        }
    } else {
        g18001d680 = reinterpret_cast<void**>(1);
        eax5 = reinterpret_cast<void**>(GetOEMCP(rcx3));
        goto addr_180007beb_6;
    }
    addr_180007c06_8:
    if (v6) {
        v7->f200 = v7->f200 & 0xfffffffd;
    }
    return ebx2;
    addr_180007beb_6:
    ebx2 = eax5;
    goto addr_180007c06_8;
}

struct s21 {
    signed char[4] pad4;
    int32_t f4;
};

int32_t fun_18000a438(struct s21** rcx, int32_t edx, void* r8, int32_t r9d);

struct s22 {
    signed char[200] pad200;
    uint32_t f200;
};

int32_t fun_18000a5b0(void** rcx, int32_t edx, void* r8, int32_t r9d) {
    void* rsp5;
    int32_t eax6;
    signed char v7;
    struct s22* v8;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 96);
    fun_180003bc4(reinterpret_cast<int64_t>(rsp5) + 64, rcx);
    eax6 = fun_18000a438(reinterpret_cast<int64_t>(rsp5) - 8 + 8 + 64, edx, r8, r9d);
    if (v7) {
        v8->f200 = v8->f200 & 0xfffffffd;
    }
    return eax6;
}

struct s23 {
    signed char[4] pad4;
    int32_t f4;
};

int32_t fun_18000a0b4(struct s23** rcx, void** rdx, uint32_t r8d, signed char* r9);

struct s24 {
    signed char[200] pad200;
    uint32_t f200;
};

int32_t fun_18000a3a0(void** rcx, void** rdx, uint32_t r8d, signed char* r9) {
    void* rsp5;
    int32_t eax6;
    signed char v7;
    struct s24* v8;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x70);
    fun_180003bc4(reinterpret_cast<int64_t>(rsp5) + 80, rcx);
    eax6 = fun_18000a0b4(reinterpret_cast<int64_t>(rsp5) - 8 + 8 + 80, rdx, r8d, r9);
    if (v7) {
        v8->f200 = v8->f200 & 0xfffffffd;
    }
    return eax6;
}

struct s25 {
    signed char[6442547888] pad6442547888;
    unsigned char f6442547888;
};

struct s26 {
    unsigned char f0;
    unsigned char f1;
};

void** g180010790 = reinterpret_cast<void**>(0xb0);

void** g180010798 = reinterpret_cast<void**>(0xc0);

void** g1800107a0 = reinterpret_cast<void**>(0xd0);

void** g1800107a8 = reinterpret_cast<void**>(0xe0);

struct s0* fun_180007cb4(void** rcx);

int64_t IsValidCodePage = 0x16768;

int64_t GetCPInfo = 0x16790;

void fun_180007c24(void** rcx, void** rdx);

uint32_t fun_180008198(void** ecx, void** rdx) {
    void* rsp3;
    uint64_t rax4;
    uint64_t v5;
    void** rbx6;
    void** eax7;
    void* rsp8;
    void** rsi9;
    int64_t rdi10;
    void** ebp11;
    void*** rax12;
    void* rsp13;
    int64_t rax14;
    unsigned char* r14_15;
    int64_t rbp16;
    struct s25* r11_17;
    struct s26* r9_18;
    struct s26* rdx19;
    int64_t r8_20;
    void* r10_21;
    uint32_t edi22;
    uint32_t edi23;
    uint32_t edi24;
    void*** rcx25;
    void* rdi26;
    int64_t rdx27;
    uint32_t eax28;
    uint64_t rcx29;
    struct s0* rax30;
    int64_t rcx31;
    void** eax32;
    int64_t rcx33;
    int1_t zf34;
    void** v35;
    unsigned char v36;
    unsigned char v37;
    uint32_t edi38;
    unsigned char v39;
    int64_t r8_40;
    unsigned char v41;
    void* rcx42;
    unsigned char* rax43;
    int64_t rdi44;
    int64_t rcx45;
    unsigned char v46;
    unsigned char* rax47;
    int64_t rcx48;
    uint32_t ecx49;
    void** rax50;
    uint32_t ecx51;
    uint32_t ecx52;
    void*** rdi53;
    int32_t ecx54;

    rsp3 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 64);
    rax4 = g1800170a0;
    v5 = rax4 ^ reinterpret_cast<uint64_t>(rsp3);
    rbx6 = rdx;
    eax7 = fun_180007ba4(ecx);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp3) - 8 + 8);
    rsi9 = reinterpret_cast<void**>(0);
    *reinterpret_cast<int32_t*>(&rsi9 + 4) = 0;
    *reinterpret_cast<void***>(&rdi10) = eax7;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi10) + 4) = 0;
    if (!eax7) 
        goto addr_1800081cd_2;
    ebp11 = reinterpret_cast<void**>(0);
    rax12 = reinterpret_cast<void***>(0x180017aa0);
    do {
        if (*rax12 == *reinterpret_cast<void***>(&rdi10)) 
            break;
        ebp11 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(ebp11) + reinterpret_cast<unsigned char>(1));
        rax12 = rax12 + 48;
    } while (reinterpret_cast<unsigned char>(ebp11) < reinterpret_cast<unsigned char>(5));
    goto addr_180008200_6;
    fun_180003c80(rbx6 + 24, 0, 0x101);
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
    *reinterpret_cast<void***>(&rax14) = ebp11;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax14) + 4) = 0;
    r14_15 = reinterpret_cast<unsigned char*>(0x180017a98);
    *reinterpret_cast<int32_t*>(&rbp16) = 4;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbp16) + 4) = 0;
    r11_17 = reinterpret_cast<struct s25*>(rax14 + rax14 * 2 << 4);
    r9_18 = reinterpret_cast<struct s26*>(0x180017ab0 + reinterpret_cast<int64_t>(r11_17));
    do {
        rdx19 = r9_18;
        if (r9_18->f0) {
            do {
                if (!rdx19->f1) 
                    break;
                *reinterpret_cast<uint32_t*>(&r8_20) = rdx19->f0;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_20) + 4) = 0;
                if (*reinterpret_cast<uint32_t*>(&r8_20) <= static_cast<uint32_t>(rdx19->f1)) {
                    *reinterpret_cast<uint32_t*>(&r10_21) = static_cast<uint32_t>(r8_20 + 1);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_21) + 4) = 0;
                    do {
                        if (*reinterpret_cast<uint32_t*>(&r10_21) >= 0x101) 
                            break;
                        *reinterpret_cast<uint32_t*>(&r8_20) = *reinterpret_cast<uint32_t*>(&r8_20) + reinterpret_cast<unsigned char>(1);
                        *reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r10_21) + reinterpret_cast<unsigned char>(rbx6)) + 24) = reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r10_21) + reinterpret_cast<unsigned char>(rbx6)) + 24) | *r14_15);
                        *reinterpret_cast<uint32_t*>(&r10_21) = *reinterpret_cast<uint32_t*>(&r10_21) + reinterpret_cast<unsigned char>(1);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_21) + 4) = 0;
                    } while (*reinterpret_cast<uint32_t*>(&r8_20) <= static_cast<uint32_t>(rdx19->f1));
                }
                ++rdx19;
            } while (rdx19->f0);
        }
        r9_18 = r9_18 + 4;
        ++r14_15;
        --rbp16;
    } while (rbp16);
    *reinterpret_cast<void***>(rbx6 + 4) = *reinterpret_cast<void***>(&rdi10);
    *reinterpret_cast<void***>(rbx6 + 8) = reinterpret_cast<void**>(1);
    edi22 = reinterpret_cast<uint32_t>(*reinterpret_cast<void***>(&rdi10) - 0x3a4);
    if (!edi22) {
        rsi9 = g180010790;
    } else {
        edi23 = edi22 - 4;
        if (!edi23) {
            rsi9 = g180010798;
        } else {
            edi24 = edi23 - 13;
            if (!edi24) {
                rsi9 = g1800107a0;
            } else {
                if (!(edi24 - 1)) {
                    rsi9 = g1800107a8;
                }
            }
        }
    }
    *reinterpret_cast<void***>(rbx6 + 0x220) = rsi9;
    rcx25 = reinterpret_cast<void***>(rbx6 + 12);
    rdi26 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(r11_17) - reinterpret_cast<unsigned char>(rbx6)) + 0x180017aa0);
    *reinterpret_cast<int32_t*>(&rdx27) = 6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx27) + 4) = 0;
    do {
        eax28 = *reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(rdi26) + reinterpret_cast<uint64_t>(rcx25) - 8);
        *rcx25 = *reinterpret_cast<void***>(&eax28);
        rcx25 = rcx25 + 2;
        --rdx27;
    } while (rdx27);
    addr_180008416_26:
    fun_180007cb4(rbx6);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
    addr_18000841e_27:
    addr_180008420_28:
    rcx29 = v5 ^ reinterpret_cast<uint64_t>(rsp8);
    rax30 = fun_180002f40(rcx29, rcx29);
    return *reinterpret_cast<uint32_t*>(&rax30);
    addr_180008200_6:
    if (reinterpret_cast<unsigned char>(static_cast<uint32_t>(rdi10 - 0xfde8)) <= reinterpret_cast<unsigned char>(1)) 
        goto addr_180008324_29;
    *reinterpret_cast<uint32_t*>(&rcx31) = *reinterpret_cast<uint16_t*>(&rdi10);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx31) + 4) = 0;
    eax32 = reinterpret_cast<void**>(IsValidCodePage(rcx31));
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
    if (!eax32) 
        goto addr_180008324_29;
    rdx = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rsp8) + 32);
    *reinterpret_cast<void***>(&rcx33) = *reinterpret_cast<void***>(&rdi10);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx33) + 4) = 0;
    eax32 = reinterpret_cast<void**>(GetCPInfo(rcx33, rdx));
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
    if (!eax32) {
        zf34 = g18001d680 == 0;
        if (!zf34) {
            addr_1800081cd_2:
            fun_180007c24(rbx6, rdx);
            rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
            goto addr_18000841e_27;
        } else {
            addr_180008324_29:
            goto addr_180008420_28;
        }
    } else {
        fun_180003c80(rbx6 + 24, 0, 0x101);
        rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
        *reinterpret_cast<void***>(rbx6 + 4) = *reinterpret_cast<void***>(&rdi10);
        *reinterpret_cast<void***>(rbx6 + 0x220) = reinterpret_cast<void**>(0);
        if (reinterpret_cast<unsigned char>(v35) <= reinterpret_cast<unsigned char>(1)) {
            *reinterpret_cast<void***>(rbx6 + 8) = reinterpret_cast<void**>(0);
        } else {
            if (v36) {
                do {
                    if (!v37) 
                        break;
                    edi38 = v39;
                    *reinterpret_cast<uint32_t*>(&r8_40) = v41;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_40) + 4) = 0;
                    if (*reinterpret_cast<uint32_t*>(&r8_40) <= edi38) {
                        *reinterpret_cast<int32_t*>(&rcx42) = static_cast<int32_t>(r8_40 + 1);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx42) + 4) = 0;
                        rax43 = reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(rbx6 + 24) + reinterpret_cast<int64_t>(rcx42));
                        *reinterpret_cast<uint32_t*>(&rdi44) = edi38 - *reinterpret_cast<uint32_t*>(&r8_40);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi44) + 4) = 0;
                        *reinterpret_cast<int32_t*>(&rcx45) = static_cast<int32_t>(1 + rdi44);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx45) + 4) = 0;
                        do {
                            *rax43 = reinterpret_cast<unsigned char>(*rax43 | 4);
                            ++rax43;
                            --rcx45;
                        } while (rcx45);
                    }
                } while (v46);
            }
            rax47 = reinterpret_cast<unsigned char*>(rbx6 + 26);
            *reinterpret_cast<int32_t*>(&rcx48) = 0xfe;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx48) + 4) = 0;
            do {
                *rax47 = reinterpret_cast<unsigned char>(*rax47 | 8);
                ++rax47;
                --rcx48;
            } while (rcx48);
            ecx49 = reinterpret_cast<uint32_t>(*reinterpret_cast<void***>(rbx6 + 4) - 0x3a4);
            if (!ecx49) {
                rax50 = g180010790;
            } else {
                ecx51 = ecx49 - 4;
                if (!ecx51) {
                    rax50 = g180010798;
                } else {
                    ecx52 = ecx51 - 13;
                    if (!ecx52) {
                        rax50 = g1800107a0;
                    } else {
                        if (!(ecx52 - 1)) {
                            rax50 = g1800107a8;
                        } else {
                            rax50 = reinterpret_cast<void**>(0);
                        }
                    }
                }
            }
            *reinterpret_cast<void***>(rbx6 + 0x220) = rax50;
            *reinterpret_cast<void***>(rbx6 + 8) = reinterpret_cast<void**>(1);
        }
        rdi53 = reinterpret_cast<void***>(rbx6 + 12);
        ecx54 = 6;
        while (*reinterpret_cast<int16_t*>(&ecx54)) {
            *reinterpret_cast<int16_t*>(&ecx54) = reinterpret_cast<int16_t>(*reinterpret_cast<int16_t*>(&ecx54) - 1);
            *rdi53 = reinterpret_cast<void**>(0);
            rdi53 = rdi53 + 2;
        }
        goto addr_180008416_26;
    }
}

void fun_180007c24(void** rcx, void** rdx) {
    void** rbx3;
    void** rsi4;
    int64_t rbp5;
    void*** rdi6;
    int32_t ecx7;
    void* rdi8;
    signed char* rcx9;
    int64_t rdx10;

    rbx3 = rcx + 24;
    rsi4 = rcx;
    *reinterpret_cast<int32_t*>(&rbp5) = 0x101;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbp5) + 4) = 0;
    fun_180003c80(rbx3, 0, 0x101);
    rdi6 = reinterpret_cast<void***>(rsi4 + 12);
    *reinterpret_cast<void***>(rsi4 + 4) = reinterpret_cast<void**>(0);
    *reinterpret_cast<void***>(rsi4 + 0x220) = reinterpret_cast<void**>(0);
    ecx7 = 6;
    while (*reinterpret_cast<int16_t*>(&ecx7)) {
        *reinterpret_cast<int16_t*>(&ecx7) = reinterpret_cast<int16_t>(*reinterpret_cast<int16_t*>(&ecx7) - 1);
        *rdi6 = reinterpret_cast<void**>(0);
        rdi6 = rdi6 + 2;
        rsi4 = rsi4 + 2;
    }
    rdi8 = reinterpret_cast<void*>(0x180017870 - reinterpret_cast<unsigned char>(rsi4));
    do {
        *reinterpret_cast<void***>(rbx3) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdi8) + reinterpret_cast<unsigned char>(rbx3));
        ++rbx3;
        --rbp5;
    } while (rbp5);
    rcx9 = reinterpret_cast<signed char*>(rsi4 + 0x119);
    *reinterpret_cast<int32_t*>(&rdx10) = 0x100;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx10) + 4) = 0;
    do {
        *rcx9 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rcx9) + reinterpret_cast<uint64_t>(rdi8));
        ++rcx9;
        --rdx10;
    } while (rdx10);
    return;
}

struct s27 {
    unsigned char f0;
    signed char[255] pad256;
    signed char f256;
};

struct s0* fun_180007cb4(void** rcx) {
    void* rsp2;
    void* rbp3;
    void* rsp4;
    uint64_t rax5;
    uint64_t v6;
    void** rdi7;
    int64_t rcx8;
    int32_t eax9;
    void* rsp10;
    int64_t rbx11;
    int64_t rdx12;
    struct s27* rcx13;
    int64_t r8_14;
    int32_t eax15;
    uint32_t eax16;
    unsigned char al17;
    unsigned char v18;
    uint32_t r8d19;
    unsigned char v20;
    void* rcx21;
    unsigned char v22;
    void* rsp23;
    void** rdx24;
    void* rsp25;
    void** rdx26;
    void* r8_27;
    struct s27* rcx28;
    void* r9_29;
    unsigned char v30;
    unsigned char v31;
    signed char al32;
    uint64_t rcx33;
    struct s0* rax34;

    rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8);
    rbp3 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp2) - 0x480);
    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp2) - 0x580);
    rax5 = g1800170a0;
    v6 = rax5 ^ reinterpret_cast<uint64_t>(rsp4);
    rdi7 = rcx;
    *reinterpret_cast<void***>(&rcx8) = *reinterpret_cast<void***>(rcx + 4);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx8) + 4) = 0;
    eax9 = reinterpret_cast<int32_t>(GetCPInfo(rcx8, reinterpret_cast<uint64_t>(rsp4) + 80));
    rsp10 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp4) - 8 + 8);
    *reinterpret_cast<uint32_t*>(&rbx11) = 0x100;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx11) + 4) = 0;
    if (!eax9) {
        *reinterpret_cast<uint32_t*>(&rdx12) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx12) + 4) = 0;
        rcx13 = reinterpret_cast<struct s27*>(rdi7 + 25);
        do {
            *reinterpret_cast<uint32_t*>(&r8_14) = static_cast<uint32_t>(rdx12 - 97);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_14) + 4) = 0;
            if (static_cast<uint32_t>(r8_14 + 32) > 25) {
                if (*reinterpret_cast<uint32_t*>(&r8_14) > 25) {
                    rcx13->f256 = 0;
                    continue;
                } else {
                    rcx13->f0 = reinterpret_cast<unsigned char>(rcx13->f0 | 32);
                    eax15 = static_cast<int32_t>(rdx12 - 32);
                }
            } else {
                rcx13->f0 = reinterpret_cast<unsigned char>(rcx13->f0 | 16);
                eax15 = static_cast<int32_t>(rdx12 + 32);
            }
            rcx13->f256 = *reinterpret_cast<signed char*>(&eax15);
            *reinterpret_cast<uint32_t*>(&rdx12) = *reinterpret_cast<uint32_t*>(&rdx12) + 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx12) + 4) = 0;
            rcx13 = reinterpret_cast<struct s27*>(&rcx13->pad256);
        } while (*reinterpret_cast<uint32_t*>(&rdx12) < 0x100);
    } else {
        eax16 = 0;
        do {
            ++eax16;
        } while (eax16 < 0x100);
        al17 = v18;
        while (al17) {
            r8d19 = v20;
            *reinterpret_cast<uint32_t*>(&rcx21) = al17;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx21) + 4) = 0;
            while (*reinterpret_cast<uint32_t*>(&rcx21) <= r8d19 && *reinterpret_cast<uint32_t*>(&rcx21) < 0x100) {
                *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rsp10) + reinterpret_cast<int64_t>(rcx21) + 0x70) = 32;
                *reinterpret_cast<uint32_t*>(&rcx21) = *reinterpret_cast<uint32_t*>(&rcx21) + 1;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx21) + 4) = 0;
            }
            al17 = v22;
        }
        fun_18000a5b0(0, 1, reinterpret_cast<uint64_t>(rsp10) + 0x70, 0x100);
        rsp23 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp10) - 8 + 8);
        rdx24 = *reinterpret_cast<void***>(rdi7 + 0x220);
        fun_18000a3a0(0, rdx24, 0x100, reinterpret_cast<uint64_t>(rsp23) + 0x70);
        rsp25 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp23) - 8 + 8);
        rdx26 = *reinterpret_cast<void***>(rdi7 + 0x220);
        fun_18000a3a0(0, rdx26, 0x200, reinterpret_cast<uint64_t>(rsp25) + 0x70);
        rsp10 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) - 8 + 8);
        r8_27 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp3) + 0x70 - reinterpret_cast<unsigned char>(rdi7));
        rcx28 = reinterpret_cast<struct s27*>(rdi7 + 25);
        r9_29 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp3) + 0x170 - reinterpret_cast<unsigned char>(rdi7));
        do {
            if (!(v30 & 1)) {
                if (!(v31 & 2)) {
                    rcx28->f256 = 0;
                    continue;
                } else {
                    rcx28->f0 = reinterpret_cast<unsigned char>(rcx28->f0 | 32);
                    al32 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(r9_29) + reinterpret_cast<uint64_t>(rcx28) - 25);
                }
            } else {
                rcx28->f0 = reinterpret_cast<unsigned char>(rcx28->f0 | 16);
                al32 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(r8_27) + reinterpret_cast<uint64_t>(rcx28) - 25);
            }
            rcx28->f256 = al32;
            rcx28 = reinterpret_cast<struct s27*>(&rcx28->pad256);
            --rbx11;
        } while (rbx11);
    }
    rcx33 = v6 ^ reinterpret_cast<uint64_t>(rsp10);
    rax34 = fun_180002f40(rcx33, rcx33);
    return rax34;
}

void fun_18000526c(int32_t ecx, void** rdx, void** r8);

int64_t g1800180d0 = 0;

int64_t fun_1800089b4(int32_t ecx, void** rdx, void** r8) {
    int64_t rbx4;
    int1_t zf5;
    int64_t rbx6;
    void** rax7;
    int64_t rcx8;
    void** rax9;
    int64_t rax10;

    rbx4 = ecx;
    zf5 = g18001d340 == 0;
    if (zf5) {
        fun_180008af0();
        fun_180008b64(30);
        fun_18000526c(0xff, rdx, r8);
    }
    rbx6 = rbx4 + rbx4;
    if (!*reinterpret_cast<void***>(0x180018030 + rbx6 * 8)) {
        rax7 = fun_180006770(40, rdx);
        if (rax7) {
            fun_1800088e8(10, rdx, r8);
            if (*reinterpret_cast<void***>(0x180018030 + rbx6 * 8)) {
                fun_180005f00(rax7);
            } else {
                *reinterpret_cast<int32_t*>(&rdx) = 0xfa0;
                *reinterpret_cast<int32_t*>(&rdx + 4) = 0;
                fun_180006234(rax7, 0xfa0);
                *reinterpret_cast<void***>(0x180018030 + rbx6 * 8) = rax7;
            }
            rcx8 = g1800180d0;
            LeaveCriticalSection(rcx8, rdx);
            goto addr_1800089fb_9;
        } else {
            rax9 = fun_1800039c8();
            *reinterpret_cast<void***>(rax9) = reinterpret_cast<void**>(12);
            *reinterpret_cast<int32_t*>(&rax10) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax10) + 4) = 0;
        }
    } else {
        addr_1800089fb_9:
        *reinterpret_cast<int32_t*>(&rax10) = 1;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax10) + 4) = 0;
    }
    return rax10;
}

uint32_t fun_18000a8cc(uint32_t ecx);

int32_t g18001d8c0;

uint32_t fun_180008af0() {
    uint32_t eax1;
    uint32_t eax2;
    int1_t zf3;

    eax1 = fun_18000a8cc(3);
    if (eax1 == 1 || (eax2 = fun_18000a8cc(3), !eax2) && (zf3 = g18001d8c0 == 1, zf3)) {
        fun_180008b64(0xfc);
        eax2 = fun_180008b64(0xff);
    }
    return eax2;
}

uint16_t* fun_180008b34(int32_t ecx);

int64_t GetStdHandle = 0x16514;

void** fun_180002ca4(int16_t* rcx, int64_t rdx, uint16_t* r8);

uint16_t g18001db0a;

int64_t GetModuleFileNameW = 0x1679c;

int64_t fun_18000a7e4(uint16_t* rcx, int64_t rdx, uint16_t* r8);

void** fun_18000a800(int16_t* rcx, int64_t rdx, uint16_t* r8, int64_t r9);

void** fun_18000a75c(int16_t* rcx, int64_t rdx, uint16_t* r8, int64_t r9);

struct s0* fun_18000a90c(int64_t rcx, int64_t rdx, int32_t r8d, int64_t r9);

struct s28 {
    signed char[6] pad6;
    uint16_t f6;
    signed char[12] pad20;
    uint16_t f20;
};

int32_t g3c;

struct s29 {
    signed char[8] pad8;
    int32_t f8;
    int32_t f12;
};

uint32_t fun_180008b64(int32_t ecx) {
    void* rsp2;
    uint64_t rax3;
    uint64_t v4;
    uint16_t* rax5;
    void* rsp6;
    uint16_t* rbx7;
    uint32_t eax8;
    uint32_t eax9;
    int1_t zf10;
    int64_t rax11;
    int64_t rdi12;
    int32_t r8d13;
    void* rax14;
    void* rsp15;
    uint64_t rcx16;
    struct s0* rax17;
    void** eax18;
    uint16_t* r8_19;
    int64_t rdx20;
    int32_t eax21;
    void* rsp22;
    void** eax23;
    int64_t rax24;
    void* rsp25;
    int64_t rax26;
    int16_t* rcx27;
    void** eax28;
    void** eax29;
    void** eax30;
    struct s28* r8_31;
    uint32_t r9d32;
    struct s28* r8_33;
    int64_t rax34;
    uint32_t r11d35;
    struct s29* rax36;
    uint64_t rdx37;
    uint64_t rcx38;
    int64_t v39;

    rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 0x250);
    rax3 = g1800170a0;
    v4 = rax3 ^ reinterpret_cast<uint64_t>(rsp2);
    rax5 = fun_180008b34(ecx);
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp2) - 8 + 8);
    rbx7 = rax5;
    if (!rax5) 
        goto addr_180008d3f_2;
    eax8 = fun_18000a8cc(3);
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
    if (eax8 == 1 || (eax9 = fun_18000a8cc(3), rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8), !eax9) && (zf10 = g18001d8c0 == 1, zf10)) {
        rax11 = reinterpret_cast<int64_t>(GetStdHandle(0xfffffff4));
        rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
        rdi12 = rax11;
        if (reinterpret_cast<uint64_t>(rax11 - 1) <= 0xfffffffffffffffd) {
            r8d13 = 0;
            do {
                if (!*rbx7) 
                    break;
                ++r8d13;
                ++rbx7;
            } while (reinterpret_cast<uint64_t>(static_cast<int64_t>(r8d13)) < 0x1f4);
            rax14 = fun_1800084f0(reinterpret_cast<uint64_t>(rsp6) + 64);
            rsp15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
            WriteFile(rdi12, reinterpret_cast<uint64_t>(rsp15) + 64, rax14, reinterpret_cast<uint64_t>(rsp15) + 48);
            rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
            goto addr_180008d3f_2;
        }
    } else {
        if (ecx == 0xfc) {
            addr_180008d3f_2:
            rcx16 = v4 ^ reinterpret_cast<uint64_t>(rsp6);
            rax17 = fun_180002f40(rcx16, rcx16);
            return *reinterpret_cast<uint32_t*>(&rax17);
        } else {
            eax18 = fun_180002ca4(0x18001d8d0, 0x314, "R");
            if (eax18) {
                addr_180008dc0_11:
                fun_18000391c();
            } else {
                *reinterpret_cast<int32_t*>(&r8_19) = 0x104;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_19) + 4) = 0;
                g18001db0a = 0;
                rdx20 = 0x18001d902;
                eax21 = reinterpret_cast<int32_t>(GetModuleFileNameW());
                rsp22 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8 - 8 + 8);
                if (!eax21 && (r8_19 = reinterpret_cast<uint16_t*>("<"), *reinterpret_cast<int32_t*>(&rdx20) = 0x2fb, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx20) + 4) = 0, eax23 = fun_180002ca4(0x18001d902, 0x2fb, "<"), rsp22 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp22) - 8 + 8), !!eax23)) {
                    fun_18000391c();
                    goto addr_180008d81_14;
                }
                rax24 = fun_18000a7e4(0x18001d902, rdx20, r8_19);
                rsp25 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp22) - 8 + 8);
                if (rax24 + 1 <= 60 || (rax26 = fun_18000a7e4(0x18001d902, rdx20, r8_19), rcx27 = reinterpret_cast<int16_t*>(0x18001d88c + rax26 * 2), eax28 = fun_18000a800(rcx27, 0x2fb - (reinterpret_cast<int64_t>(rcx27 - 0xc000ec81) >> 1), ".", 3), rsp25 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) - 8 + 8 - 8 + 8), !eax28)) {
                    eax29 = fun_18000a75c(0x18001d8d0, 0x314, "\n", 3);
                    if (eax29) {
                        addr_180008dab_17:
                        fun_18000391c();
                        goto addr_180008dc0_11;
                    } else {
                        eax30 = fun_18000a75c(0x18001d8d0, 0x314, rbx7, 3);
                        if (eax30) {
                            addr_180008d96_19:
                            fun_18000391c();
                            goto addr_180008dab_17;
                        } else {
                            fun_18000a90c(0x18001d8d0, "M", 0x12010, 3);
                            rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) - 8 + 8 - 8 + 8 - 8 + 8);
                            goto addr_180008d3f_2;
                        }
                    }
                } else {
                    addr_180008d81_14:
                    fun_18000391c();
                    goto addr_180008d96_19;
                }
            }
        }
        r8_31 = reinterpret_cast<struct s28*>(static_cast<int64_t>(g3c));
        r9d32 = 0;
        r8_33 = reinterpret_cast<struct s28*>(&r8_31->pad6);
        *reinterpret_cast<uint32_t*>(&rax34) = r8_33->f20;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax34) + 4) = 0;
        r11d35 = r8_33->f6;
        rax36 = reinterpret_cast<struct s29*>(rax34 + 24 + reinterpret_cast<int64_t>(r8_33));
        if (!r11d35) {
            addr_180008e21_22:
        } else {
            do {
                *reinterpret_cast<int32_t*>(&rdx37) = rax36->f12;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx37) + 4) = 0;
                if (0 < rdx37) 
                    continue;
                *reinterpret_cast<int32_t*>(&rcx38) = rax36->f8 + *reinterpret_cast<int32_t*>(&rdx37);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx38) + 4) = 0;
                if (0 < rcx38) 
                    break;
                ++r9d32;
                rax36 = reinterpret_cast<struct s29*>(reinterpret_cast<int64_t>(rax36) + 40);
            } while (r9d32 < r11d35);
            goto addr_180008e21_22;
        }
        goto v39;
    }
}

void** g18001d308;

void** g18001d2f8;

void** g18001d2f0;

void** g18001df40;

void** g18001df48;

void fun_18000526c(int32_t ecx, void** rdx, void** r8) {
    int64_t rcx4;
    void** rcx5;
    void** rax6;
    void** rbx7;
    void** rdi8;
    void** rcx9;
    void** rbx10;
    void** rcx11;
    void** rcx12;
    void** rcx13;
    int1_t zf14;
    void** rax15;
    void** rcx16;
    void** rcx17;
    void** rcx18;
    int64_t v19;

    fun_180005228(ecx, rdx);
    *reinterpret_cast<int32_t*>(&rcx4) = ecx;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx4) + 4) = 0;
    ExitProcess(rcx4);
    rcx5 = g18001f100;
    rax6 = reinterpret_cast<void**>(DecodePointer(rcx5));
    rbx7 = g18001d308;
    rdi8 = rax6;
    if (rbx7) {
        do {
            rcx9 = *reinterpret_cast<void***>(rbx7);
            if (!rcx9) 
                break;
            fun_180005f00(rcx9, rcx9);
            rbx7 = rbx7 + 8;
        } while (rbx7);
        rbx7 = g18001d308;
    }
    fun_180005f00(rbx7, rbx7);
    rbx10 = g18001d300;
    g18001d308 = reinterpret_cast<void**>(0);
    if (rbx10) {
        do {
            rcx11 = *reinterpret_cast<void***>(rbx10);
            if (!rcx11) 
                break;
            fun_180005f00(rcx11, rcx11);
            rbx10 = rbx10 + 8;
        } while (rbx10);
        rbx10 = g18001d300;
    }
    fun_180005f00(rbx10, rbx10);
    rcx12 = g18001d2f8;
    g18001d300 = reinterpret_cast<void**>(0);
    fun_180005f00(rcx12, rcx12);
    rcx13 = g18001d2f0;
    fun_180005f00(rcx13, rcx13);
    g18001d2f8 = reinterpret_cast<void**>(0);
    g18001d2f0 = reinterpret_cast<void**>(0);
    if (rdi8 != 0xffffffffffffffff && (zf14 = g18001f100 == 0, !zf14)) {
        fun_180005f00(rdi8, rdi8);
    }
    rax15 = reinterpret_cast<void**>(EncodePointer(-1));
    rcx16 = g18001df40;
    g18001f100 = rax15;
    if (rcx16) {
        fun_180005f00(rcx16, rcx16);
        g18001df40 = reinterpret_cast<void**>(0);
    }
    rcx17 = g18001df48;
    if (rcx17) {
        fun_180005f00(rcx17, rcx17);
        g18001df48 = reinterpret_cast<void**>(0);
    }
    __asm__("lock xadd [rax], ecx");
    if (!1 && (rcx18 = g180017b90, rcx18 != 0x180017870)) {
        fun_180005f00(rcx18, rcx18);
        g180017b90 = reinterpret_cast<void**>(0x180017870);
    }
    goto v19;
}

uint32_t g18001df5c;

uint32_t fun_18000a8cc(uint32_t ecx) {
    uint32_t eax2;
    void** rax3;

    if (reinterpret_cast<int32_t>(ecx) < reinterpret_cast<int32_t>(0)) 
        goto addr_18000a8f4_2;
    if (reinterpret_cast<int32_t>(ecx) <= reinterpret_cast<int32_t>(2)) {
        eax2 = g18001df5c;
        g18001df5c = ecx;
    } else {
        if (ecx != 3) {
            addr_18000a8f4_2:
            rax3 = fun_1800039c8();
            *reinterpret_cast<void***>(rax3) = reinterpret_cast<void**>(22);
            fun_1800038fc();
            eax2 = 0xffffffff;
        } else {
            eax2 = g18001df5c;
        }
    }
    return eax2;
}

void** fun_180002ca4(int16_t* rcx, int64_t rdx, uint16_t* r8) {
    void** rax4;
    void** ebx5;
    int64_t r9_6;
    uint32_t eax7;
    void** eax8;

    if (!rcx || !rdx) {
        addr_180002cc0_2:
        rax4 = fun_1800039c8();
        ebx5 = reinterpret_cast<void**>(22);
    } else {
        if (r8) {
            r9_6 = reinterpret_cast<int64_t>(rcx) - reinterpret_cast<int64_t>(r8);
            do {
                eax7 = *r8;
                *reinterpret_cast<int16_t*>(r9_6 + reinterpret_cast<int64_t>(r8)) = *reinterpret_cast<int16_t*>(&eax7);
                ++r8;
                if (!*reinterpret_cast<int16_t*>(&eax7)) 
                    break;
                --rdx;
            } while (rdx);
            if (rdx) 
                goto addr_180002d0b_8; else 
                goto addr_180002cfb_9;
        } else {
            *rcx = 0;
            goto addr_180002cc0_2;
        }
    }
    addr_180002cca_11:
    *reinterpret_cast<void***>(rax4) = ebx5;
    fun_1800038fc();
    eax8 = ebx5;
    addr_180002cd3_12:
    return eax8;
    addr_180002d0b_8:
    eax8 = reinterpret_cast<void**>(0);
    goto addr_180002cd3_12;
    addr_180002cfb_9:
    *rcx = 0;
    rax4 = fun_1800039c8();
    ebx5 = reinterpret_cast<void**>(34);
    goto addr_180002cca_11;
}

int64_t fun_18000a7e4(uint16_t* rcx, int64_t rdx, uint16_t* r8) {
    uint16_t* rax4;
    uint32_t edx5;

    rax4 = rcx;
    do {
        edx5 = *rax4;
        ++rax4;
    } while (*reinterpret_cast<int16_t*>(&edx5));
    return (reinterpret_cast<int64_t>(rax4) - reinterpret_cast<int64_t>(rcx) >> 1) - 1;
}

void** fun_18000a800(int16_t* rcx, int64_t rdx, uint16_t* r8, int64_t r9) {
    void** rax5;
    void** ebx6;
    void** eax7;
    int16_t* r11_8;
    int64_t r10_9;
    void* r8_10;
    uint32_t eax11;
    int64_t r11_12;
    uint32_t eax13;

    if (r9) {
        if (!rcx) 
            goto addr_18000a837_3;
    } else {
        if (!rcx) {
            if (rdx) 
                goto addr_18000a837_3; else 
                goto addr_18000a817_6;
        }
    }
    if (!rdx) {
        addr_18000a837_3:
        rax5 = fun_1800039c8();
        ebx6 = reinterpret_cast<void**>(22);
    } else {
        if (!r9) {
            *rcx = 0;
            goto addr_18000a817_6;
        }
        if (r8) 
            goto addr_18000a850_11; else 
            goto addr_18000a834_12;
    }
    addr_18000a841_13:
    *reinterpret_cast<void***>(rax5) = ebx6;
    fun_1800038fc();
    eax7 = ebx6;
    addr_18000a84a_14:
    return eax7;
    addr_18000a850_11:
    r11_8 = rcx;
    r10_9 = rdx;
    if (r9 != -1) {
        r8_10 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(r8) - reinterpret_cast<int64_t>(rcx));
        do {
            eax11 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(r8_10) + reinterpret_cast<int64_t>(r11_8));
            *r11_8 = *reinterpret_cast<int16_t*>(&eax11);
            ++r11_8;
            if (!*reinterpret_cast<int16_t*>(&eax11)) 
                break;
            --r10_9;
        } while (r10_9 && (--r9, !!r9));
        if (!r9) 
            goto addr_18000a89c_19;
    } else {
        r11_12 = reinterpret_cast<int64_t>(r11_8) - reinterpret_cast<int64_t>(r8);
        do {
            eax13 = *r8;
            *reinterpret_cast<int16_t*>(r11_12 + reinterpret_cast<int64_t>(r8)) = *reinterpret_cast<int16_t*>(&eax13);
            ++r8;
            if (!*reinterpret_cast<int16_t*>(&eax13)) 
                break;
            --r10_9;
        } while (r10_9);
        goto addr_18000a876_23;
    }
    addr_18000a8a0_24:
    if (r10_9) {
        addr_18000a817_6:
        eax7 = reinterpret_cast<void**>(0);
        goto addr_18000a84a_14;
    } else {
        if (r9 != -1) {
            *rcx = 0;
            rax5 = fun_1800039c8();
            ebx6 = reinterpret_cast<void**>(34);
            goto addr_18000a841_13;
        } else {
            *(rcx + rdx - 1) = 0;
            eax7 = reinterpret_cast<void**>(static_cast<uint32_t>(r10_9 + 80));
            goto addr_18000a84a_14;
        }
    }
    addr_18000a89c_19:
    *r11_8 = 0;
    goto addr_18000a8a0_24;
    addr_18000a876_23:
    goto addr_18000a8a0_24;
    addr_18000a834_12:
    *rcx = 0;
    goto addr_18000a837_3;
}

void** fun_18000a75c(int16_t* rcx, int64_t rdx, uint16_t* r8, int64_t r9) {
    int16_t* r9_5;
    void** rax6;
    void** ebx7;
    void** eax8;
    int64_t rcx9;
    uint32_t eax10;

    r9_5 = rcx;
    if (!rcx || !rdx) {
        addr_18000a77b_2:
        rax6 = fun_1800039c8();
        ebx7 = reinterpret_cast<void**>(22);
    } else {
        if (r8) {
            do {
                if (!*rcx) 
                    break;
                ++rcx;
                --rdx;
            } while (rdx);
            if (rdx) 
                goto addr_18000a7ae_7; else 
                goto addr_18000a7a8_8;
        } else {
            *rcx = 0;
            goto addr_18000a77b_2;
        }
    }
    addr_18000a785_10:
    *reinterpret_cast<void***>(rax6) = ebx7;
    fun_1800038fc();
    eax8 = ebx7;
    addr_18000a78e_11:
    return eax8;
    addr_18000a7ae_7:
    rcx9 = reinterpret_cast<int64_t>(rcx) - reinterpret_cast<int64_t>(r8);
    do {
        eax10 = *r8;
        *reinterpret_cast<int16_t*>(rcx9 + reinterpret_cast<int64_t>(r8)) = *reinterpret_cast<int16_t*>(&eax10);
        ++r8;
        if (!*reinterpret_cast<int16_t*>(&eax10)) 
            break;
        --rdx;
    } while (rdx);
    if (!rdx) 
        goto addr_18000a7cd_15;
    eax8 = reinterpret_cast<void**>(0);
    goto addr_18000a78e_11;
    addr_18000a7cd_15:
    *r9_5 = 0;
    rax6 = fun_1800039c8();
    ebx7 = reinterpret_cast<void**>(34);
    goto addr_18000a785_10;
    addr_18000a7a8_8:
    *r9_5 = 0;
    goto addr_18000a77b_2;
}

int32_t fun_180006260();

int64_t g18001df60;

int64_t LoadLibraryExW = 0x167b2;

int64_t g18001df68;

int64_t g18001df70;

int64_t g18001df80;

int64_t g18001df78;

int64_t OutputDebugStringW = 0x162fa;

struct s0* fun_18000a90c(int64_t rcx, int64_t rdx, int32_t r8d, int64_t r9) {
    void* r8_3;
    void* rsp5;
    uint64_t rax6;
    int64_t rcx7;
    int32_t ebp8;
    int64_t r12_9;
    int64_t rax10;
    int64_t rdi11;
    int32_t eax12;
    void* rsp13;
    int1_t zf14;
    int64_t rax15;
    void* rsp16;
    int64_t rbx17;
    int32_t eax18;
    int64_t rax19;
    int64_t rax20;
    int64_t rax21;
    int64_t rax22;
    int64_t rax23;
    int64_t rax24;
    int64_t rax25;
    int64_t rax26;
    int64_t rax27;
    int64_t rax28;
    int64_t rax29;
    int32_t eax30;
    int64_t rcx31;
    int1_t zf32;
    int64_t rax33;
    int64_t rcx34;
    int64_t rax35;
    int64_t rax36;
    int32_t eax37;
    unsigned char v38;
    int64_t rcx39;
    int64_t rax40;
    int64_t rax41;
    int64_t rcx42;
    int64_t rax43;
    int64_t rax44;
    int64_t rcx45;
    int64_t rcx46;
    int64_t rax47;
    int64_t r9_48;
    uint64_t rcx49;
    struct s0* rax50;

    *reinterpret_cast<int32_t*>(&r8_3) = r8d;
    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 8 - 8 - 80);
    rax6 = g1800170a0;
    *reinterpret_cast<int32_t*>(&rcx7) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
    ebp8 = *reinterpret_cast<int32_t*>(&r8_3);
    r12_9 = rdx;
    rax10 = reinterpret_cast<int64_t>(EncodePointer());
    *reinterpret_cast<int32_t*>(&rdi11) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi11) + 4) = 0;
    eax12 = fun_180006260();
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8 - 8 + 8);
    zf14 = g18001df60 == 0;
    if (zf14) {
        *reinterpret_cast<int32_t*>(&r8_3) = 0x800;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
        rax15 = reinterpret_cast<int64_t>(LoadLibraryExW("U"));
        rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
        rbx17 = rax15;
        if (rax15) 
            goto addr_18000a99f_3;
        eax18 = reinterpret_cast<int32_t>(GetLastError("U"));
        rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
        if (eax18 != 87) 
            goto addr_18000ab61_5;
        *reinterpret_cast<int32_t*>(&r8_3) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_3) + 4) = 0;
        rax19 = reinterpret_cast<int64_t>(LoadLibraryExW("U"));
        rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
        rbx17 = rax19;
        if (!rax19) 
            goto addr_18000ab61_5;
        addr_18000a99f_3:
        rax20 = reinterpret_cast<int64_t>(GetProcAddress(rbx17, "MessageBoxW", r8_3));
        rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
        if (!rax20) 
            goto addr_18000ab61_5;
        rax21 = reinterpret_cast<int64_t>(EncodePointer(rax20, "MessageBoxW", r8_3));
        g18001df60 = rax21;
        rax22 = reinterpret_cast<int64_t>(GetProcAddress(rbx17, "GetActiveWindow", r8_3));
        rax23 = reinterpret_cast<int64_t>(EncodePointer(rax22, "GetActiveWindow", r8_3));
        g18001df68 = rax23;
        rax24 = reinterpret_cast<int64_t>(GetProcAddress(rbx17, "GetLastActivePopup", r8_3));
        rax25 = reinterpret_cast<int64_t>(EncodePointer(rax24, "GetLastActivePopup", r8_3));
        rdx = reinterpret_cast<int64_t>("GetUserObjectInformationW");
        g18001df70 = rax25;
        rax26 = reinterpret_cast<int64_t>(GetProcAddress(rbx17, "GetUserObjectInformationW", r8_3));
        rcx7 = rax26;
        rax27 = reinterpret_cast<int64_t>(EncodePointer(rcx7, "GetUserObjectInformationW", r8_3));
        rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8);
        g18001df80 = rax27;
        if (rax27) {
            rdx = reinterpret_cast<int64_t>("GetProcessWindowStation");
            rax28 = reinterpret_cast<int64_t>(GetProcAddress(rbx17, "GetProcessWindowStation", r8_3));
            rcx7 = rax28;
            rax29 = reinterpret_cast<int64_t>(EncodePointer(rcx7, "GetProcessWindowStation", r8_3));
            rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8 - 8 + 8);
            g18001df78 = rax29;
        }
    }
    eax30 = reinterpret_cast<int32_t>(IsDebuggerPresent(rcx7, rdx, r8_3));
    rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
    if (!eax30) {
        if (!eax12) {
            addr_18000aa90_11:
            rcx31 = g18001df78;
            if (rcx31 == rax10 || ((zf32 = g18001df80 == rax10, zf32) || ((rax33 = reinterpret_cast<int64_t>(DecodePointer()), rcx34 = g18001df80, rax35 = reinterpret_cast<int64_t>(DecodePointer(rcx34, rdx, r8_3)), rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8 - 8 + 8), rax33 == 0) || (!rax35 || (rax36 = reinterpret_cast<int64_t>(rax33(rcx34, rdx, r8_3)), rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8), !!rax36) && ((r8_3 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) + 56), *reinterpret_cast<int32_t*>(&rdx) = 1, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx) + 4) = 0, eax37 = reinterpret_cast<int32_t>(rax35(rax36, 1, r8_3)), rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8), !!eax37) && v38 & 1))))) {
                rcx39 = g18001df68;
                if (rcx39 != rax10 && ((rax40 = reinterpret_cast<int64_t>(DecodePointer()), rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8), !!rax40) && ((rax41 = reinterpret_cast<int64_t>(rax40()), rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8), rdi11 = rax41, !!rax41) && ((rcx42 = g18001df70, rcx42 != rax10) && (rax43 = reinterpret_cast<int64_t>(DecodePointer()), rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8), !!rax43))))) {
                    rax44 = reinterpret_cast<int64_t>(rax43(rdi11, rdx, r8_3));
                    rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
                    rdi11 = rax44;
                }
            } else {
                __asm__("bts ebp, 0x15");
            }
        } else {
            rcx45 = g18001df60;
            DecodePointer(rcx45, rdx, r8_3);
            rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
            goto addr_18000ab63_16;
        }
    } else {
        if (rcx) {
            OutputDebugStringW(rcx, rdx, r8_3);
            rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
        }
        if (!eax12) 
            goto addr_18000aa90_11;
        goto addr_18000ab63_16;
    }
    rcx46 = g18001df60;
    rax47 = reinterpret_cast<int64_t>(DecodePointer(rcx46, rdx, r8_3));
    rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
    if (!rax47) {
        addr_18000ab61_5:
    } else {
        *reinterpret_cast<int32_t*>(&r9_48) = ebp8;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_48) + 4) = 0;
        rax47(rdi11, rcx, r12_9, r9_48);
        rsp16 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp16) - 8 + 8);
    }
    addr_18000ab63_16:
    rcx49 = rax6 ^ reinterpret_cast<uint64_t>(rsp5) ^ reinterpret_cast<uint64_t>(rsp16);
    rax50 = fun_180002f40(rcx49, rcx49);
    return rax50;
}

struct s30 {
    signed char[6] pad6;
    uint16_t f6;
    signed char[12] pad20;
    uint16_t f20;
};

struct s10* fun_180008de0(struct s11* rcx, uint64_t rdx) {
    uint32_t r9d3;
    uint64_t r10_4;
    struct s30* r8_5;
    int64_t rax6;
    uint32_t r11d7;
    struct s10* rax8;
    uint64_t rdx9;
    uint64_t rcx10;

    r9d3 = 0;
    r10_4 = rdx;
    r8_5 = reinterpret_cast<struct s30*>(rcx->f60 + reinterpret_cast<int64_t>(rcx));
    *reinterpret_cast<uint32_t*>(&rax6) = r8_5->f20;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax6) + 4) = 0;
    r11d7 = r8_5->f6;
    rax8 = reinterpret_cast<struct s10*>(rax6 + 24 + reinterpret_cast<int64_t>(r8_5));
    if (!r11d7) {
        addr_180008e21_2:
        *reinterpret_cast<int32_t*>(&rax8) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax8) + 4) = 0;
    } else {
        do {
            *reinterpret_cast<int32_t*>(&rdx9) = rax8->f12;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx9) + 4) = 0;
            if (r10_4 < rdx9) 
                continue;
            *reinterpret_cast<int32_t*>(&rcx10) = rax8->f8 + *reinterpret_cast<int32_t*>(&rdx9);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx10) + 4) = 0;
            if (r10_4 < rcx10) 
                break;
            ++r9d3;
            ++rax8;
        } while (r9d3 < r11d7);
        goto addr_180008e21_2;
    }
    return rax8;
}

int64_t HeapSize = 0x16804;

void** fun_18000ab80(void** rcx) {
    void** rax2;

    if (rcx) {
        goto HeapSize;
    } else {
        rax2 = fun_1800039c8();
        *reinterpret_cast<void***>(rax2) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        return 0xffffffffffffffff;
    }
}

void** fun_1800094cc(void** rcx, void** rdx);

void** fun_1800067ec(void** rcx, void** rdx) {
    int64_t rbx3;
    void** rsi4;
    void** rbp5;
    void** rax6;
    int1_t below_or_equal7;
    int64_t rcx8;
    uint32_t ecx9;
    int1_t below_or_equal10;

    *reinterpret_cast<uint32_t*>(&rbx3) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx3) + 4) = 0;
    rsi4 = rdx;
    rbp5 = rcx;
    do {
        rax6 = fun_1800094cc(rbp5, rsi4);
        if (rax6) 
            break;
        if (!rsi4) 
            break;
        below_or_equal7 = g18001d658 <= *reinterpret_cast<uint32_t*>(&rax6);
        if (below_or_equal7) 
            break;
        *reinterpret_cast<uint32_t*>(&rcx8) = *reinterpret_cast<uint32_t*>(&rbx3);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx8) + 4) = 0;
        fun_1800066a8(rcx8, rsi4);
        ecx9 = static_cast<uint32_t>(rbx3 + 0x3e8);
        below_or_equal10 = ecx9 <= g18001d658;
        *reinterpret_cast<uint32_t*>(&rbx3) = ecx9;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx3) + 4) = 0;
        if (!below_or_equal10) {
            *reinterpret_cast<uint32_t*>(&rbx3) = 0xffffffff;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx3) + 4) = 0;
        }
    } while (*reinterpret_cast<uint32_t*>(&rbx3) != 0xffffffff);
    return rax6;
}

void fun_18000549c(int32_t ecx) {
    void** rdx2;
    int32_t r13d3;
    int1_t zf4;
    void** rcx5;
    int64_t* rax6;
    int64_t* rsi7;
    void** rcx8;
    int64_t* rax9;
    int64_t* rdi10;
    int64_t* r12_11;
    int64_t* r15_12;
    int64_t rax13;
    int64_t rcx14;
    int64_t rax15;
    int64_t rax16;
    void** rcx17;
    int64_t* rax18;
    void** rcx19;
    int64_t* rax20;
    int64_t rcx21;

    *reinterpret_cast<int32_t*>(&rdx2) = 1;
    *reinterpret_cast<int32_t*>(&rdx2 + 4) = 0;
    r13d3 = ecx;
    fun_1800088e8(8, 1, 0);
    zf4 = g18001d2e8 == 1;
    if (!zf4) {
        g18001d328 = 1;
        g18001d324 = 0;
        if (!1) {
            rcx5 = g18001f100;
            rax6 = reinterpret_cast<int64_t*>(DecodePointer(rcx5));
            rsi7 = rax6;
            if (rax6) {
                rcx8 = g18001f0f8;
                rax9 = reinterpret_cast<int64_t*>(DecodePointer(rcx8));
                rdi10 = rax9;
                r12_11 = rsi7;
                r15_12 = rax9;
                while (--rdi10, reinterpret_cast<uint64_t>(rdi10) >= reinterpret_cast<uint64_t>(rsi7)) {
                    rax13 = reinterpret_cast<int64_t>(EncodePointer());
                    if (*rdi10 != rax13) {
                        if (reinterpret_cast<uint64_t>(rdi10) < reinterpret_cast<uint64_t>(rsi7)) 
                            break;
                        rcx14 = *rdi10;
                        rax15 = reinterpret_cast<int64_t>(DecodePointer(rcx14));
                        rax16 = reinterpret_cast<int64_t>(EncodePointer());
                        *rdi10 = rax16;
                        rax15();
                        rcx17 = g18001f100;
                        rax18 = reinterpret_cast<int64_t*>(DecodePointer(rcx17));
                        rcx19 = g18001f0f8;
                        rax20 = reinterpret_cast<int64_t*>(DecodePointer(rcx19));
                        if (r12_11 != rax18) 
                            goto addr_1800056a2_10;
                        if (r15_12 == rax20) 
                            goto addr_18000565b_12;
                    } else {
                        addr_18000565b_12:
                        continue;
                    }
                    addr_1800056a2_10:
                    r12_11 = rax18;
                    rsi7 = rax18;
                    r15_12 = rax20;
                    rdi10 = rax20;
                    goto addr_18000565b_12;
                }
            }
            fun_1800054f4(0x18000f2b0, 0x18000f2d0);
        }
        rdx2 = reinterpret_cast<void**>(0x18000f2e0);
        fun_1800054f4(0x18000f2d8, 0x18000f2e0);
    }
    if (1 || (fun_180008ad8(8, 8), !0)) {
        g18001d2e8 = 1;
        fun_180008ad8(8, 8);
        fun_180005228(r13d3, rdx2);
        *reinterpret_cast<int32_t*>(&rcx21) = r13d3;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx21) + 4) = 0;
        ExitProcess(rcx21, rdx2);
    }
    return;
}

int64_t g18001df00;

int32_t fun_180009058(void** rcx, ...) {
    int64_t rcx2;
    int64_t rax3;
    int32_t eax4;
    int32_t eax5;

    rcx2 = g18001df00;
    rax3 = reinterpret_cast<int64_t>(DecodePointer(rcx2));
    if (!rax3 || (eax4 = reinterpret_cast<int32_t>(rax3(rcx)), eax4 == 0)) {
        eax5 = 0;
    } else {
        eax5 = 1;
    }
    return eax5;
}

int32_t g18001df90;

void** fun_180009414(void** rcx, ...) {
    void** rbx2;
    void** rax3;
    void** rax4;
    void** rdi5;
    uint64_t rcx6;
    void** r8_7;
    void** rax8;
    int1_t zf9;
    int32_t eax10;
    void** rax11;
    void** rax12;

    rbx2 = rcx;
    if (reinterpret_cast<unsigned char>(rcx) > reinterpret_cast<unsigned char>(0xffffffffffffffe0)) {
        fun_180009058(rcx);
        rax3 = fun_1800039c8();
        *reinterpret_cast<void***>(rax3) = reinterpret_cast<void**>(12);
        *reinterpret_cast<int32_t*>(&rax4) = 0;
        *reinterpret_cast<int32_t*>(&rax4 + 4) = 0;
    } else {
        *reinterpret_cast<int32_t*>(&rdi5) = 1;
        *reinterpret_cast<int32_t*>(&rdi5 + 4) = 0;
        if (rcx) {
            rdi5 = rcx;
        }
        while (1) {
            rcx6 = g18001d340;
            if (!rcx6) {
                fun_180008af0();
                fun_180008b64(30);
                fun_18000526c(0xff, 0, r8_7);
                rcx6 = g18001d340;
            }
            r8_7 = rdi5;
            rax8 = reinterpret_cast<void**>(HeapAlloc(rcx6));
            if (rax8) 
                goto addr_1800094a3_8;
            zf9 = g18001df90 == *reinterpret_cast<int32_t*>(&rax8);
            if (zf9) 
                goto addr_18000948d_10;
            eax10 = fun_180009058(rbx2);
            if (!eax10) 
                goto addr_180009498_12;
        }
    }
    addr_1800094ba_14:
    return rax4;
    addr_1800094a3_8:
    rax4 = rax8;
    goto addr_1800094ba_14;
    addr_18000948d_10:
    rax11 = fun_1800039c8();
    *reinterpret_cast<void***>(rax11) = reinterpret_cast<void**>(12);
    addr_180009498_12:
    rax12 = fun_1800039c8();
    *reinterpret_cast<void***>(rax12) = reinterpret_cast<void**>(12);
    goto addr_1800094a3_8;
}

void fun_180006b9c(void** rcx);

uint32_t fun_18000adbc(void** rcx, void** rdx, void** r8);

void fun_180006c38(void** rcx);

uint32_t fun_18000ae38(void** rcx, void** rdx, void** r8) {
    uint32_t edi4;
    int32_t eax5;
    uint32_t eax6;
    void** rax7;

    edi4 = 0xffffffff;
    eax5 = 0;
    *reinterpret_cast<unsigned char*>(&eax5) = reinterpret_cast<uint1_t>(!!rcx);
    if (eax5) {
        if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 64)) {
            fun_180006b9c(rcx);
            eax6 = fun_18000adbc(rcx, rdx, r8);
            edi4 = eax6;
            fun_180006c38(rcx);
        } else {
            *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(0);
        }
    } else {
        rax7 = fun_1800039c8();
        *reinterpret_cast<void***>(rax7) = reinterpret_cast<void**>(22);
        fun_1800038fc();
    }
    return edi4;
}

int64_t FlushFileBuffers = 0x16820;

void** fun_18000aea0(void** ecx, void** rdx, void** r8) {
    int64_t rdi4;
    int1_t cf5;
    int64_t rax6;
    int64_t rbx7;
    int64_t rax8;
    int64_t rsi9;
    void** rax10;
    void** rax11;
    uint64_t rax12;
    int32_t eax13;
    void** eax14;
    void** rax15;
    void** eax16;
    void** rax17;

    rdi4 = reinterpret_cast<int32_t>(ecx);
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rdi4) == 0xfffffffe)) {
        if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || ((cf5 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rdi4)) < reinterpret_cast<unsigned char>(g18001f0e8), !cf5) || (rax6 = rdi4, rbx7 = rdi4 >> 5, *reinterpret_cast<uint32_t*>(&rax8) = *reinterpret_cast<uint32_t*>(&rax6) & 31, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax8) + 4) = 0, rsi9 = rax8 * 88, (reinterpret_cast<uint32_t>(static_cast<int32_t>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rbx7 * 8)) + rsi9 + 8))) & 1) == 0))) {
            rax10 = fun_1800039c8();
            *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(9);
            fun_1800038fc();
        } else {
            fun_1800098a0(*reinterpret_cast<void***>(&rdi4), rdx, r8);
            if (!(*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rbx7 * 8)) + rsi9 + 8) & 1)) {
                addr_18000af3d_5:
                rax11 = fun_1800039c8();
                *reinterpret_cast<void***>(rax11) = reinterpret_cast<void**>(9);
                *reinterpret_cast<void***>(&rbx7) = reinterpret_cast<void**>(0xffffffff);
                goto addr_18000af4b_6;
            } else {
                rax12 = fun_1800099e4(*reinterpret_cast<void***>(&rdi4));
                eax13 = reinterpret_cast<int32_t>(FlushFileBuffers(rax12));
                if (eax13) {
                    *reinterpret_cast<void***>(&rbx7) = reinterpret_cast<void**>(0);
                } else {
                    eax14 = reinterpret_cast<void**>(GetLastError(rax12));
                    *reinterpret_cast<void***>(&rbx7) = eax14;
                }
                if (!*reinterpret_cast<void***>(&rbx7)) 
                    goto addr_18000af4b_6; else 
                    goto addr_18000af36_11;
            }
        }
    } else {
        rax15 = fun_1800039c8();
        *reinterpret_cast<void***>(rax15) = reinterpret_cast<void**>(9);
    }
    eax16 = reinterpret_cast<void**>(0xffffffff);
    addr_18000af69_14:
    return eax16;
    addr_18000af4b_6:
    fun_180009a58(*reinterpret_cast<void***>(&rdi4), rdx, r8);
    eax16 = *reinterpret_cast<void***>(&rbx7);
    goto addr_18000af69_14;
    addr_18000af36_11:
    rax17 = fun_180003958();
    *reinterpret_cast<void***>(rax17) = *reinterpret_cast<void***>(&rbx7);
    goto addr_18000af3d_5;
}

void fun_180006c04(int32_t ecx, void** rdx, void** r8) {
    if (ecx >= 20) {
        goto EnterCriticalSection;
    } else {
        fun_1800088e8(ecx + 16, rdx, r8);
        __asm__("bts dword [rbx+0x18], 0xf");
        return;
    }
}

uint32_t fun_180009730(void** rcx, void** rdx);

void fun_180006c88(int32_t ecx, void** rdx);

uint32_t fun_1800096e4(void** rcx, void** rdx, void** r8) {
    uint32_t eax4;
    uint32_t eax5;
    void** eax6;
    void** eax7;
    uint32_t eax8;
    int32_t r14d9;
    int64_t rsi10;
    uint32_t edi11;
    int32_t ebx12;
    int1_t less13;
    int64_t r15_14;
    void** rax15;
    void** rdx16;
    void** rax17;
    void** rcx18;
    uint32_t eax19;
    uint32_t eax20;
    void** rdx21;
    void** rdx22;

    if (rcx) {
        eax4 = fun_180009730(rcx, rdx);
        if (!eax4) {
            if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 0x4000)) {
                eax5 = 0;
            } else {
                eax6 = fun_180006ca8(rcx, rdx);
                eax7 = fun_18000aea0(eax6, rdx, r8);
                eax8 = -reinterpret_cast<unsigned char>(eax7);
                eax5 = eax8 - (eax8 + reinterpret_cast<uint1_t>(eax8 < eax8 + reinterpret_cast<uint1_t>(!!eax7)));
            }
        } else {
            eax5 = 0xffffffff;
        }
        return eax5;
    }
    r14d9 = *reinterpret_cast<int32_t*>(&rcx);
    *reinterpret_cast<uint32_t*>(&rsi10) = 0;
    edi11 = 0;
    fun_1800088e8(1, rdx, r8);
    ebx12 = 0;
    while (less13 = ebx12 < g18001dfa8, less13) {
        r15_14 = ebx12;
        rax15 = g18001dfa0;
        rdx16 = *reinterpret_cast<void***>(rax15 + r15_14 * 8);
        if (rdx16 && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx16 + 24)) & 0x83) {
            fun_180006c04(ebx12, rdx16, r8);
            rax17 = g18001dfa0;
            rcx18 = *reinterpret_cast<void***>(rax17 + r15_14 * 8);
            if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx18 + 24)) & 0x83) {
                if (r14d9 != 1) {
                    if (!r14d9 && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx18 + 24)) & 2) {
                        eax19 = fun_1800096e4(rcx18, rdx16, r8);
                        if (eax19 == 0xffffffff) {
                            edi11 = 0xffffffff;
                        }
                    }
                } else {
                    eax20 = fun_1800096e4(rcx18, rdx16, r8);
                    if (eax20 != 0xffffffff) {
                        *reinterpret_cast<uint32_t*>(&rsi10) = *reinterpret_cast<uint32_t*>(&rsi10) + 1;
                    }
                }
            }
            rdx21 = g18001dfa0;
            rdx22 = *reinterpret_cast<void***>(rdx21 + r15_14 * 8);
            fun_180006c88(ebx12, rdx22);
        }
        ++ebx12;
    }
    fun_180008ad8(1, 1);
    if (r14d9 != 1) 
        goto addr_180009882_23;
    edi11 = *reinterpret_cast<uint32_t*>(&rsi10);
    addr_180009882_23:
    return edi11;
}

int64_t CreateFileW = 0x16834;

void fun_18000af98() {
    int64_t rax1;

    rax1 = reinterpret_cast<int64_t>(CreateFileW("C", 0x40000000));
    g180018338 = rax1;
    return;
}

uint64_t g18001f0c0;

int32_t fun_18000aca0(void** rcx);

int64_t LCMapStringW = 0x16810;

int32_t fun_18000acd4(void** rcx, uint32_t edx, void** r8, uint32_t r9d) {
    uint64_t r10_5;
    uint64_t r10_6;
    int32_t eax7;
    int64_t r9_8;
    int64_t rcx9;
    int64_t rdx10;
    int32_t eax11;

    r10_5 = g18001f0c0;
    r10_6 = r10_5 ^ g1800170a0;
    if (!r10_6) {
        eax7 = fun_18000aca0(rcx);
        *reinterpret_cast<uint32_t*>(&r9_8) = r9d;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_8) + 4) = 0;
        *reinterpret_cast<int32_t*>(&rcx9) = eax7;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx9) + 4) = 0;
        *reinterpret_cast<uint32_t*>(&rdx10) = edx;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx10) + 4) = 0;
        eax11 = reinterpret_cast<int32_t>(LCMapStringW(rcx9, rdx10, r8, r9_8));
    } else {
        eax11 = reinterpret_cast<int32_t>(r10_6());
    }
    return eax11;
}

void** fun_180007b18(void*** rcx, void** rdx) {
    void** rax3;
    void** rbx4;

    if (!rdx || !rcx) {
        *reinterpret_cast<int32_t*>(&rax3) = 0;
        *reinterpret_cast<int32_t*>(&rax3 + 4) = 0;
    } else {
        rbx4 = *rcx;
        if (rbx4 != rdx && ((*rcx = rdx, fun_1800077d8(rdx), !!rbx4) && ((fun_1800079fc(rbx4), !*reinterpret_cast<void***>(rbx4)) && rbx4 != 0x180017e80))) {
            fun_180007864(rbx4);
        }
        rax3 = rdx;
    }
    return rax3;
}

int64_t g18001df10;

int32_t g180010438 = 3;

int32_t g18001043c = 9;

int64_t g18001df20;

int32_t g180010430 = 12;

int64_t g18001df28;

int64_t g18001df18;

int64_t fun_1800090cc(void** ecx) {
    void** ebx2;
    void** r13_3;
    void** v4;
    int32_t edi5;
    void** rsi6;
    void** rdx7;
    void*** r14_8;
    int64_t rcx9;
    void* edx10;
    void** rax11;
    void** r15_12;
    void** r8_13;
    int64_t rax14;
    void** rax15;
    int32_t ecx16;
    int32_t edx17;
    int32_t eax18;
    int64_t rcx19;
    int64_t rcx20;
    int64_t rdx21;
    int64_t rcx22;
    void* edx23;
    void* edx24;
    void** rax25;
    void** rcx26;
    void** rax27;

    ebx2 = ecx;
    *reinterpret_cast<uint32_t*>(&r13_3) = 0;
    *reinterpret_cast<int32_t*>(&r13_3 + 4) = 0;
    v4 = reinterpret_cast<void**>(0);
    edi5 = 0;
    *reinterpret_cast<int32_t*>(&rsi6) = 0;
    *reinterpret_cast<int32_t*>(&rsi6 + 4) = 0;
    *reinterpret_cast<void****>(&rdx7) = reinterpret_cast<void***>(ecx - 2);
    *reinterpret_cast<int32_t*>(&rdx7 + 4) = 0;
    if (!*reinterpret_cast<void****>(&rdx7)) {
        r14_8 = reinterpret_cast<void***>(0x18001df10);
        rcx9 = g18001df10;
    } else {
        edx10 = reinterpret_cast<void*>(*reinterpret_cast<void****>(&rdx7) - 2);
        if (!edx10) 
            goto addr_180009167_4;
        *reinterpret_cast<void****>(&rdx7) = reinterpret_cast<void***>(reinterpret_cast<uint32_t>(edx10) - 2);
        *reinterpret_cast<int32_t*>(&rdx7 + 4) = 0;
        if (!*reinterpret_cast<void****>(&rdx7)) 
            goto addr_180009157_6; else 
            goto addr_18000910a_7;
    }
    addr_1800091d2_8:
    edi5 = 1;
    rax11 = reinterpret_cast<void**>(DecodePointer(rcx9));
    r15_12 = rax11;
    addr_1800091e4_9:
    if (!reinterpret_cast<int1_t>(r15_12 == 1)) {
        if (!r15_12) {
            fun_18000549c(static_cast<int32_t>(reinterpret_cast<uint64_t>(r15_12 + 3)));
        }
        if (edi5) {
            fun_1800088e8(0, rdx7, r8_13);
        }
        if (reinterpret_cast<unsigned char>(ebx2) > reinterpret_cast<unsigned char>(11)) 
            goto addr_18000924a_15;
        if (static_cast<int1_t>(0x910 >> reinterpret_cast<unsigned char>(ebx2))) 
            goto addr_18000921d_17;
    } else {
        addr_1800091ea_18:
        *reinterpret_cast<uint32_t*>(&rax14) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax14) + 4) = 0;
        goto addr_1800092e7_19;
    }
    addr_18000924a_15:
    if (!reinterpret_cast<int1_t>(ebx2 == 8)) {
        addr_180009288_20:
        rax15 = reinterpret_cast<void**>(EncodePointer());
        *r14_8 = rax15;
    } else {
        ecx16 = g180010438;
        edx17 = ecx16;
        while (eax18 = g18001043c, edx17 < ecx16 + eax18) {
            rcx19 = edx17;
            *reinterpret_cast<uint64_t*>(reinterpret_cast<uint64_t>(*reinterpret_cast<void***>(rsi6 + 0xa0) + (rcx19 + rcx19) * 8) + 8) = 0;
            ++edx17;
            ecx16 = g180010438;
        }
    }
    if (edi5) {
        fun_180008ad8(0, 0);
    }
    if (!reinterpret_cast<int1_t>(ebx2 == 8)) {
        *reinterpret_cast<void***>(&rcx20) = ebx2;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx20) + 4) = 0;
        r15_12(rcx20);
    } else {
        *reinterpret_cast<void***>(&rdx21) = *reinterpret_cast<void***>(rsi6 + 0xb0);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx21) + 4) = 0;
        *reinterpret_cast<void***>(&rcx22) = ebx2;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx22) + 4) = 0;
        r15_12(rcx22, rdx21);
    }
    if (reinterpret_cast<unsigned char>(ebx2) <= reinterpret_cast<unsigned char>(11) && (static_cast<int1_t>(0x910 >> reinterpret_cast<unsigned char>(ebx2)) && (*reinterpret_cast<void***>(rsi6 + 0xa8) = r13_3, reinterpret_cast<int1_t>(ebx2 == 8)))) {
        *reinterpret_cast<void***>(rsi6 + 0xb0) = v4;
        goto addr_1800091ea_18;
    }
    addr_18000921d_17:
    r13_3 = *reinterpret_cast<void***>(rsi6 + 0xa8);
    *reinterpret_cast<void***>(rsi6 + 0xa8) = reinterpret_cast<void**>(0);
    if (!reinterpret_cast<int1_t>(ebx2 == 8)) 
        goto addr_180009288_20;
    v4 = *reinterpret_cast<void***>(rsi6 + 0xb0);
    *reinterpret_cast<void***>(rsi6 + 0xb0) = reinterpret_cast<void**>(0x8c);
    goto addr_18000924a_15;
    addr_1800092e7_19:
    return rax14;
    addr_180009157_6:
    r14_8 = reinterpret_cast<void***>(0x18001df20);
    rcx9 = g18001df20;
    goto addr_1800091d2_8;
    addr_18000910a_7:
    edx23 = reinterpret_cast<void*>(*reinterpret_cast<void****>(&rdx7) - 2);
    if (!edx23 || (edx24 = reinterpret_cast<void*>(reinterpret_cast<uint32_t>(edx23) - 3), edx24 == 0)) {
        addr_180009167_4:
        rax25 = fun_18000503c();
        rsi6 = rax25;
        if (rax25) {
            rdx7 = *reinterpret_cast<void***>(rax25 + 0xa0);
            rcx26 = rdx7;
            r8_13 = reinterpret_cast<void**>(static_cast<int64_t>(g180010430));
            do {
                if (*reinterpret_cast<void***>(rcx26 + 4) == ebx2) 
                    break;
                rcx26 = rcx26 + 16;
            } while (reinterpret_cast<unsigned char>(rcx26) < reinterpret_cast<unsigned char>(reinterpret_cast<uint64_t>(reinterpret_cast<unsigned char>(r8_13) << 4) + reinterpret_cast<unsigned char>(rdx7)));
            if (reinterpret_cast<unsigned char>(rcx26) >= reinterpret_cast<unsigned char>(reinterpret_cast<uint64_t>(reinterpret_cast<unsigned char>(r8_13) << 4) + reinterpret_cast<unsigned char>(rdx7))) 
                goto addr_1800091b9_36;
            if (*reinterpret_cast<void***>(rcx26 + 4) == ebx2) 
                goto addr_1800091bb_38;
        } else {
            addr_180009174_39:
            *reinterpret_cast<uint32_t*>(&rax14) = 0xffffffff;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax14) + 4) = 0;
            goto addr_1800092e7_19;
        }
    } else {
        *reinterpret_cast<void****>(&rdx7) = reinterpret_cast<void***>(reinterpret_cast<uint32_t>(edx24) - 4);
        *reinterpret_cast<int32_t*>(&rdx7 + 4) = 0;
        if (!*reinterpret_cast<void****>(&rdx7)) {
            r14_8 = reinterpret_cast<void***>(0x18001df28);
            rcx9 = g18001df28;
            goto addr_1800091d2_8;
        } else {
            *reinterpret_cast<void****>(&rdx7) = *reinterpret_cast<void****>(&rdx7) - 6;
            *reinterpret_cast<int32_t*>(&rdx7 + 4) = 0;
            if (!*reinterpret_cast<void****>(&rdx7)) {
                r14_8 = reinterpret_cast<void***>(0x18001df18);
                rcx9 = g18001df18;
                goto addr_1800091d2_8;
            } else {
                *reinterpret_cast<void****>(&rdx7) = *reinterpret_cast<void****>(&rdx7) - 1;
                *reinterpret_cast<int32_t*>(&rdx7 + 4) = 0;
                if (*reinterpret_cast<void****>(&rdx7)) {
                    rax27 = fun_1800039c8();
                    *reinterpret_cast<void***>(rax27) = reinterpret_cast<void**>(22);
                    fun_1800038fc();
                    goto addr_180009174_39;
                }
            }
        }
    }
    addr_1800091b9_36:
    *reinterpret_cast<int32_t*>(&rcx26) = 0;
    *reinterpret_cast<int32_t*>(&rcx26 + 4) = 0;
    addr_1800091bb_38:
    r14_8 = reinterpret_cast<void***>(rcx26 + 8);
    r15_12 = *r14_8;
    goto addr_1800091e4_9;
}

int64_t IsProcessorFeaturePresent = 0x164ac;

int32_t fun_18000e730(int64_t rcx) {
    goto IsProcessorFeaturePresent;
}

uint32_t fun_18000ad64(void** rcx, uint16_t* rdx, int64_t r8);

uint32_t fun_18000ac14(void** rcx) {
    void** rbp2;
    int64_t rdi3;
    int64_t rsi4;
    int64_t rbx5;
    uint16_t* rdx6;
    uint32_t eax7;
    uint32_t eax8;

    rbp2 = rcx;
    *reinterpret_cast<int32_t*>(&rdi3) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
    *reinterpret_cast<int32_t*>(&rsi4) = 0xe3;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi4) + 4) = 0;
    do {
        __asm__("cdq ");
        rbx5 = static_cast<int32_t>(rsi4 + rdi3) - *reinterpret_cast<int32_t*>(&rdx6) >> 1;
        rdx6 = *reinterpret_cast<uint16_t**>(0x180012e80 + (rbx5 + rbx5) * 8);
        eax7 = fun_18000ad64(rbp2, rdx6, 85);
        if (!eax7) 
            break;
        if (reinterpret_cast<int32_t>(eax7) >= reinterpret_cast<int32_t>(0)) {
            *reinterpret_cast<int32_t*>(&rdi3) = static_cast<int32_t>(rbx5 + 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
        } else {
            *reinterpret_cast<int32_t*>(&rsi4) = static_cast<int32_t>(rbx5 - 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi4) + 4) = 0;
        }
    } while (*reinterpret_cast<int32_t*>(&rdi3) <= *reinterpret_cast<int32_t*>(&rsi4));
    goto addr_18000ac73_7;
    eax8 = *reinterpret_cast<uint32_t*>(0x180012e80 + (rbx5 + rbx5) * 8 + 8);
    addr_18000ac83_9:
    return eax8;
    addr_18000ac73_7:
    eax8 = 0xffffffff;
    goto addr_18000ac83_9;
}

uint32_t fun_180009730(void** rcx, void** rdx) {
    void** eax3;
    uint32_t esi4;
    void** edi5;
    void** eax6;
    void** rdx7;
    void** r8_8;
    void** eax9;
    void** eax10;
    void** rcx11;

    eax3 = *reinterpret_cast<void***>(rcx + 24);
    esi4 = 0;
    if ((*reinterpret_cast<unsigned char*>(&eax3) & 3) == 2 && (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 0x108 && (edi5 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx)) - reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 16))), !(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(edi5) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(edi5 == 0))))) {
        eax6 = fun_180006ca8(rcx, rdx);
        rdx7 = *reinterpret_cast<void***>(rcx + 16);
        r8_8 = edi5;
        *reinterpret_cast<int32_t*>(&r8_8 + 4) = 0;
        eax9 = fun_180006d30(eax6, rdx7, r8_8);
        if (eax9 != edi5) {
            *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) | 32);
            esi4 = 0xffffffff;
        } else {
            eax10 = *reinterpret_cast<void***>(rcx + 24);
            if (*reinterpret_cast<signed char*>(&eax10) < 0) {
                *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(eax10) & 0xfffffffd);
            }
        }
    }
    rcx11 = *reinterpret_cast<void***>(rcx + 16);
    *reinterpret_cast<void***>(rcx + 8) = reinterpret_cast<void**>(0);
    *reinterpret_cast<void***>(rcx) = rcx11;
    return esi4;
}

void fun_18000b238(void** rcx) {
    void** rcx2;

    if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 0x83 && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 8) {
        rcx2 = *reinterpret_cast<void***>(rcx + 16);
        fun_180005f00(rcx2);
        *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 0xfffffbf7);
        *reinterpret_cast<void***>(rcx) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rcx + 16) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rcx + 8) = reinterpret_cast<void**>(0);
    }
    return;
}

uint32_t fun_18000b17c(void** ecx);

uint32_t fun_18000b0b8(void** ecx, void** rdx, void** r8) {
    int64_t rbx4;
    int1_t cf5;
    int64_t rax6;
    int64_t rdi7;
    int64_t rax8;
    int64_t rsi9;
    void** rax10;
    void** rax11;
    void** rax12;
    uint32_t edi13;
    uint32_t eax14;
    uint32_t eax15;
    void** rax16;
    void** rax17;

    rbx4 = reinterpret_cast<int32_t>(ecx);
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rbx4) == 0xfffffffe)) {
        if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || ((cf5 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rbx4)) < reinterpret_cast<unsigned char>(g18001f0e8), !cf5) || (rax6 = rbx4, rdi7 = rbx4 >> 5, *reinterpret_cast<uint32_t*>(&rax8) = *reinterpret_cast<uint32_t*>(&rax6) & 31, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax8) + 4) = 0, rsi9 = rax8 * 88, (reinterpret_cast<uint32_t>(static_cast<int32_t>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi7 * 8)) + rsi9 + 8))) & 1) == 0))) {
            rax10 = fun_180003958();
            *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(0);
            rax11 = fun_1800039c8();
            *reinterpret_cast<void***>(rax11) = reinterpret_cast<void**>(9);
            fun_1800038fc();
        } else {
            fun_1800098a0(*reinterpret_cast<void***>(&rbx4), rdx, r8);
            if (!(*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + rdi7 * 8)) + rsi9 + 8) & 1)) {
                rax12 = fun_1800039c8();
                *reinterpret_cast<void***>(rax12) = reinterpret_cast<void**>(9);
                edi13 = 0xffffffff;
            } else {
                eax14 = fun_18000b17c(*reinterpret_cast<void***>(&rbx4));
                edi13 = eax14;
            }
            fun_180009a58(*reinterpret_cast<void***>(&rbx4), rdx, r8);
            eax15 = edi13;
            goto addr_18000b16d_8;
        }
    } else {
        rax16 = fun_180003958();
        *reinterpret_cast<void***>(rax16) = reinterpret_cast<void**>(0);
        rax17 = fun_1800039c8();
        *reinterpret_cast<void***>(rax17) = reinterpret_cast<void**>(9);
    }
    eax15 = 0xffffffff;
    addr_18000b16d_8:
    return eax15;
}

uint64_t fun_1800099e4(void** ecx) {
    int1_t cf2;
    int64_t rcx3;
    int64_t rcx4;
    int64_t rdx5;
    void** rax6;
    void** rax7;
    uint64_t rax8;
    void** rax9;
    void** rax10;

    if (!reinterpret_cast<int1_t>(ecx == 0xfffffffe)) {
        if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || ((cf2 = reinterpret_cast<unsigned char>(ecx) < reinterpret_cast<unsigned char>(g18001f0e8), !cf2) || (rcx3 = reinterpret_cast<int32_t>(ecx), *reinterpret_cast<uint32_t*>(&rcx4) = *reinterpret_cast<uint32_t*>(&rcx3) & 31, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx4) + 4) = 0, rdx5 = rcx4 * 88, (*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<uint64_t**>(0x18001d350 + (rcx3 >> 5) * 8)) + rdx5 + 8) & 1) == 0))) {
            rax6 = fun_180003958();
            *reinterpret_cast<void***>(rax6) = reinterpret_cast<void**>(0);
            rax7 = fun_1800039c8();
            *reinterpret_cast<void***>(rax7) = reinterpret_cast<void**>(9);
            fun_1800038fc();
        } else {
            rax8 = *reinterpret_cast<uint64_t*>(reinterpret_cast<int64_t>(*reinterpret_cast<uint64_t**>(0x18001d350 + (rcx3 >> 5) * 8)) + rdx5);
            goto addr_180009a53_5;
        }
    } else {
        rax9 = fun_180003958();
        *reinterpret_cast<void***>(rax9) = reinterpret_cast<void**>(0);
        rax10 = fun_1800039c8();
        *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(9);
    }
    rax8 = 0xffffffffffffffff;
    addr_180009a53_5:
    return rax8;
}

void** g18001d350;

int64_t fun_180009938(void** ecx);

uint32_t fun_18000b17c(void** ecx) {
    int64_t rdi2;
    uint64_t rax3;
    void** rax4;
    uint64_t rax5;
    uint64_t rax6;
    uint64_t rax7;
    int32_t eax8;
    void** ebx9;
    void** eax10;
    int64_t rdx11;
    int64_t rdx12;
    void** rdx13;
    uint32_t eax14;
    void*** r9_15;

    rdi2 = reinterpret_cast<int32_t>(ecx);
    rax3 = fun_1800099e4(*reinterpret_cast<void***>(&rdi2));
    if (rax3 == 0xffffffffffffffff || (((rax4 = g18001d350, reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rdi2) == 1)) && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rax4 + 0xb8)) & *reinterpret_cast<unsigned char*>(&rdi2) || reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rdi2) == 2) && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rax4 + 96)) & 1) && (rax5 = fun_1800099e4(2), rax6 = fun_1800099e4(1), rax6 == rax5) || (rax7 = fun_1800099e4(*reinterpret_cast<void***>(&rdi2)), eax8 = reinterpret_cast<int32_t>(CloseHandle(rax7)), !!eax8))) {
        ebx9 = reinterpret_cast<void**>(0);
    } else {
        eax10 = reinterpret_cast<void**>(GetLastError(rax7));
        ebx9 = eax10;
    }
    fun_180009938(*reinterpret_cast<void***>(&rdi2));
    rdx11 = rdi2;
    *reinterpret_cast<uint32_t*>(&rdx12) = *reinterpret_cast<uint32_t*>(&rdx11) & 31;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx12) + 4) = 0;
    rdx13 = reinterpret_cast<void**>(rdx12 * 88);
    *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(0x18001d350 + (rdi2 >> 5) * 8)) + reinterpret_cast<unsigned char>(rdx13)) + 8) = 0;
    if (!ebx9) {
        eax14 = 0;
    } else {
        fun_180003978(ebx9, rdx13, 0x18001d350, r9_15);
        eax14 = 0xffffffff;
    }
    return eax14;
}

struct s31 {
    signed char[2] pad2;
    uint32_t f2;
    uint32_t f6;
    uint16_t f10;
};

struct s32 {
    uint32_t f0;
    uint32_t f4;
};

uint32_t g180018378 = 24;

uint32_t g180018374 = 0xffffff81;

uint32_t g18001837c = 8;

uint32_t g180018370 = 0x80;

int32_t g180018384 = 0x7f;

int32_t g180018380 = 32;

int32_t fun_18000ba58(struct s31* rcx, struct s32* rdx, unsigned char* r8) {
    void* rsp4;
    void* rbp5;
    void* rsp6;
    uint64_t rax7;
    uint64_t v8;
    uint32_t eax9;
    uint32_t v10;
    int64_t v11;
    uint32_t eax12;
    uint32_t edi13;
    struct s32* v14;
    void* r14_15;
    int64_t v16;
    uint32_t eax17;
    uint32_t v18;
    uint32_t eax19;
    uint32_t r13d20;
    uint32_t v21;
    uint32_t edx22;
    uint32_t eax23;
    int64_t r10_24;
    uint32_t r8d25;
    int64_t r11_26;
    uint32_t ecx27;
    uint32_t v28;
    uint32_t ecx29;
    void* rdx30;
    uint64_t r8_31;
    void** rcx32;
    uint32_t ecx33;
    int64_t rdx34;
    uint32_t edx35;
    uint32_t eax36;
    int64_t r8_37;
    uint32_t ecx38;
    int64_t r11_39;
    int64_t rax40;
    int64_t rdx41;
    uint32_t ecx42;
    void* rcx43;
    uint32_t r8d44;
    void* rax45;
    uint32_t ecx46;
    uint32_t eax47;
    uint32_t r10d48;
    uint32_t edx49;
    uint32_t eax50;
    uint32_t eax51;
    int32_t r11d52;
    uint32_t ecx53;
    uint32_t r15d54;
    int32_t r8d55;
    uint32_t r10d56;
    uint32_t edi57;
    uint32_t r13d58;
    uint32_t ecx59;
    uint32_t ecx60;
    uint32_t v61;
    uint64_t r10_62;
    uint64_t rdi63;
    int64_t r9_64;
    void* rdx65;
    uint32_t r13d66;
    uint32_t edi67;
    uint32_t r9d68;
    uint32_t ecx69;
    uint32_t ecx70;
    uint32_t v71;
    uint64_t r9_72;
    uint64_t rdi73;
    int64_t r8_74;
    void* rdx75;
    int32_t r8d76;
    void* r11_77;
    uint32_t r9d78;
    uint32_t edx79;
    uint32_t eax80;
    uint32_t eax81;
    int32_t r13d82;
    uint32_t ecx83;
    uint32_t edi84;
    uint32_t r14d85;
    uint32_t r10d86;
    uint32_t ecx87;
    uint32_t ecx88;
    void* rdx89;
    uint32_t v90;
    uint32_t v91;
    uint64_t r10_92;
    uint64_t rdi93;
    void* r14_94;
    uint64_t r8_95;
    int64_t r9_96;
    int64_t r8_97;
    uint32_t edx98;
    uint32_t eax99;
    int64_t r9_100;
    uint32_t r11d101;
    uint32_t r12d102;
    int32_t eax103;
    uint32_t r8d104;
    uint64_t rcx105;
    struct s0* rax106;
    uint32_t ecx107;
    int64_t rcx108;
    void* rdx109;
    void* r8_110;
    void** rcx111;
    uint32_t eax112;
    uint32_t r9d113;
    uint32_t edx114;
    uint32_t eax115;
    uint32_t eax116;
    int32_t r10d117;
    uint32_t ecx118;
    uint32_t r11d119;
    uint32_t r13d120;
    uint32_t r15d121;
    uint32_t ecx122;
    uint32_t ecx123;
    uint64_t r10_124;
    uint64_t r8_125;
    int64_t r9_126;
    void* rdx127;
    uint32_t ecx128;
    int64_t rdx129;
    uint32_t edx130;
    uint32_t eax131;
    int64_t r10_132;
    uint32_t ecx133;
    int64_t r13_134;
    int64_t rax135;
    int64_t rdx136;
    uint32_t ecx137;
    uint32_t r8d138;
    void* rcx139;
    int32_t eax140;
    uint64_t rdx141;
    int64_t rax142;
    uint32_t r8d143;
    int32_t eax144;
    uint64_t rdx145;
    int64_t rax146;
    uint32_t r8d147;

    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8);
    rbp5 = rsp4;
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp4) - 96);
    rax7 = g1800170a0;
    v8 = rax7 ^ reinterpret_cast<uint64_t>(rsp6);
    eax9 = rcx->f10;
    v10 = eax9 & 0x8000;
    *reinterpret_cast<uint32_t*>(&v11) = rcx->f6;
    eax12 = rcx->f2;
    edi13 = (eax9 & 0x7fff) - 0x3fff;
    v14 = rdx;
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v11) + 4) = eax12;
    *reinterpret_cast<int32_t*>(&r14_15) = 3;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_15) + 4) = 0;
    if (edi13 != 0xffffc001) {
        v16 = v11;
        eax17 = g180018378;
        v18 = edi13;
        eax19 = eax17 - 1;
        r13d20 = 0;
        v21 = eax19;
        __asm__("cdq ");
        edx22 = *reinterpret_cast<uint32_t*>(&rdx) & 31;
        eax23 = eax19 + 1 + edx22;
        *reinterpret_cast<int32_t*>(&r10_24) = reinterpret_cast<int32_t>(eax23) >> 5;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_24) + 4) = 0;
        r8d25 = 31 - ((eax23 & 31) - edx22);
        r11_26 = *reinterpret_cast<int32_t*>(&r10_24);
        ecx27 = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_26 * 4 - 24);
        v28 = r8d25;
        if (!static_cast<int1_t>(ecx27 >> r8d25)) {
            addr_18000bbeb_3:
            ecx29 = r8d25;
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_26 * 4 - 24) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_26 * 4 - 24) & 0xffffffff << *reinterpret_cast<unsigned char*>(&ecx29);
            rdx30 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r10_24 + 1)));
            if (reinterpret_cast<int64_t>(rdx30) < reinterpret_cast<int64_t>(3)) {
                r8_31 = 3 - reinterpret_cast<uint64_t>(rdx30);
                rcx32 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) - 24 + reinterpret_cast<uint64_t>(rdx30) * 4);
                *reinterpret_cast<uint32_t*>(&rdx30) = 0;
                fun_180003c80(rcx32, 0, r8_31 << 2);
                rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
            }
        } else {
            ecx33 = r8d25;
            rdx34 = *reinterpret_cast<int32_t*>(&r10_24);
            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx34 * 4 - 24) & reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx33)))) {
                addr_18000bb79_6:
                __asm__("cdq ");
                edx35 = *reinterpret_cast<uint32_t*>(&rdx34) & 31;
                eax36 = v21 + edx35;
                *reinterpret_cast<int32_t*>(&r8_37) = reinterpret_cast<int32_t>(eax36) >> 5;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_37) + 4) = 0;
                ecx38 = 31 - ((eax36 & 31) - edx35);
                r11_39 = *reinterpret_cast<int32_t*>(&r8_37);
                *reinterpret_cast<uint32_t*>(&rax40) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_39 * 4 - 24);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax40) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rdx41) = 1 << *reinterpret_cast<unsigned char*>(&ecx38);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx41) + 4) = 0;
                ecx42 = static_cast<uint32_t>(rax40 + rdx41);
                if (ecx42 < *reinterpret_cast<uint32_t*>(&rax40) || ecx42 < *reinterpret_cast<uint32_t*>(&rdx41)) {
                    r13d20 = 1;
                    goto addr_18000bbad_8;
                }
            } else {
                rcx43 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r10_24 + 1)));
                while (reinterpret_cast<int64_t>(rcx43) < reinterpret_cast<int64_t>(3)) {
                    if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rcx43) * 4 - 24)) 
                        goto addr_18000bb79_6;
                    rcx43 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx43) + 1);
                }
                goto addr_18000bb77_13;
            }
        }
    } else {
        r8d44 = 0;
        *reinterpret_cast<uint32_t*>(&rax45) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax45) + 4) = 0;
        do {
            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) * 4 - 24)) 
                goto addr_18000baef_16;
            rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rax45) + 1);
        } while (reinterpret_cast<int64_t>(rax45) < reinterpret_cast<int64_t>(3));
        goto addr_18000baea_18;
    }
    if (r13d20) {
        ++edi13;
    }
    ecx46 = g180018374;
    *reinterpret_cast<uint32_t*>(&rax45) = ecx46 - g180018378;
    if (reinterpret_cast<int32_t>(edi13) >= *reinterpret_cast<int32_t*>(&rax45)) {
        if (reinterpret_cast<int32_t>(edi13) > reinterpret_cast<int32_t>(ecx46)) {
            eax47 = g18001837c;
            r10d48 = g180018370;
            __asm__("cdq ");
            edx49 = *reinterpret_cast<uint32_t*>(&rdx30) & 31;
            eax50 = eax47 + edx49;
            eax51 = (eax50 & 31) - edx49;
            r11d52 = reinterpret_cast<int32_t>(eax50) >> 5;
            ecx53 = eax51;
            r15d54 = reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx53)));
            if (reinterpret_cast<int32_t>(edi13) < reinterpret_cast<int32_t>(r10d48)) {
                r8d55 = g180018384;
                __asm__("btr dword [rbp-0x18], 0x1f");
                r10d56 = 0;
                r8d44 = r8d55 + edi13;
                edi57 = eax51;
                r13d58 = 32 - eax51;
                do {
                    ecx59 = edi57;
                    ecx60 = r13d58;
                    *reinterpret_cast<uint32_t*>(&rax45) = v61 >> *reinterpret_cast<signed char*>(&ecx59) | r10d56;
                    r10d56 = (v61 & r15d54) << *reinterpret_cast<unsigned char*>(&ecx60);
                    r14_15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_15) - 1);
                } while (r14_15);
                r10_62 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r11d52));
                *reinterpret_cast<int32_t*>(&rdi63) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r14_15) + 2);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi63) + 4) = 0;
                r9_64 = reinterpret_cast<int64_t>(-r10_62);
                do {
                    if (reinterpret_cast<int64_t>(rdi63) < reinterpret_cast<int64_t>(r10_62)) {
                        *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdi63 * 4 - 24) = 0;
                    } else {
                        rdx65 = reinterpret_cast<void*>(rdi63 << 2);
                        rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx65) + r9_64 * 4);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx65) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) + 0xffffffffffffffe8);
                    }
                    --rdi63;
                } while (reinterpret_cast<int64_t>(rdi63) >= reinterpret_cast<int64_t>(0));
            } else {
                v11 = 0;
                __asm__("bts dword [rbp-0x18], 0x1f");
                r13d66 = 32 - eax51;
                edi67 = eax51;
                r9d68 = 0;
                do {
                    ecx69 = edi67;
                    ecx70 = r13d66;
                    *reinterpret_cast<uint32_t*>(&rax45) = v71 >> *reinterpret_cast<signed char*>(&ecx69) | r9d68;
                    r9d68 = (r15d54 & v71) << *reinterpret_cast<unsigned char*>(&ecx70);
                    r14_15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_15) - 1);
                } while (r14_15);
                r9_72 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r11d52));
                *reinterpret_cast<int32_t*>(&rdi73) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r14_15) + 2);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi73) + 4) = 0;
                r8_74 = reinterpret_cast<int64_t>(-r9_72);
                do {
                    if (reinterpret_cast<int64_t>(rdi73) < reinterpret_cast<int64_t>(r9_72)) {
                        *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdi73 * 4 - 24) = 0;
                    } else {
                        rdx75 = reinterpret_cast<void*>(rdi73 << 2);
                        rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx75) + r8_74 * 4);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx75) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) + 0xffffffffffffffe8);
                    }
                    --rdi73;
                } while (reinterpret_cast<int64_t>(rdi73) >= reinterpret_cast<int64_t>(0));
                r8d76 = g180018384;
                r8d44 = r8d76 + r10d48;
            }
        } else {
            v11 = v16;
            __asm__("cdq ");
            r11_77 = reinterpret_cast<void*>(3);
            r9d78 = 0;
            edx79 = *reinterpret_cast<uint32_t*>(&rdx30) & 31;
            eax80 = ecx46 - v18 + edx79;
            eax81 = (eax80 & 31) - edx79;
            r13d82 = reinterpret_cast<int32_t>(eax80) >> 5;
            ecx83 = eax81;
            edi84 = eax81;
            r14d85 = 32 - ecx83;
            r10d86 = reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx83)));
            do {
                ecx87 = edi84;
                ecx88 = r14d85;
                *reinterpret_cast<uint32_t*>(&rdx89) = v90 & r10d86;
                v91 = v90 >> *reinterpret_cast<signed char*>(&ecx87) | r9d78;
                r9d78 = *reinterpret_cast<uint32_t*>(&rdx89) << *reinterpret_cast<unsigned char*>(&ecx88);
                r11_77 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r11_77) - 1);
            } while (r11_77);
            r10_92 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r13d82));
            *reinterpret_cast<int32_t*>(&rdi93) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r11_77) + 2);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi93) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r14_94) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r11_77) + 3);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_94) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_95) = *reinterpret_cast<int32_t*>(&rdi93);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_95) + 4) = 0;
            r9_96 = reinterpret_cast<int64_t>(-r10_92);
            do {
                if (reinterpret_cast<int64_t>(r8_95) < reinterpret_cast<int64_t>(r10_92)) {
                    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r8_95 * 4 - 24) = 0;
                } else {
                    rdx89 = reinterpret_cast<void*>(r8_95 << 2);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx89) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + (reinterpret_cast<uint64_t>(rdx89) + r9_96 * 4) - 24);
                }
                --r8_95;
            } while (reinterpret_cast<int64_t>(r8_95) >= reinterpret_cast<int64_t>(0));
            *reinterpret_cast<uint32_t*>(&r8_97) = v21;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_97) + 4) = 0;
            __asm__("cdq ");
            edx98 = *reinterpret_cast<uint32_t*>(&rdx89) & 31;
            eax99 = static_cast<int32_t>(r8_97 + 1) + edx98;
            *reinterpret_cast<int32_t*>(&r9_100) = reinterpret_cast<int32_t>(eax99) >> 5;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_100) + 4) = 0;
            r11d101 = 31 - ((eax99 & 31) - edx98);
            if (!static_cast<int1_t>(*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + *reinterpret_cast<int32_t*>(&r9_100) * 4 - 24) >> r11d101)) 
                goto addr_18000bdbf_47; else 
                goto addr_18000bd27_48;
        }
    } else {
        v11 = 0;
        r8d44 = 0;
    }
    addr_18000bfa2_50:
    rdx = v14;
    addr_18000bfa6_51:
    r12d102 = 31 - g18001837c;
    eax103 = g180018380;
    r8d104 = r8d44 << *reinterpret_cast<unsigned char*>(&r12d102) | *reinterpret_cast<uint32_t*>(&rax45) - (*reinterpret_cast<uint32_t*>(&rax45) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax45) < *reinterpret_cast<uint32_t*>(&rax45) + reinterpret_cast<uint1_t>(!!v10))) & 0x80000000 | *reinterpret_cast<uint32_t*>(&v11);
    if (eax103 != 64) {
        if (eax103 == 32) {
            rdx->f0 = r8d104;
        }
    } else {
        rdx->f4 = r8d104;
        rdx->f0 = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v11) + 4);
    }
    rcx105 = v8 ^ reinterpret_cast<uint64_t>(rsp6);
    rax106 = fun_180002f40(rcx105, rcx105);
    return *reinterpret_cast<int32_t*>(&rax106);
    addr_18000bdbf_47:
    ecx107 = r11d101;
    rcx108 = *reinterpret_cast<int32_t*>(&r9_100);
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rcx108 * 4 - 24) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rcx108 * 4 - 24) & 0xffffffff << *reinterpret_cast<unsigned char*>(&ecx107);
    rdx109 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r9_100 + 1)));
    if (reinterpret_cast<int64_t>(rdx109) < reinterpret_cast<int64_t>(r14_94)) {
        r8_110 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_94) - reinterpret_cast<uint64_t>(rdx109));
        rcx111 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) - 24 + reinterpret_cast<uint64_t>(rdx109) * 4);
        *reinterpret_cast<uint32_t*>(&rdx109) = 0;
        fun_180003c80(rcx111, 0, reinterpret_cast<uint64_t>(r8_110) << 2);
        rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
    }
    eax112 = g18001837c;
    r9d113 = 0;
    __asm__("cdq ");
    edx114 = *reinterpret_cast<uint32_t*>(&rdx109) & 31;
    eax115 = eax112 + 1 + edx114;
    eax116 = (eax115 & 31) - edx114;
    r10d117 = reinterpret_cast<int32_t>(eax115) >> 5;
    ecx118 = eax116;
    r11d119 = eax116;
    r13d120 = 32 - eax116;
    r15d121 = reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx118)));
    do {
        ecx122 = r11d119;
        ecx123 = r13d120;
        *reinterpret_cast<uint32_t*>(&rax45) = v91 >> *reinterpret_cast<signed char*>(&ecx122) | r9d113;
        r9d113 = (v91 & r15d121) << *reinterpret_cast<unsigned char*>(&ecx123);
        r14_94 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_94) - 1);
    } while (r14_94);
    r10_124 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r10d117));
    r8_125 = rdi93;
    r9_126 = reinterpret_cast<int64_t>(-r10_124);
    do {
        if (reinterpret_cast<int64_t>(r8_125) < reinterpret_cast<int64_t>(r10_124)) {
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r8_125 * 4 - 24) = 0;
        } else {
            rdx127 = reinterpret_cast<void*>(r8_125 << 2);
            rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx127) + r9_126 * 4);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx127) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) + 0xffffffffffffffe8);
        }
        --r8_125;
    } while (reinterpret_cast<int64_t>(r8_125) >= reinterpret_cast<int64_t>(0));
    r8d44 = 0;
    goto addr_18000bfa2_50;
    addr_18000bd27_48:
    ecx128 = r11d101;
    rdx129 = *reinterpret_cast<int32_t*>(&r9_100);
    if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx129 * 4 - 24) & reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx128)))) {
        addr_18000bd53_65:
        __asm__("cdq ");
        edx130 = *reinterpret_cast<uint32_t*>(&rdx129) & 31;
        eax131 = *reinterpret_cast<uint32_t*>(&r8_97) + edx130;
        *reinterpret_cast<int32_t*>(&r10_132) = reinterpret_cast<int32_t>(eax131) >> 5;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_132) + 4) = 0;
        ecx133 = 31 - ((eax131 & 31) - edx130);
        r13_134 = *reinterpret_cast<int32_t*>(&r10_132);
        *reinterpret_cast<uint32_t*>(&rax135) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r13_134 * 4 - 24);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax135) + 4) = 0;
        *reinterpret_cast<uint32_t*>(&rdx136) = 1 << *reinterpret_cast<unsigned char*>(&ecx133);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx136) + 4) = 0;
        ecx137 = 0;
        r8d138 = static_cast<uint32_t>(rax135 + rdx136);
        if (r8d138 < *reinterpret_cast<uint32_t*>(&rax135) || r8d138 < *reinterpret_cast<uint32_t*>(&rdx136)) {
            ecx137 = 1;
        }
    } else {
        rcx139 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r9_100 + 1)));
        while (reinterpret_cast<int64_t>(rcx139) < reinterpret_cast<int64_t>(r14_94)) {
            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rcx139) * 4 - 24)) 
                goto addr_18000bd53_65;
            rcx139 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx139) + 1);
        }
        goto addr_18000bd51_71;
    }
    eax140 = static_cast<int32_t>(r10_132 - 1);
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r13_134 * 4 - 24) = r8d138;
    rdx141 = reinterpret_cast<uint64_t>(static_cast<int64_t>(eax140));
    if (eax140 >= 0) {
        do {
            if (!ecx137) 
                goto addr_18000bdbf_47;
            *reinterpret_cast<uint32_t*>(&rax142) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx141 * 4 - 24);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax142) + 4) = 0;
            ecx137 = 0;
            r8d143 = static_cast<uint32_t>(rax142 + 1);
            if (r8d143 < *reinterpret_cast<uint32_t*>(&rax142) || r8d143 < 1) {
                ecx137 = 1;
            }
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx141 * 4 - 24) = r8d143;
            --rdx141;
        } while (reinterpret_cast<int64_t>(rdx141) >= reinterpret_cast<int64_t>(0));
        goto addr_18000bdbf_47;
    }
    addr_18000bd51_71:
    goto addr_18000bdbf_47;
    addr_18000bbad_8:
    eax144 = static_cast<int32_t>(r8_37 - 1);
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_39 * 4 - 24) = ecx42;
    rdx145 = reinterpret_cast<uint64_t>(static_cast<int64_t>(eax144));
    if (eax144 >= 0) {
        do {
            if (!r13d20) 
                break;
            *reinterpret_cast<uint32_t*>(&rax146) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx145 * 4 - 24);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax146) + 4) = 0;
            r13d20 = 0;
            r8d147 = static_cast<uint32_t>(rax146 + 1);
            if (r8d147 < *reinterpret_cast<uint32_t*>(&rax146) || r8d147 < 1) {
                r13d20 = 1;
            }
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx145 * 4 - 24) = r8d147;
            --rdx145;
        } while (reinterpret_cast<int64_t>(rdx145) >= reinterpret_cast<int64_t>(0));
    }
    r8d25 = v28;
    r11_26 = *reinterpret_cast<int32_t*>(&r10_24);
    goto addr_18000bbeb_3;
    addr_18000bb77_13:
    goto addr_18000bbeb_3;
    addr_18000baef_16:
    v11 = 0;
    goto addr_18000bfa6_51;
    addr_18000baea_18:
    goto addr_18000bfa6_51;
}

struct s33 {
    uint32_t f0;
    uint32_t f4;
    uint32_t f8;
    int16_t f10;
};

struct s34 {
    int32_t f0;
    int32_t f4;
};

struct s35 {
    int32_t f0;
    int32_t f4;
};

void fun_18000d4ac(signed char* rcx, uint16_t edx, struct s33* r8) {
    struct s33* r10_4;
    struct s34* rdi5;
    signed char* rbp6;
    int32_t ebx7;
    int64_t r11_8;
    uint32_t r8d9;
    uint32_t r9d10;
    struct s35* rsi11;
    int32_t* rdi12;
    uint32_t r14d13;
    int64_t rdi14;
    uint32_t r9d15;
    uint32_t edx16;
    uint32_t r8d17;
    int64_t rdx18;
    int64_t r8_19;
    uint32_t eax20;
    uint32_t r9d21;
    int64_t rcx22;
    uint32_t v23;
    uint32_t eax24;
    uint32_t ecx25;
    uint32_t ecx26;
    uint64_t rax27;
    uint32_t v28;
    int64_t r11_29;
    uint32_t r9d30;
    int64_t rdx31;
    uint32_t eax32;
    int64_t rcx33;
    uint32_t eax34;
    uint32_t ecx35;
    uint32_t r8d36;
    uint32_t ecx37;
    uint32_t r9d38;
    uint32_t edx39;
    uint32_t r9d40;
    uint32_t r8d41;
    uint32_t ecx42;

    r8->f0 = 0;
    r8->f4 = 0;
    r8->f8 = 0;
    r10_4 = r8;
    *reinterpret_cast<uint16_t*>(&rdi5) = edx;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi5) + 4) = 0;
    rbp6 = rcx;
    ebx7 = 0x404e;
    if (edx) {
        *reinterpret_cast<uint32_t*>(&r11_8) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r11_8) + 4) = 0;
        r8d9 = 0;
        r9d10 = 0;
        do {
            rdi5->f0 = rsi11->f0;
            rdi12 = &rdi5->f4;
            r14d13 = r10_4->f8;
            *rdi12 = rsi11->f4;
            rdi14 = reinterpret_cast<int64_t>(rdi12 + 1);
            r9d15 = r9d10 + r9d10 | r8d9 >> 31;
            edx16 = static_cast<uint32_t>(r11_8 + r11_8);
            r8d17 = r8d9 + r8d9 | *reinterpret_cast<uint32_t*>(&r11_8) >> 31;
            *reinterpret_cast<uint32_t*>(&rdx18) = edx16 + edx16;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx18) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&r8_19) = r8d17 + r8d17 | edx16 >> 31;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_19) + 4) = 0;
            eax20 = 0;
            r9d21 = r9d15 + r9d15 | r8d17 >> 31;
            *reinterpret_cast<uint32_t*>(&rcx22) = v23;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx22) + 4) = 0;
            r10_4->f0 = *reinterpret_cast<uint32_t*>(&rdx18);
            *reinterpret_cast<uint32_t*>(&rsi11) = static_cast<uint32_t>(rdx18 + rcx22);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi11) + 4) = 0;
            r10_4->f4 = *reinterpret_cast<uint32_t*>(&r8_19);
            r10_4->f8 = r9d21;
            if (*reinterpret_cast<uint32_t*>(&rsi11) < *reinterpret_cast<uint32_t*>(&rdx18) || *reinterpret_cast<uint32_t*>(&rsi11) < *reinterpret_cast<uint32_t*>(&rcx22)) {
                eax20 = 1;
            }
            r10_4->f0 = *reinterpret_cast<uint32_t*>(&rsi11);
            if (eax20) {
                eax24 = *reinterpret_cast<uint32_t*>(&r8_19);
                *reinterpret_cast<uint32_t*>(&r8_19) = *reinterpret_cast<uint32_t*>(&r8_19) + 1;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_19) + 4) = 0;
                ecx25 = 0;
                if (*reinterpret_cast<uint32_t*>(&r8_19) < eax24 || *reinterpret_cast<uint32_t*>(&r8_19) < 1) {
                    ecx25 = 1;
                }
                r10_4->f4 = *reinterpret_cast<uint32_t*>(&r8_19);
                if (ecx25) {
                    ++r9d21;
                    r10_4->f8 = r9d21;
                }
            }
            ecx26 = 0;
            rax27 = v28 >> 32;
            *reinterpret_cast<uint32_t*>(&r11_29) = static_cast<uint32_t>(r8_19 + rax27);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r11_29) + 4) = 0;
            if (*reinterpret_cast<uint32_t*>(&r11_29) < *reinterpret_cast<uint32_t*>(&r8_19) || *reinterpret_cast<uint32_t*>(&r11_29) < *reinterpret_cast<uint32_t*>(&rax27)) {
                ecx26 = 1;
            }
            r10_4->f4 = *reinterpret_cast<uint32_t*>(&r11_29);
            if (ecx26) {
                ++r9d21;
                r10_4->f8 = r9d21;
            }
            r9d30 = r9d21 + r14d13;
            *reinterpret_cast<uint32_t*>(&rdx31) = static_cast<uint32_t>(reinterpret_cast<int64_t>(rsi11) + reinterpret_cast<int64_t>(rsi11));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx31) + 4) = 0;
            r9d10 = r9d30 + r9d30 | *reinterpret_cast<uint32_t*>(&r11_29) >> 31;
            r10_4->f0 = *reinterpret_cast<uint32_t*>(&rdx31);
            r10_4->f8 = r9d10;
            r8d9 = static_cast<uint32_t>(r11_29 + r11_29) | *reinterpret_cast<uint32_t*>(&rsi11) >> 31;
            eax32 = 0;
            r10_4->f4 = r8d9;
            *reinterpret_cast<uint32_t*>(&rcx33) = reinterpret_cast<uint32_t>(static_cast<int32_t>(*rbp6));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx33) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&r11_8) = static_cast<uint32_t>(rdx31 + rcx33);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r11_8) + 4) = 0;
            if (*reinterpret_cast<uint32_t*>(&r11_8) < *reinterpret_cast<uint32_t*>(&rdx31) || *reinterpret_cast<uint32_t*>(&r11_8) < *reinterpret_cast<uint32_t*>(&rcx33)) {
                eax32 = 1;
            }
            r10_4->f0 = *reinterpret_cast<uint32_t*>(&r11_8);
            if (eax32) {
                eax34 = r8d9;
                ++r8d9;
                ecx35 = 0;
                if (r8d9 < eax34 || r8d9 < 1) {
                    ecx35 = 1;
                }
                r10_4->f4 = r8d9;
                if (ecx35) {
                    ++r9d10;
                    r10_4->f8 = r9d10;
                }
            }
            ++rbp6;
            r10_4->f4 = r8d9;
            r10_4->f8 = r9d10;
            *reinterpret_cast<uint16_t*>(&rdi5) = reinterpret_cast<uint16_t>(*reinterpret_cast<int32_t*>(&rdi14) - 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi5) + 4) = 0;
        } while (*reinterpret_cast<uint16_t*>(&rdi5));
    }
    if (!r10_4->f8) {
        r8d36 = r10_4->f4;
        do {
            ecx37 = r10_4->f0 >> 16;
            r9d38 = r8d36 >> 16;
            r10_4->f0 = r10_4->f0 << 16;
            r8d36 = ecx37 | r8d36 << 16;
            *reinterpret_cast<int16_t*>(&ebx7) = reinterpret_cast<int16_t>(*reinterpret_cast<int16_t*>(&ebx7) - 16);
        } while (!r9d38);
        r10_4->f4 = r8d36;
        r10_4->f8 = r9d38;
    }
    edx39 = r10_4->f8;
    if (!(0x8000 & edx39)) {
        r9d40 = r10_4->f0;
        r8d41 = r10_4->f4;
        do {
            ecx42 = r8d41 >> 31;
            r8d41 = r8d41 + r8d41 | r9d40 >> 31;
            edx39 = edx39 + edx39 | ecx42;
            *reinterpret_cast<int16_t*>(&ebx7) = reinterpret_cast<int16_t>(*reinterpret_cast<int16_t*>(&ebx7) - 1);
            r9d40 = r9d40 + r9d40;
        } while (!(0x8000 & edx39));
        r10_4->f0 = r9d40;
        r10_4->f4 = r8d41;
        r10_4->f8 = edx39;
    }
    *reinterpret_cast<int16_t*>(reinterpret_cast<int64_t>(r10_4) + 10) = *reinterpret_cast<int16_t*>(&ebx7);
    return;
}

struct s36 {
    int32_t f0;
    int32_t f4;
};

struct s37 {
    int32_t f0;
    int32_t f4;
};

struct s0* fun_18000dba0(uint64_t rcx, struct s36* rdx, struct s37* r8, void* r9);

struct s38 {
    signed char[4] pad4;
    int32_t f4;
    signed char[8] pad16;
    void*** f16;
};

void** fun_18000da04(void** rcx, void* rdx, void** r8d, struct s38* r9);

struct s39 {
    int32_t f0;
    void* f4;
};

int64_t fun_18000cfbc(void** rcx, void* rdx, void** r8d, struct s39* r9);

struct s0* fun_18000d120(uint64_t* rcx, void** rdx, void* r8, void** r9d) {
    void* rsp5;
    uint64_t rax6;
    uint64_t rcx7;
    void* rsp8;
    void** rax9;
    void* rsp10;
    void* rdx11;
    uint64_t rax12;
    int32_t v13;
    void* rcx14;
    int32_t v15;
    void* v16;
    void** eax17;
    uint64_t rcx18;
    struct s0* rax19;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 0x78);
    rax6 = g1800170a0;
    rcx7 = *rcx;
    fun_18000dba0(rcx7, reinterpret_cast<uint64_t>(rsp5) + 48, reinterpret_cast<uint64_t>(rsp5) + 72, 22);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8);
    if (!rdx || !r8) {
        rax9 = fun_1800039c8();
        *reinterpret_cast<void***>(rax9) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        rsp10 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8 - 8 + 8);
    } else {
        rdx11 = reinterpret_cast<void*>(0xffffffffffffffff);
        if (r8 != 0xffffffffffffffff) {
            *reinterpret_cast<int32_t*>(&rax12) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax12) + 4) = 0;
            *reinterpret_cast<unsigned char*>(&rax12) = reinterpret_cast<uint1_t>(v13 == 45);
            rdx11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - rax12);
        }
        *reinterpret_cast<int32_t*>(&rcx14) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx14) + 4) = 0;
        *reinterpret_cast<unsigned char*>(&rcx14) = reinterpret_cast<uint1_t>(v15 == 45);
        eax17 = fun_18000da04(reinterpret_cast<int64_t>(rcx14) + reinterpret_cast<unsigned char>(rdx), rdx11, reinterpret_cast<int32_t>(v16) + reinterpret_cast<unsigned char>(r9d), reinterpret_cast<uint64_t>(rsp8) + 48);
        rsp10 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
        if (!eax17) {
            fun_18000cfbc(rdx, r8, r9d, reinterpret_cast<uint64_t>(rsp10) + 48);
            rsp10 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp10) - 8 + 8);
        } else {
            *reinterpret_cast<void***>(rdx) = reinterpret_cast<void**>(0);
        }
    }
    rcx18 = rax6 ^ reinterpret_cast<uint64_t>(rsp5) ^ reinterpret_cast<uint64_t>(rsp10);
    rax19 = fun_180002f40(rcx18, rcx18);
    return rax19;
}

int64_t fun_18000ccc8(void** rcx, void* rdx, void** r8d, void** r9);

struct s0* fun_18000d1f4(uint64_t* rcx, void** rdx, void* r8, void** r9d) {
    void* rsp5;
    uint64_t rax6;
    uint64_t v7;
    uint64_t rcx8;
    void* rdi9;
    void** rsi10;
    void** ebp11;
    void* rsp12;
    void** rax13;
    void* rsp14;
    void* rax15;
    int32_t v16;
    void* rdx17;
    void** rbx18;
    void** eax19;
    void** eax20;
    void* v21;
    void** r9_22;
    int32_t v23;
    void* v24;
    uint64_t rcx25;
    struct s0* rax26;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 0x80);
    rax6 = g1800170a0;
    v7 = rax6 ^ reinterpret_cast<uint64_t>(rsp5);
    rcx8 = *rcx;
    rdi9 = r8;
    rsi10 = rdx;
    ebp11 = r9d;
    fun_18000dba0(rcx8, reinterpret_cast<uint64_t>(rsp5) + 64, reinterpret_cast<uint64_t>(rsp5) + 88, 22);
    rsp12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8);
    if (!rsi10 || !rdi9) {
        rax13 = fun_1800039c8();
        *reinterpret_cast<void***>(rax13) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        rsp14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp12) - 8 + 8 - 8 + 8);
    } else {
        *reinterpret_cast<int32_t*>(&rax15) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax15) + 4) = 0;
        *reinterpret_cast<unsigned char*>(&rax15) = reinterpret_cast<uint1_t>(v16 == 45);
        rdx17 = reinterpret_cast<void*>(0xffffffffffffffff);
        rbx18 = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rax15) + reinterpret_cast<unsigned char>(rsi10));
        if (rdi9 != 0xffffffffffffffff) {
            rdx17 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdi9) - reinterpret_cast<uint64_t>(rax15));
        }
        eax19 = fun_18000da04(rbx18, rdx17, ebp11, reinterpret_cast<uint64_t>(rsp12) + 64);
        rsp14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp12) - 8 + 8);
        if (!eax19) {
            eax20 = reinterpret_cast<void**>(reinterpret_cast<int32_t>(v21) - 1);
            if (reinterpret_cast<signed char>(eax20) < reinterpret_cast<signed char>(0xfffffffc) || reinterpret_cast<signed char>(eax20) >= reinterpret_cast<signed char>(ebp11)) {
                *reinterpret_cast<int32_t*>(&r9_22) = v23;
                *reinterpret_cast<int32_t*>(&r9_22 + 4) = 0;
                fun_18000ccc8(rsi10, rdi9, ebp11, r9_22);
                rsp14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp14) - 8 + 8);
            } else {
                if (reinterpret_cast<signed char>(reinterpret_cast<int32_t>(v24) - 1) < reinterpret_cast<signed char>(eax20)) {
                    do {
                        ++rbx18;
                    } while (*reinterpret_cast<void***>(rbx18));
                    *reinterpret_cast<void***>(rbx18 + 0xfffffffffffffffe) = *reinterpret_cast<void***>(rbx18);
                }
                fun_18000cfbc(rsi10, rdi9, ebp11, reinterpret_cast<uint64_t>(rsp14) + 64);
                rsp14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp14) - 8 + 8);
            }
        } else {
            *reinterpret_cast<void***>(rsi10) = reinterpret_cast<void**>(0);
        }
    }
    rcx25 = v7 ^ reinterpret_cast<uint64_t>(rsp14);
    rax26 = fun_180002f40(rcx25, rcx25);
    return rax26;
}

struct s0* fun_18000cec4(uint64_t* rcx, void** rdx, void* r8, void** r9d) {
    void* rsp5;
    uint64_t rax6;
    uint64_t rcx7;
    int64_t rsi8;
    void* rsp9;
    void** rax10;
    void* rsp11;
    void* rdx12;
    uint64_t rax13;
    int32_t v14;
    uint64_t rax15;
    void* rax16;
    int32_t v17;
    void* rcx18;
    void** eax19;
    void** r9_20;
    int32_t v21;
    uint64_t rcx22;
    struct s0* rax23;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 0x88);
    rax6 = g1800170a0;
    rcx7 = *rcx;
    *reinterpret_cast<void***>(&rsi8) = r9d;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi8) + 4) = 0;
    fun_18000dba0(rcx7, reinterpret_cast<uint64_t>(rsp5) + 64, reinterpret_cast<uint64_t>(rsp5) + 88, 22);
    rsp9 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8);
    if (!rdx || !r8) {
        rax10 = fun_1800039c8();
        *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        rsp11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp9) - 8 + 8 - 8 + 8);
    } else {
        rdx12 = reinterpret_cast<void*>(0xffffffffffffffff);
        if (r8 != 0xffffffffffffffff) {
            *reinterpret_cast<int32_t*>(&rax13) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax13) + 4) = 0;
            *reinterpret_cast<unsigned char*>(&rax13) = reinterpret_cast<uint1_t>(v14 == 45);
            *reinterpret_cast<int32_t*>(&rax15) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax15) + 4) = 0;
            *reinterpret_cast<unsigned char*>(&rax15) = reinterpret_cast<uint1_t>(!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(*reinterpret_cast<void***>(&rsi8)) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<void***>(&rsi8) == 0)));
            rdx12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - rax13 - rax15);
        }
        *reinterpret_cast<int32_t*>(&rax16) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax16) + 4) = 0;
        *reinterpret_cast<unsigned char*>(&rax16) = reinterpret_cast<uint1_t>(v17 == 45);
        *reinterpret_cast<int32_t*>(&rcx18) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx18) + 4) = 0;
        *reinterpret_cast<unsigned char*>(&rcx18) = reinterpret_cast<uint1_t>(!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(*reinterpret_cast<void***>(&rsi8)) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<void***>(&rsi8) == 0)));
        eax19 = fun_18000da04(reinterpret_cast<int64_t>(rcx18) + reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(rax16) + reinterpret_cast<unsigned char>(rdx)), rdx12, static_cast<uint32_t>(rsi8 + 1), reinterpret_cast<uint64_t>(rsp9) + 64);
        rsp11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp9) - 8 + 8);
        if (!eax19) {
            *reinterpret_cast<int32_t*>(&r9_20) = v21;
            *reinterpret_cast<int32_t*>(&r9_20 + 4) = 0;
            fun_18000ccc8(rdx, r8, *reinterpret_cast<void***>(&rsi8), r9_20);
            rsp11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp11) - 8 + 8);
        } else {
            *reinterpret_cast<void***>(rdx) = reinterpret_cast<void**>(0);
        }
    }
    rcx22 = rax6 ^ reinterpret_cast<uint64_t>(rsp5) ^ reinterpret_cast<uint64_t>(rsp11);
    rax23 = fun_180002f40(rcx22, rcx22);
    return rax23;
}

struct s40 {
    unsigned char f0;
    signed char[2] pad3;
    void** f3;
};

int32_t g180017230 = 1;

struct s40* fun_18000d8c0(struct s40* rcx, uint32_t edx, void* r8) {
    struct s40* r8_4;
    struct s40* r9_5;
    int1_t less6;
    void* r10_7;
    uint32_t ecx8;
    uint32_t r9d9;
    uint32_t edx10;
    struct s40* rcx11;
    void* rdx12;
    uint32_t ecx13;
    void* rax14;
    uint32_t eax15;
    struct s40* rax16;

    *reinterpret_cast<int32_t*>(&r8_4) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_4) + 4) = 0;
    r9_5 = rcx;
    if (edx) {
        less6 = g180017230 < 2;
        if (!less6) {
            if (!(*reinterpret_cast<unsigned char*>(&rcx) & 15)) {
                addr_18000d9df_4:
                __asm__("movd xmm0, eax");
            } else {
                do {
                    if (static_cast<int32_t>(reinterpret_cast<signed char>(r9_5->f0)) == edx) {
                        r8_4 = r9_5;
                    }
                    if (!r9_5->f0) 
                        goto addr_18000d9b9_8;
                    r9_5 = reinterpret_cast<struct s40*>(&r9_5->pad3);
                } while (*reinterpret_cast<unsigned char*>(&r9_5) & 15);
                goto addr_18000d9df_4;
            }
        } else {
            r10_7 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx) & 0xfffffffffffffff0);
            __asm__("xorps xmm2, xmm2");
            __asm__("movd xmm0, ecx");
            ecx8 = *reinterpret_cast<uint32_t*>(&r9_5) & 15;
            r9d9 = 0xffffffff << *reinterpret_cast<unsigned char*>(&ecx8);
            __asm__("pshuflw xmm1, xmm0, 0x0");
            __asm__("movdqa xmm0, xmm2");
            __asm__("pcmpeqb xmm0, [r10]");
            __asm__("pshufd xmm3, xmm1, 0x0");
            __asm__("pmovmskb ecx, xmm0");
            __asm__("movdqa xmm0, xmm3");
            __asm__("pcmpeqb xmm0, [r10]");
            __asm__("pmovmskb edx, xmm0");
            edx10 = edx & r9d9;
            *reinterpret_cast<uint32_t*>(&rcx11) = ecx8 & r9d9;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx11) + 4) = 0;
            if (!*reinterpret_cast<uint32_t*>(&rcx11)) {
                do {
                    __asm__("bsr ecx, edx");
                    __asm__("movdqa xmm1, xmm2");
                    __asm__("movdqa xmm0, xmm3");
                    rcx11 = reinterpret_cast<struct s40*>(reinterpret_cast<uint64_t>(rcx11) + reinterpret_cast<uint64_t>(r10_7));
                    if (edx10) {
                        r8_4 = rcx11;
                    }
                    r10_7 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r10_7) + 16);
                    __asm__("pcmpeqb xmm1, [r10]");
                    __asm__("pcmpeqb xmm0, [r10]");
                    __asm__("pmovmskb ecx, xmm1");
                    __asm__("pmovmskb edx, xmm0");
                } while (!*reinterpret_cast<uint32_t*>(&rcx11));
            }
            __asm__("bsr ecx, edx");
            if (edx10 & (-*reinterpret_cast<uint32_t*>(&rcx11) & *reinterpret_cast<uint32_t*>(&rcx11)) - 1) {
                r8_4 = reinterpret_cast<struct s40*>(reinterpret_cast<uint64_t>(rcx11) + reinterpret_cast<uint64_t>(r10_7));
                goto addr_18000d9b9_8;
            }
        }
    } else {
        __asm__("xorps xmm1, xmm1");
        rdx12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx) & 0xfffffffffffffff0);
        ecx13 = *reinterpret_cast<uint32_t*>(&r9_5) & 15;
        __asm__("movdqa xmm0, [rdx]");
        __asm__("pcmpeqb xmm0, xmm1");
        __asm__("pmovmskb eax, xmm0");
        *reinterpret_cast<uint32_t*>(&rax14) = eax15 & 0xffffffff << *reinterpret_cast<unsigned char*>(&ecx13);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax14) + 4) = 0;
        if (!*reinterpret_cast<uint32_t*>(&rax14)) {
            do {
                rdx12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx12) + 16);
                __asm__("movdqa xmm0, [rdx]");
                __asm__("pcmpeqb xmm0, xmm1");
                __asm__("pmovmskb eax, xmm0");
            } while (!*reinterpret_cast<uint32_t*>(&rax14));
        }
        __asm__("bsf eax, eax");
        rax16 = reinterpret_cast<struct s40*>(reinterpret_cast<int64_t>(rax14) + reinterpret_cast<uint64_t>(rdx12));
        goto addr_18000d9bc_19;
    }
    addr_18000d9b9_8:
    rax16 = r8_4;
    addr_18000d9bc_19:
    return rax16;
}

struct s41 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s42 {
    int32_t f0;
    int32_t f4;
    signed char[8] pad16;
    signed char* f16;
};

void** fun_180002f70(void** rcx, void** rdx, void* r8);

struct s43 {
    signed char[240] pad240;
    void**** f240;
};

uint64_t g0;

unsigned char g18001df98;

int64_t fun_18000ccc8(void** rcx, void* rdx, void** r8d, void** r9) {
    void* rsi5;
    void** v6;
    void* rsp7;
    void** rax8;
    void** ebx9;
    int32_t eax10;
    signed char v11;
    struct s41* v12;
    int64_t rax13;
    signed char v14;
    void* rbx15;
    struct s42* v16;
    int32_t r15d17;
    void** rbx18;
    void* rax19;
    void** rdx20;
    struct s43* v21;
    void* rcx22;
    unsigned char v23;
    void** rbx24;
    void* rdx25;
    void** eax26;
    void* rsp27;
    uint64_t rax28;
    uint64_t rcx29;
    void* rsp30;
    void** rax31;
    void* rsp32;
    uint64_t rcx33;
    int64_t v34;
    void* rdx35;
    uint64_t rax36;
    int32_t v37;
    void** rax38;
    int32_t v39;
    void** eax40;
    void** r9_41;
    int32_t v42;
    void** rcx43;
    uint32_t r8d44;
    uint32_t edx45;
    uint32_t edx46;
    uint32_t edx47;
    uint32_t edx48;
    int1_t zf49;

    rsi5 = reinterpret_cast<void*>(static_cast<int64_t>(reinterpret_cast<int32_t>(r8d)));
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) + 0xffffffffffffffc8, v6);
    rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 80 - 8 + 8);
    if (!rcx || !rdx) {
        rax8 = fun_1800039c8();
        ebx9 = reinterpret_cast<void**>(22);
    } else {
        eax10 = 0;
        if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&rsi5) < 0) | reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&rsi5) == 0))) {
            eax10 = *reinterpret_cast<int32_t*>(&rsi5);
        }
        if (reinterpret_cast<uint64_t>(rdx) > reinterpret_cast<uint64_t>(static_cast<int64_t>(eax10 + 9))) 
            goto addr_18000cd3f_6; else 
            goto addr_18000cd29_7;
    }
    addr_18000cd33_8:
    *reinterpret_cast<void***>(rax8) = ebx9;
    fun_1800038fc();
    addr_18000ce77_9:
    if (v11) {
        v12->f200 = v12->f200 & 0xfffffffd;
    }
    *reinterpret_cast<void***>(&rax13) = ebx9;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax13) + 4) = 0;
    return rax13;
    addr_18000cd3f_6:
    if (v14 && (*reinterpret_cast<int32_t*>(&rbx15) = 0, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx15) + 4) = 0, *reinterpret_cast<unsigned char*>(&rbx15) = reinterpret_cast<uint1_t>(v16->f0 == 45), r15d17 = 0, rbx18 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbx15) + reinterpret_cast<unsigned char>(rcx)), *reinterpret_cast<unsigned char*>(&r15d17) = reinterpret_cast<uint1_t>(!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&rsi5) < 0) | reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&rsi5) == 0))), !!r15d17)) {
        rax19 = fun_1800084f0(rbx18, rbx18);
        fun_180002f70(static_cast<int64_t>(r15d17) + reinterpret_cast<unsigned char>(rbx18), rbx18, reinterpret_cast<uint64_t>(rax19) + 1);
        rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 8 + 8 - 8 + 8);
    }
    rdx20 = rcx;
    if (v16->f0 == 45) {
        *reinterpret_cast<void***>(rcx) = reinterpret_cast<void**>(45);
        rdx20 = rcx + 1;
    }
    if (!(reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&rsi5) < 0) | reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&rsi5) == 0))) {
        *reinterpret_cast<void***>(rdx20) = *reinterpret_cast<void***>(rdx20 + 1);
        ++rdx20;
        *reinterpret_cast<void***>(rdx20) = **v21->f240;
    }
    *reinterpret_cast<int32_t*>(&rcx22) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx22) + 4) = 0;
    *reinterpret_cast<unsigned char*>(&rcx22) = reinterpret_cast<uint1_t>(v23 == 0);
    rbx24 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rdx20) + reinterpret_cast<uint64_t>(rsi5) + reinterpret_cast<uint64_t>(rcx22));
    rdx25 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx) + (reinterpret_cast<unsigned char>(rcx) - reinterpret_cast<unsigned char>(rbx24)));
    if (rdx == 0xffffffffffffffff) {
        rdx25 = rdx;
    }
    eax26 = fun_180002c40(rbx24, rdx25, "e+000", r9);
    if (!eax26) 
        goto addr_18000cded_20;
    fun_18000391c();
    rsp27 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 8 + 8 - 8 + 8 - 8 - 8 - 8 - 8 - 0x88);
    rax28 = g1800170a0;
    rcx29 = g0;
    fun_18000dba0(rcx29, reinterpret_cast<uint64_t>(rsp27) + 64, reinterpret_cast<uint64_t>(rsp27) + 88, 22);
    rsp30 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp27) - 8 + 8);
    if (!0) 
        goto addr_18000cf07_23;
    if (!1) 
        goto addr_18000cf1f_25;
    addr_18000cf07_23:
    rax31 = fun_1800039c8();
    *reinterpret_cast<void***>(rax31) = reinterpret_cast<void**>(22);
    fun_1800038fc();
    rsp32 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp30) - 8 + 8 - 8 + 8);
    addr_18000cfa2_26:
    rcx33 = rax28 ^ reinterpret_cast<uint64_t>(rsp27) ^ reinterpret_cast<uint64_t>(rsp32);
    fun_180002f40(rcx33, rcx33);
    goto v34;
    addr_18000cf1f_25:
    rdx35 = reinterpret_cast<void*>(0xffffffffffffffff);
    if (!0) {
        *reinterpret_cast<int32_t*>(&rax36) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax36) + 4) = 0;
        *reinterpret_cast<unsigned char*>(&rax36) = reinterpret_cast<uint1_t>(v37 == 45);
        rdx35 = reinterpret_cast<void*>(-rax36);
    }
    *reinterpret_cast<int32_t*>(&rax38) = 0;
    *reinterpret_cast<int32_t*>(&rax38 + 4) = 0;
    *reinterpret_cast<unsigned char*>(&rax38) = reinterpret_cast<uint1_t>(v39 == 45);
    eax40 = fun_18000da04(rax38, rdx35, 1, reinterpret_cast<uint64_t>(rsp30) + 64);
    rsp32 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp30) - 8 + 8);
    if (!eax40) {
        *reinterpret_cast<int32_t*>(&r9_41) = v42;
        *reinterpret_cast<int32_t*>(&r9_41 + 4) = 0;
        fun_18000ccc8(0, 0, 0, r9_41);
        rsp32 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp32) - 8 + 8);
        goto addr_18000cfa2_26;
    } else {
        *reinterpret_cast<signed char*>(&g0) = 0;
        goto addr_18000cfa2_26;
    }
    addr_18000cded_20:
    rcx43 = rbx24 + 2;
    if (*reinterpret_cast<int32_t*>(&r9)) {
        *reinterpret_cast<void***>(rbx24) = reinterpret_cast<void**>(69);
    }
    if (*v16->f16 != 48) {
        r8d44 = v16->f4 - 1;
        if (reinterpret_cast<int32_t>(r8d44) < reinterpret_cast<int32_t>(0)) {
            r8d44 = -r8d44;
            *reinterpret_cast<void***>(rbx24 + 1) = reinterpret_cast<void**>(45);
        }
        if (reinterpret_cast<int32_t>(r8d44) >= reinterpret_cast<int32_t>(100)) {
            edx45 = reinterpret_cast<uint32_t>(__intrinsic() >> 5);
            edx46 = edx45 + (edx45 >> 31);
            *reinterpret_cast<unsigned char*>(rbx24 + 2) = reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(rbx24 + 2) + *reinterpret_cast<unsigned char*>(&edx46));
            r8d44 = r8d44 + edx46 * 0xffffff9c;
        }
        if (reinterpret_cast<int32_t>(r8d44) >= reinterpret_cast<int32_t>(10)) {
            edx47 = reinterpret_cast<uint32_t>(__intrinsic() >> 2);
            edx48 = edx47 + (edx47 >> 31);
            *reinterpret_cast<void**>(rbx24 + 3) = reinterpret_cast<void*>(reinterpret_cast<unsigned char>(*reinterpret_cast<void**>(rbx24 + 3)) + reinterpret_cast<unsigned char>(*reinterpret_cast<void**>(&edx48)));
            r8d44 = r8d44 + edx48 * 0xfffffff6;
        }
        *reinterpret_cast<void***>(rbx24 + 4) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rbx24 + 4)) + reinterpret_cast<unsigned char>(*reinterpret_cast<void**>(&r8d44)));
    }
    zf49 = (g18001df98 & 1) == 0;
    if (!zf49 && reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx43) == 48)) {
        fun_180002f70(rcx43, rcx43 + 1, 3);
    }
    ebx9 = reinterpret_cast<void**>(0);
    goto addr_18000ce77_9;
    addr_18000cd29_7:
    rax8 = fun_1800039c8();
    ebx9 = reinterpret_cast<void**>(34);
    goto addr_18000cd33_8;
}

struct s44 {
    signed char f0;
    signed char[7] pad8;
    int64_t f8;
    int64_t f16;
    int64_t f24;
};

void** fun_180002f70(void** rcx, void** rdx, void* r8) {
    void** r11_4;
    void* rdx5;
    int1_t cf6;
    void** rdi7;
    void** rsi8;
    void* rcx9;
    int1_t cf10;
    int1_t cf11;
    void* rcx12;
    void* rcx13;
    void* r8_14;
    uint64_t r9_15;
    uint64_t r9_16;
    struct s44* rcx17;
    uint64_t r9_18;
    int64_t r10_19;
    signed char r10_20;
    uint64_t r9_21;
    int64_t rax22;
    void** rcx23;
    void* r8_24;
    uint64_t r9_25;
    uint64_t r9_26;
    uint64_t r9_27;
    void** r10_28;
    void** r10_29;
    uint64_t r9_30;

    r11_4 = rcx;
    if (reinterpret_cast<uint64_t>(r8) > 16) {
        rdx5 = reinterpret_cast<void*>(reinterpret_cast<unsigned char>(rdx) - reinterpret_cast<unsigned char>(rcx));
        if (reinterpret_cast<unsigned char>(rdx) >= reinterpret_cast<unsigned char>(rcx) || reinterpret_cast<signed char>(rcx) >= reinterpret_cast<signed char>(reinterpret_cast<unsigned char>(rdx) + reinterpret_cast<uint64_t>(r8))) {
            cf6 = static_cast<int1_t>(g18001d2e4 >> 1);
            if (cf6) {
                rdi7 = rcx;
                rsi8 = rdx;
                rcx9 = r8;
                while (*reinterpret_cast<int32_t*>(&rcx9)) {
                    *reinterpret_cast<int32_t*>(&rcx9) = *reinterpret_cast<int32_t*>(&rcx9) - 1;
                    *reinterpret_cast<void***>(rdi7) = *reinterpret_cast<void***>(rsi8);
                    ++rdi7;
                    ++rsi8;
                }
                return r11_4;
            }
            cf10 = static_cast<int1_t>(g18001d2e4 >> 2);
            if (cf10) 
                goto addr_180003215_10; else 
                goto addr_180002fbf_11;
        } else {
            cf11 = static_cast<int1_t>(g18001d2e4 >> 2);
            if (cf11) {
                if (reinterpret_cast<uint64_t>(r8) > 32) {
                    rcx12 = reinterpret_cast<void*>(reinterpret_cast<unsigned char>(rcx) + reinterpret_cast<uint64_t>(r8));
                    if (*reinterpret_cast<unsigned char*>(&rcx12) & 15) {
                        rcx13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx12) - 16);
                        __asm__("movups xmm1, [rdx+rcx]");
                        *reinterpret_cast<unsigned char*>(&rcx13) = reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx13) & 0xf0);
                        __asm__("movups xmm0, [rdx+rcx]");
                        __asm__("movups [rax], xmm1");
                        r8_14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx13) - reinterpret_cast<unsigned char>(r11_4));
                    } else {
                        __asm__("movups xmm0, [rdx+rcx]");
                        r8_14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 16);
                    }
                    r9_15 = reinterpret_cast<uint64_t>(r8_14) >> 7;
                    if (r9_15) {
                        __asm__("movaps [rcx], xmm0");
                        while (--r9_15, !!r9_15) {
                            __asm__("movaps [rcx+0x10], xmm0");
                            __asm__("movaps [rcx], xmm1");
                        }
                        __asm__("movaps [rcx+0x10], xmm0");
                        r8_14 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8_14) & 0x7f);
                        __asm__("movaps xmm0, xmm1");
                    }
                    r9_16 = reinterpret_cast<uint64_t>(r8_14) >> 4;
                    if (r9_16) {
                        do {
                            __asm__("movaps [rcx], xmm0");
                            __asm__("movups xmm0, [rdx+rcx]");
                            --r9_16;
                        } while (r9_16);
                    }
                    if (reinterpret_cast<uint64_t>(r8_14) & 15) {
                        __asm__("movups xmm1, [r10]");
                        __asm__("movups [r11], xmm1");
                    }
                    __asm__("movaps [rcx], xmm0");
                    return r11_4;
                }
            } else {
                rcx17 = reinterpret_cast<struct s44*>(reinterpret_cast<unsigned char>(rcx) + reinterpret_cast<uint64_t>(r8));
                if (*reinterpret_cast<unsigned char*>(&rcx17) & 7) {
                    if (*reinterpret_cast<unsigned char*>(&rcx17) & 1) {
                        rcx17 = reinterpret_cast<struct s44*>(reinterpret_cast<uint64_t>(rcx17) - 1);
                        r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 1);
                        rcx17->f0 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17));
                    }
                    if (*reinterpret_cast<unsigned char*>(&rcx17) & 2) {
                        rcx17 = reinterpret_cast<struct s44*>(reinterpret_cast<uint64_t>(rcx17) - 2);
                        r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 2);
                        rcx17->f0 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17));
                    }
                    if (*reinterpret_cast<unsigned char*>(&rcx17) & 4) {
                        rcx17 = reinterpret_cast<struct s44*>(reinterpret_cast<uint64_t>(rcx17) - 4);
                        r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 4);
                        rcx17->f0 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17));
                    }
                }
                r9_18 = reinterpret_cast<uint64_t>(r8) >> 5;
                if (r9_18) {
                    do {
                        r10_19 = *reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17) + 0xfffffffffffffff0);
                        --rcx17;
                        rcx17->f24 = *reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17) + 0xfffffffffffffff8);
                        rcx17->f16 = r10_19;
                        r10_20 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17));
                        --r9_18;
                        rcx17->f8 = *reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17) + 8);
                        rcx17->f0 = r10_20;
                    } while (r9_18);
                    r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) & 31);
                }
                r9_21 = reinterpret_cast<uint64_t>(r8) >> 3;
                if (r9_21) {
                    do {
                        rcx17 = reinterpret_cast<struct s44*>(reinterpret_cast<uint64_t>(rcx17) - 8);
                        --r9_21;
                        rcx17->f0 = *reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<uint64_t>(rcx17));
                    } while (r9_21);
                    r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) & 7);
                }
                if (!r8) {
                    return r11_4;
                }
            }
        }
    }
    addr_18000303c_44:
    *reinterpret_cast<int32_t*>(&rax22) = *reinterpret_cast<int32_t*>(0x180000000 + reinterpret_cast<uint64_t>(r8) * 4 + 0x3050);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax22) + 4) = 0;
    goto rax22 + 0x180000000;
    addr_180003215_10:
    if (reinterpret_cast<uint64_t>(r8) > 32) {
        if (*reinterpret_cast<unsigned char*>(&rcx) & 15) {
            __asm__("movups xmm1, [rdx+rcx]");
            rcx23 = rcx + 32;
            *reinterpret_cast<unsigned char*>(&rcx23) = reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx23) & 0xf0);
            __asm__("movups xmm0, [rdx+rcx-0x10]");
            __asm__("movups [r11], xmm1");
            r8_24 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - (reinterpret_cast<unsigned char>(rcx23) - reinterpret_cast<unsigned char>(r11_4)));
        } else {
            __asm__("movups xmm0, [rdx+rcx]");
            r8_24 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 16);
        }
        r9_25 = reinterpret_cast<uint64_t>(r8_24) >> 7;
        if (r9_25) {
            __asm__("movaps [rcx-0x10], xmm0");
            while (--r9_25, !!r9_25) {
                __asm__("movaps [rcx-0x20], xmm0");
                __asm__("movaps [rcx-0x10], xmm1");
            }
            __asm__("movaps [rcx-0x20], xmm0");
            r8_24 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8_24) & 0x7f);
            __asm__("movaps xmm0, xmm1");
        }
        r9_26 = reinterpret_cast<uint64_t>(r8_24) >> 4;
        if (r9_26) {
            do {
                __asm__("movaps [rcx-0x10], xmm0");
                __asm__("movups xmm0, [rdx+rcx]");
                --r9_26;
            } while (r9_26);
        }
        if (reinterpret_cast<uint64_t>(r8_24) & 15) {
            __asm__("movups xmm1, [rdx+rax-0x10]");
            __asm__("movups [rax-0x10], xmm1");
        }
        __asm__("movaps [rcx-0x10], xmm0");
        return r11_4;
    }
    __asm__("movups xmm0, [r10]");
    __asm__("movups xmm1, [rdx+rcx]");
    __asm__("movups [r11], xmm0");
    __asm__("movups [rcx], xmm1");
    return r11_4;
    addr_180002fbf_11:
    if (*reinterpret_cast<unsigned char*>(&rcx) & 7) {
        if (*reinterpret_cast<unsigned char*>(&rcx) & 1) {
            r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 1);
            *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx));
            ++rcx;
        }
        if (*reinterpret_cast<unsigned char*>(&rcx) & 2) {
            r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 2);
            *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx));
            rcx = rcx + 2;
        }
        if (*reinterpret_cast<unsigned char*>(&rcx) & 4) {
            r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) - 4);
            *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx));
            rcx = rcx + 4;
        }
    }
    r9_27 = reinterpret_cast<uint64_t>(r8) >> 5;
    if (r9_27) {
        do {
            r10_28 = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx) + 8);
            rcx = rcx + 32;
            *reinterpret_cast<void***>(rcx + 0xffffffffffffffe0) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx));
            *reinterpret_cast<void***>(rcx + 0xffffffffffffffe8) = r10_28;
            r10_29 = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx) + 0xfffffffffffffff8);
            --r9_27;
            *reinterpret_cast<void***>(rcx + 0xfffffffffffffff0) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx) + 0xfffffffffffffff0);
            *reinterpret_cast<void***>(rcx + 0xfffffffffffffff8) = r10_29;
        } while (r9_27);
        r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) & 31);
    }
    r9_30 = reinterpret_cast<uint64_t>(r8) >> 3;
    if (r9_30) {
        do {
            *reinterpret_cast<void***>(rcx) = *reinterpret_cast<void***>(reinterpret_cast<uint64_t>(rdx5) + reinterpret_cast<unsigned char>(rcx));
            rcx = rcx + 8;
            --r9_30;
        } while (r9_30);
        r8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) & 7);
    }
    if (r8) {
        goto addr_18000303c_44;
    } else {
        return r11_4;
    }
}

struct s45 {
    uint32_t f0;
    uint32_t f4;
};

struct s46 {
    int16_t f0;
    uint16_t f2;
    signed char[2] pad6;
    uint16_t f6;
    signed char[2] pad10;
    uint16_t f10;
};

int32_t fun_18000c010(struct s46* rcx, unsigned char** rdx, unsigned char* r8, uint16_t r9d);

struct s47 {
    signed char[2] pad2;
    uint32_t f2;
    uint32_t f6;
    uint16_t f10;
};

int32_t fun_18000b4a0(struct s47* rcx, struct s45* rdx, unsigned char* r8);

struct s48 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s0* fun_18000b340(struct s45* rcx, unsigned char* rdx, void** r8) {
    void* rsp4;
    uint64_t rax5;
    void* rsp6;
    int32_t eax7;
    void* rsp8;
    int32_t ebx9;
    int32_t eax10;
    signed char v11;
    struct s48* v12;
    uint64_t rcx13;
    struct s0* rax14;

    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x80);
    rax5 = g1800170a0;
    fun_180003bc4(reinterpret_cast<uint64_t>(rsp4) + 64, r8);
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp4) - 8 + 8);
    eax7 = fun_18000c010(reinterpret_cast<uint64_t>(rsp6) + 0x68, reinterpret_cast<uint64_t>(rsp6) + 96, rdx, 0);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
    ebx9 = eax7;
    eax10 = fun_18000b4a0(reinterpret_cast<uint64_t>(rsp8) + 0x68, rcx, rdx);
    if (3 & *reinterpret_cast<unsigned char*>(&ebx9)) {
        if (!(*reinterpret_cast<unsigned char*>(&ebx9) & 1)) {
            if (*reinterpret_cast<unsigned char*>(&ebx9) & 2) {
                addr_18000b3d6_4:
                if (v11) {
                    v12->f200 = v12->f200 & 0xfffffffd;
                }
            } else {
                addr_18000b3d4_6:
                goto addr_18000b3d6_4;
            }
            rcx13 = rax5 ^ reinterpret_cast<uint64_t>(rsp4) ^ reinterpret_cast<uint64_t>(rsp8) - 8 + 8;
            rax14 = fun_180002f40(rcx13, rcx13);
            return rax14;
        }
    } else {
        if (eax10 == 1) 
            goto addr_18000b3d6_4;
        if (eax10 != 2) 
            goto addr_18000b3d4_6;
    }
    goto addr_18000b3d6_4;
}

int32_t g18001df58;

struct s49 {
    signed char[212] pad212;
    int32_t f212;
    signed char[48] pad264;
    uint16_t* f264;
};

uint32_t fun_18000a638(uint32_t ecx, uint32_t edx, void** r8);

struct s50 {
    signed char[200] pad200;
    uint32_t f200;
};

uint16_t* g180017f88 = reinterpret_cast<uint16_t*>(0x180011820);

uint32_t fun_18000d6d0(uint32_t ecx) {
    void* rsp2;
    int1_t zf3;
    int64_t rbx4;
    struct s49* v5;
    uint32_t ecx6;
    uint32_t eax7;
    signed char v8;
    struct s50* v9;
    uint32_t eax10;
    uint16_t* rax11;

    rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64);
    zf3 = g18001df58 == 0;
    rbx4 = reinterpret_cast<int32_t>(ecx);
    if (!zf3) {
        fun_180003bc4(reinterpret_cast<int64_t>(rsp2) + 32, 0);
        rsp2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp2) - 8 + 8);
        if (v5->f212 <= 1) {
            ecx6 = static_cast<uint32_t>(v5->f264[rbx4]) & 4;
        } else {
            eax7 = fun_18000a638(*reinterpret_cast<uint32_t*>(&rbx4), 4, reinterpret_cast<int64_t>(rsp2) + 32);
            ecx6 = eax7;
        }
        if (v8) {
            v9->f200 = v9->f200 & 0xfffffffd;
        }
        eax10 = ecx6;
    } else {
        rax11 = g180017f88;
        eax10 = static_cast<uint32_t>(rax11[rbx4]) & 4;
    }
    return eax10;
}

struct s51 {
    signed char[212] pad212;
    int32_t f212;
};

struct s52 {
    signed char[312] pad312;
    void** f312;
};

struct s53 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s54 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s55 {
    signed char[212] pad212;
    int32_t f212;
    signed char[48] pad264;
    uint16_t* f264;
    void* f272;
};

uint32_t fun_18000d8a0(int64_t rcx) {
    int1_t zf2;
    void* rbp3;
    int64_t rdi4;
    struct s51* v5;
    int32_t r14d6;
    uint32_t eax7;
    void** rax8;
    void** rdx9;
    struct s52* v10;
    int32_t eax11;
    signed char v12;
    struct s53* v13;
    uint32_t eax14;
    unsigned char v15;
    unsigned char v16;
    signed char v17;
    struct s54* v18;
    struct s55* rdx19;
    struct s55* v20;
    uint32_t eax21;
    struct s55* v22;

    zf2 = g18001df58 == 0;
    if (zf2) {
        if (static_cast<uint32_t>(rcx - 65) <= 25) {
            *reinterpret_cast<uint32_t*>(&rcx) = *reinterpret_cast<uint32_t*>(&rcx) + 32;
        }
        return *reinterpret_cast<uint32_t*>(&rcx);
    }
    rbp3 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8);
    rdi4 = *reinterpret_cast<int32_t*>(&rcx);
    fun_180003bc4(reinterpret_cast<int64_t>(rbp3) + 0xffffffffffffffe0, 0);
    if (*reinterpret_cast<uint32_t*>(&rdi4) < 0x100) 
        goto addr_18000d772_7;
    if (v5->f212 <= 1 || (r14d6 = *reinterpret_cast<int32_t*>(&rdi4) >> 8, eax7 = fun_180008448(static_cast<uint32_t>(*reinterpret_cast<unsigned char*>(&r14d6)), reinterpret_cast<int64_t>(rbp3) + 0xffffffffffffffe0), eax7 == 0)) {
        rax8 = fun_1800039c8();
        *reinterpret_cast<void***>(rax8) = reinterpret_cast<void**>(42);
    }
    rdx9 = v10->f312;
    eax11 = fun_18000a3a0(reinterpret_cast<int64_t>(rbp3) + 0xffffffffffffffe0, rdx9, 0x100, reinterpret_cast<int64_t>(rbp3) + 16);
    if (!eax11) {
        addr_18000d7b7_12:
        if (v12) {
            v13->f200 = v13->f200 & 0xfffffffd;
        }
    } else {
        eax14 = v15;
        if (eax11 != 1) {
            eax14 = eax14 << 8 | static_cast<uint32_t>(v16);
            goto addr_18000d87b_16;
        }
    }
    eax14 = *reinterpret_cast<uint32_t*>(&rdi4);
    addr_18000d88c_18:
    return eax14;
    addr_18000d87b_16:
    if (v17) {
        v18->f200 = v18->f200 & 0xfffffffd;
        goto addr_18000d88c_18;
    }
    addr_18000d772_7:
    rdx19 = v20;
    if (rdx19->f212 <= 1) {
        eax21 = static_cast<uint32_t>(rdx19->f264[rdi4]) & 1;
    } else {
        eax21 = fun_18000a638(*reinterpret_cast<uint32_t*>(&rdi4), 1, reinterpret_cast<int64_t>(rbp3) + 0xffffffffffffffe0);
        rdx19 = v22;
    }
    if (!eax21) 
        goto addr_18000d7b7_12;
    eax14 = *reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(rdx19->f272) + rdi4);
    goto addr_18000d87b_16;
}

struct s56 {
    signed char[264] pad264;
    uint16_t* f264;
};

struct s57 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s58 {
    signed char[200] pad200;
    uint32_t f200;
};

uint32_t fun_18000a638(uint32_t ecx, uint32_t edx, void** r8) {
    void* rbp4;
    int64_t rdi5;
    int32_t esi6;
    uint32_t eax7;
    int32_t r9d8;
    int32_t eax9;
    uint32_t eax10;
    struct s56* v11;
    uint16_t v12;
    uint32_t eax13;
    signed char v14;
    struct s57* v15;
    signed char v16;
    struct s58* v17;

    rbp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8);
    rdi5 = reinterpret_cast<int32_t>(ecx);
    fun_180003bc4(reinterpret_cast<int64_t>(rbp4) + 0xffffffffffffffe0, r8);
    if (static_cast<uint32_t>(rdi5 + 1) > 0x100) {
        esi6 = *reinterpret_cast<int32_t*>(&rdi5) >> 8;
        eax7 = fun_180008448(static_cast<uint32_t>(*reinterpret_cast<unsigned char*>(&esi6)), reinterpret_cast<int64_t>(rbp4) + 0xffffffffffffffe0);
        if (!eax7) {
            r9d8 = 1;
        } else {
            r9d8 = 2;
        }
        eax9 = fun_18000a5b0(reinterpret_cast<int64_t>(rbp4) + 0xffffffffffffffe0, 1, reinterpret_cast<int64_t>(rbp4) + 56, r9d8);
        if (!eax9) 
            goto addr_18000a6d6_6;
    } else {
        eax10 = v11->f264[rdi5];
        goto addr_18000a6ee_8;
    }
    eax10 = v12;
    addr_18000a6ee_8:
    eax13 = eax10 & edx;
    if (v14) {
        v15->f200 = v15->f200 & 0xfffffffd;
    }
    addr_18000a702_11:
    return eax13;
    addr_18000a6d6_6:
    if (v16 != *reinterpret_cast<signed char*>(&eax9)) {
        v17->f200 = v17->f200 & 0xfffffffd;
    }
    eax13 = 0;
    goto addr_18000a702_11;
}

struct s59 {
    signed char[264] pad264;
    uint16_t* f264;
};

struct s60 {
    signed char[200] pad200;
    uint32_t f200;
};

uint32_t fun_180008448(uint32_t ecx, void** rdx) {
    uint32_t ebx3;
    int64_t rdx4;
    uint32_t eax5;
    struct s59* v6;
    signed char v7;
    struct s60* v8;

    ebx3 = ecx;
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 + 32, rdx);
    *reinterpret_cast<uint32_t*>(&rdx4) = *reinterpret_cast<unsigned char*>(&ebx3);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx4) + 4) = 0;
    eax5 = static_cast<uint32_t>(v6->f264[rdx4]) & 0x8000;
    if (v7) {
        v8->f200 = v8->f200 & 0xfffffffd;
    }
    return eax5;
}

void** fun_18000da04(void** rcx, void* rdx, void** r8d, struct s38* r9) {
    void** rbx5;
    void*** rcx6;
    void** rax7;
    void** ebx8;
    void** eax9;
    void** eax10;
    void** rdi11;
    void** rax12;
    int1_t sf13;
    int32_t edx14;
    void* rax15;

    rbx5 = rcx;
    rcx6 = r9->f16;
    if (!rbx5 || !rdx) {
        rax7 = fun_1800039c8();
        ebx8 = reinterpret_cast<void**>(22);
    } else {
        eax9 = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx5) = reinterpret_cast<void**>(0);
        if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(r8d) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(r8d == 0))) {
            eax9 = r8d;
        }
        if (reinterpret_cast<uint64_t>(rdx) > reinterpret_cast<uint64_t>(static_cast<int64_t>(reinterpret_cast<int32_t>(eax9 + 1)))) 
            goto addr_18000da5c_6; else 
            goto addr_18000da50_7;
    }
    addr_18000da27_8:
    *reinterpret_cast<void***>(rax7) = ebx8;
    fun_1800038fc();
    eax10 = ebx8;
    addr_18000dac4_9:
    return eax10;
    addr_18000da5c_6:
    rdi11 = rbx5 + 1;
    *reinterpret_cast<void***>(rbx5) = reinterpret_cast<void**>(48);
    rax12 = rdi11;
    while (sf13 = reinterpret_cast<signed char>(r8d) < reinterpret_cast<signed char>(0), !reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(sf13) | reinterpret_cast<uint1_t>(r8d == 0))) {
        if (!*rcx6) {
            edx14 = 48;
        } else {
            edx14 = reinterpret_cast<signed char>(*rcx6);
            ++rcx6;
        }
        *reinterpret_cast<void***>(rax12) = *reinterpret_cast<void***>(&edx14);
        ++rax12;
        --r8d;
    }
    *reinterpret_cast<void***>(rax12) = reinterpret_cast<void**>(0);
    if (sf13) 
        goto addr_18000daa0_16;
    if (reinterpret_cast<signed char>(*rcx6) >= reinterpret_cast<signed char>(53)) 
        goto addr_18000da91_18;
    addr_18000daa0_16:
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rbx5) == 49)) {
        rax15 = fun_1800084f0(rdi11);
        fun_180002f70(rbx5, rdi11, reinterpret_cast<uint64_t>(rax15) + 1);
    } else {
        r9->f4 = r9->f4 + 1;
    }
    eax10 = reinterpret_cast<void**>(0);
    goto addr_18000dac4_9;
    addr_18000da91_18:
    while (--rax12, *reinterpret_cast<void***>(rax12) == 57) {
        *reinterpret_cast<void***>(rax12) = reinterpret_cast<void**>(48);
    }
    *reinterpret_cast<void***>(rax12) = *reinterpret_cast<void***>(rax12) + 1;
    goto addr_18000daa0_16;
    addr_18000da50_7:
    rax7 = fun_1800039c8();
    ebx8 = reinterpret_cast<void**>(34);
    goto addr_18000da27_8;
}

struct s61 {
    int32_t f0;
    uint16_t f4;
    signed char[2] pad8;
    uint16_t f8;
};

struct s62 {
    uint16_t f0;
    signed char[2] pad4;
    uint32_t f4;
};

struct s63 {
    void** f0;
    signed char[3] pad4;
    void** f4;
};

struct s64 {
    signed char[48] pad48;
    void** f48;
};

struct s65 {
    uint16_t f0;
    signed char[2] pad4;
    uint16_t f4;
    signed char[2] pad8;
    uint32_t f8;
    uint16_t f10;
};

struct s66 {
    uint32_t f0;
    uint16_t f4;
};

int32_t fun_18000dc58(struct s61* rcx, int32_t edx, int32_t r8d, void** r9) {
    void* rsp5;
    void* rbp6;
    void* rsp7;
    uint64_t rax8;
    uint64_t v9;
    uint32_t r10d10;
    void** rbx11;
    void** r9_12;
    int32_t v13;
    int32_t v14;
    uint16_t r8d15;
    uint32_t ecx16;
    void* cx17;
    int64_t rax18;
    void** r10w19;
    void** v20;
    uint32_t v21;
    void* v22;
    uint32_t edx23;
    uint96_t v24;
    int64_t rcx25;
    int64_t rax26;
    uint32_t r14d27;
    uint16_t* r9_28;
    uint32_t v29;
    struct s62* rdi30;
    int32_t ecx31;
    int32_t v32;
    uint32_t r10d33;
    uint16_t r8d34;
    uint16_t edx35;
    int1_t zf36;
    void** eax37;
    void* rdx38;
    void** eax39;
    void* rdx40;
    void** eax41;
    void** eax42;
    int64_t rax43;
    int64_t rcx44;
    uint32_t r13d45;
    uint96_t v46;
    uint16_t r13w47;
    uint16_t r13w48;
    int32_t r9d49;
    int32_t eax50;
    int64_t r14_51;
    uint16_t r9d52;
    struct s63* rsi53;
    uint64_t r10_54;
    uint32_t r9d55;
    uint32_t ecx56;
    int32_t r9d57;
    uint32_t r10d58;
    uint32_t eax59;
    uint32_t ecx60;
    uint32_t r15d61;
    void** rdi62;
    void** r10_63;
    void** rdi64;
    void*** rsi65;
    uint32_t edx66;
    void* rsi67;
    uint32_t r8d68;
    uint32_t r9d69;
    int64_t r8_70;
    int64_t rax71;
    uint64_t v72;
    int64_t rdx73;
    int64_t r12_74;
    uint32_t r9d75;
    uint32_t eax76;
    uint32_t ecx77;
    uint64_t rax78;
    int64_t r14_79;
    int64_t r9_80;
    uint16_t eax81;
    uint16_t v82;
    uint32_t eax83;
    void** r10_84;
    void** r10_85;
    void* r10b86;
    uint64_t rcx87;
    struct s0* rax88;
    int64_t rax89;
    uint32_t esi90;
    uint32_t r8d91;
    int64_t rax92;
    uint32_t v93;
    uint32_t r10d94;
    uint16_t r8d95;
    void* r9w96;
    uint32_t eax97;
    uint32_t ebx98;
    uint32_t eax99;
    uint32_t* rdx100;
    uint32_t eax101;
    uint32_t eax102;
    uint32_t eax103;
    uint32_t v104;
    uint16_t* v105;
    uint32_t eax106;
    int64_t rax107;
    struct s65* rsi108;
    struct s66* rdi109;
    uint64_t rax110;
    int64_t rcx111;
    int64_t rax112;
    uint32_t ebx113;
    uint96_t v114;
    uint16_t bx115;
    uint16_t bx116;
    int32_t r9d117;
    uint16_t v118;
    uint1_t cf119;
    uint32_t edi120;
    uint32_t r13d121;
    uint32_t r10d122;
    int64_t rax123;
    uint32_t v124;
    uint32_t r8d125;
    uint16_t r10d126;
    uint32_t r9d127;
    uint32_t eax128;
    uint32_t eax129;
    uint32_t* rdx130;
    uint16_t v131;
    uint32_t r9d132;
    uint32_t eax133;
    uint32_t eax134;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 8 - 8);
    rbp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 39);
    rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 0xc0);
    rax8 = g1800170a0;
    v9 = rax8 ^ reinterpret_cast<uint64_t>(rsp7);
    r10d10 = rcx->f8;
    rbx11 = r9;
    *reinterpret_cast<int32_t*>(&r9_12) = rcx->f0;
    *reinterpret_cast<int32_t*>(&r9_12 + 4) = 0;
    v13 = edx;
    v14 = r8d;
    r8d15 = rcx->f4;
    ecx16 = *reinterpret_cast<uint16_t*>(&r10d10);
    cx17 = reinterpret_cast<void*>(*reinterpret_cast<uint16_t*>(&ecx16) & 0x8000);
    *reinterpret_cast<int32_t*>(&rax18) = 32;
    r10w19 = reinterpret_cast<void**>(*reinterpret_cast<uint16_t*>(&r10d10) & reinterpret_cast<unsigned char>(0x7fff));
    v20 = rbx11;
    v21 = 0x3ffbcccc;
    v22 = cx17;
    if (!cx17) {
        *reinterpret_cast<unsigned char*>(rbx11 + 2) = 32;
    } else {
        *reinterpret_cast<unsigned char*>(rbx11 + 2) = 45;
    }
    if (r10w19) {
        if (!reinterpret_cast<int1_t>(r10w19 == 0x7fff)) {
            addr_18000ddea_6:
            edx23 = reinterpret_cast<uint16_t>(r10w19);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v24) + 2) = *reinterpret_cast<int32_t*>(&r9_12);
            *reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10) = r10w19;
            *reinterpret_cast<uint32_t*>(&rcx25) = r8d15 >> 24;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx25) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&rax26) = edx23 >> 8;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax26) + 4) = 0;
            r14d27 = 5;
            r9_28 = reinterpret_cast<uint16_t*>(0x180018330);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 6) = r8d15;
            *reinterpret_cast<void***>(&v24) = reinterpret_cast<void**>(0);
            v29 = 5;
            *reinterpret_cast<uint32_t*>(&rdi30) = 0x7fffffff;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi30) + 4) = 0;
            ecx31 = reinterpret_cast<int32_t>(static_cast<int32_t>(rax26 + rcx25 * 2) * 77 + (edx23 * 0x4d10 + 0xecbced0c)) >> 16;
            v32 = ecx31;
            r10d33 = reinterpret_cast<uint32_t>(-static_cast<int32_t>(*reinterpret_cast<int16_t*>(&ecx31)));
            if (!r10d33) {
                addr_18000e1c4_7:
                r8d34 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 4);
                edx35 = *reinterpret_cast<uint16_t*>(&v24);
            } else {
                zf36 = r10d33 == 0;
                if (reinterpret_cast<int32_t>(r10d33) < reinterpret_cast<int32_t>(0)) {
                    r10d33 = -r10d33;
                    r9_28 = reinterpret_cast<uint16_t*>(0x180018490);
                    zf36 = r10d33 == 0;
                }
                if (zf36) 
                    goto addr_18000e1c4_7; else 
                    goto addr_18000de71_11;
            }
        } else {
            *reinterpret_cast<void***>(rbx11) = reinterpret_cast<void**>(1);
            if (r8d15 == 0x80000000 && !*reinterpret_cast<int32_t*>(&r9_12) || static_cast<int1_t>(r8d15 >> 30)) {
                if (!cx17 || r8d15 != 0xc0000000) {
                    if (r8d15 != 0x80000000 || *reinterpret_cast<int32_t*>(&r9_12)) {
                        addr_18000ddc1_15:
                        eax37 = fun_180002c40(rbx11 + 4, 22, "1#QNAN", r9_12);
                        rsp7 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp7) - 8 + 8);
                        if (eax37) {
                            addr_18000e71b_16:
                            fun_18000391c();
                            goto addr_18000e730_17;
                        } else {
                            addr_18000ddde_18:
                            *reinterpret_cast<void**>(rbx11 + 3) = reinterpret_cast<void*>(6);
                            goto addr_18000dde2_19;
                        }
                    } else {
                        *reinterpret_cast<int32_t*>(&rdx38) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r9_12 + 22));
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx38) + 4) = 0;
                        eax39 = fun_180002c40(rbx11 + 4, rdx38, "1#INF", r9_12);
                        rsp7 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp7) - 8 + 8);
                        if (eax39) {
                            addr_18000e706_21:
                            fun_18000391c();
                            goto addr_18000e71b_16;
                        } else {
                            addr_18000ddb7_22:
                            *reinterpret_cast<void**>(rbx11 + 3) = reinterpret_cast<void*>(5);
                            goto addr_18000dde2_19;
                        }
                    }
                } else {
                    if (*reinterpret_cast<int32_t*>(&r9_12)) 
                        goto addr_18000ddc1_15;
                    *reinterpret_cast<int32_t*>(&rdx40) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r9_12 + 22));
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx40) + 4) = 0;
                    eax41 = fun_180002c40(rbx11 + 4, rdx40, "1#IND", r9_12);
                    rsp7 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp7) - 8 + 8);
                    if (!eax41) 
                        goto addr_18000ddb7_22;
                    goto addr_18000e6f1_26;
                }
            } else {
                eax42 = fun_180002c40(rbx11 + 4, 22, "1#SNAN", r9_12);
                rsp7 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp7) - 8 + 8);
                if (!eax42) 
                    goto addr_18000ddde_18;
                fun_18000391c();
                goto addr_18000e6f1_26;
            }
        }
    } else {
        if (r8d15) 
            goto addr_18000ddea_6;
        if (*reinterpret_cast<int32_t*>(&r9_12)) 
            goto addr_18000ddea_6;
        if (cx17 == 0x8000) {
            *reinterpret_cast<int32_t*>(&rax18) = 45;
            goto addr_18000dd05_34;
        }
    }
    addr_18000e1cb_35:
    *reinterpret_cast<uint32_t*>(&rax43) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) >> 16;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax43) + 4) = 0;
    if (*reinterpret_cast<uint16_t*>(&rax43) < 0x3fff) {
        addr_18000e497_36:
    } else {
        *reinterpret_cast<uint16_t*>(&ecx31) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&ecx31) + reinterpret_cast<unsigned char>(1));
        v32 = ecx31;
        *reinterpret_cast<uint32_t*>(&rcx44) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v21) + 2);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx44) + 4) = 0;
        r13d45 = *reinterpret_cast<uint16_t*>(&rcx44);
        *reinterpret_cast<uint16_t*>(&rcx44) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rcx44) & 0x7fff);
        *reinterpret_cast<int64_t*>(&v46) = 0;
        r13w47 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r13d45) ^ *reinterpret_cast<uint16_t*>(&rax43));
        *reinterpret_cast<uint16_t*>(&rax43) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax43) & 0x7fff);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 8) = reinterpret_cast<uint16_t>(0);
        r13w48 = reinterpret_cast<uint16_t>(r13w47 & 0x8000);
        r9d49 = static_cast<int32_t>(rax43 + rcx44);
        if (*reinterpret_cast<uint16_t*>(&rax43) >= 0x7fff || (*reinterpret_cast<uint16_t*>(&rcx44) >= 0x7fff || reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d49)) > 0xbffd)) {
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) = reinterpret_cast<uint16_t>((*reinterpret_cast<uint32_t*>(&rax43) - (*reinterpret_cast<uint32_t*>(&rax43) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax43) < *reinterpret_cast<uint32_t*>(&rax43) + reinterpret_cast<uint1_t>(!!r13w48))) & 0x80000000) + 0x7fff8000);
            goto addr_18000e491_39;
        } else {
            if (reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d49)) <= 0x3fbf) 
                goto addr_18000e248_41;
            if (*reinterpret_cast<uint16_t*>(&rax43)) 
                goto addr_18000e272_43;
            *reinterpret_cast<void**>(&r9d49) = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d49)) + reinterpret_cast<unsigned char>(1));
            if (*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) & *reinterpret_cast<uint32_t*>(&rdi30)) 
                goto addr_18000e272_43;
            if (r8d34) 
                goto addr_18000e272_43;
            if (edx35) 
                goto addr_18000e272_43; else 
                goto addr_18000e268_47;
        }
    }
    addr_18000e49c_48:
    eax50 = v32;
    *reinterpret_cast<int32_t*>(&r14_51) = v13;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_51) + 4) = 0;
    *reinterpret_cast<void***>(rbx11) = *reinterpret_cast<void***>(&eax50);
    if (!(*reinterpret_cast<unsigned char*>(&v14) & 1) || (*reinterpret_cast<int32_t*>(&r14_51) = *reinterpret_cast<int32_t*>(&r14_51) + reinterpret_cast<int16_t>(*reinterpret_cast<void***>(&eax50)), *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_51) + 4) = 0, !reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&r14_51) < 0) | reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&r14_51) == 0)))) {
        r9d52 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8);
        *reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10) = reinterpret_cast<void**>(0);
        *reinterpret_cast<uint16_t*>(&rsi53) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8);
        *reinterpret_cast<int32_t*>(&r10_54) = 8;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_54) + 4) = 0;
        if (*reinterpret_cast<int32_t*>(&r14_51) > 21) {
            *reinterpret_cast<int32_t*>(&r14_51) = 21;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_51) + 4) = 0;
        }
        r9d55 = (r9d52 >> 16) - 0x3ffe;
        do {
            ecx56 = r8d34 >> 31;
            r8d34 = reinterpret_cast<uint16_t>(r8d34 + r8d34 | edx35 >> 31);
            *reinterpret_cast<uint16_t*>(&rsi53) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rsi53) + *reinterpret_cast<uint16_t*>(&rsi53) | ecx56);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi53) + 4) = 0;
            edx35 = reinterpret_cast<uint16_t>(edx35 + edx35);
            --r10_54;
        } while (r10_54);
        if (reinterpret_cast<int32_t>(r9d55) < reinterpret_cast<int32_t>(0) && (r9d57 = reinterpret_cast<int32_t>(-r9d55), r10d58 = *reinterpret_cast<unsigned char*>(&r9d57), !(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r10d58) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r10d58 == 0)))) {
            do {
                eax59 = *reinterpret_cast<uint16_t*>(&rsi53) << 31;
                ecx60 = r8d34 << 31;
                --r10d58;
                *reinterpret_cast<uint16_t*>(&rsi53) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rsi53) >> 1);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi53) + 4) = 0;
                r8d34 = reinterpret_cast<uint16_t>(r8d34 >> 1 | eax59);
                edx35 = reinterpret_cast<uint16_t>(edx35 >> 1 | ecx60);
            } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r10d58) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r10d58 == 0)));
        }
        r15d61 = static_cast<uint32_t>(r14_51 + 1);
        rdi62 = rbx11 + 4;
        r10_63 = rdi62;
        if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r15d61) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r15d61 == 0))) {
            while (1) {
                *reinterpret_cast<void***>(rdi62) = rsi53->f0;
                rdi64 = rdi62 + 4;
                rsi65 = &rsi53->f4;
                edx66 = edx35 + edx35;
                *reinterpret_cast<void***>(rdi64) = *rsi65;
                rdi62 = rdi64 + 4;
                rsi67 = reinterpret_cast<void*>(rsi65 + 4);
                r8d68 = r8d34 + r8d34 | edx35 >> 31;
                r9d69 = static_cast<uint32_t>(reinterpret_cast<uint64_t>(rsi65) + reinterpret_cast<uint64_t>(rsi65)) | r8d34 >> 31;
                *reinterpret_cast<uint32_t*>(&r8_70) = r8d68 + r8d68 | edx66 >> 31;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_70) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rax71) = *reinterpret_cast<uint32_t*>(&v72);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax71) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rdx73) = edx66 + edx66;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx73) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&r12_74) = static_cast<uint32_t>(rax71 + rdx73);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_74) + 4) = 0;
                r9d75 = r9d69 + r9d69 | r8d68 >> 31;
                if (*reinterpret_cast<uint32_t*>(&r12_74) < *reinterpret_cast<uint32_t*>(&rdx73) || *reinterpret_cast<uint32_t*>(&r12_74) < *reinterpret_cast<uint32_t*>(&rax71)) {
                    eax76 = static_cast<uint32_t>(r8_70 + 1);
                    ecx77 = 0;
                    if (eax76 < *reinterpret_cast<uint32_t*>(&r8_70) || eax76 < 1) {
                        ecx77 = 1;
                    }
                    *reinterpret_cast<uint32_t*>(&r8_70) = eax76;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_70) + 4) = 0;
                    if (ecx77) {
                        ++r9d75;
                    }
                }
                rax78 = v72 >> 32;
                *reinterpret_cast<uint32_t*>(&r14_79) = static_cast<uint32_t>(r8_70 + rax78);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_79) + 4) = 0;
                if (*reinterpret_cast<uint32_t*>(&r14_79) < *reinterpret_cast<uint32_t*>(&r8_70) || *reinterpret_cast<uint32_t*>(&r14_79) < *reinterpret_cast<uint32_t*>(&rax78)) {
                    ++r9d75;
                }
                *reinterpret_cast<uint32_t*>(&r9_80) = r9d75 + *reinterpret_cast<int32_t*>(&rsi67);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_80) + 4) = 0;
                edx35 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r12_74 + r12_74));
                r8d34 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r14_79 + r14_79) | *reinterpret_cast<uint32_t*>(&r12_74) >> 31);
                --r15d61;
                eax81 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r9_80 + r9_80) | *reinterpret_cast<uint32_t*>(&r14_79) >> 31);
                v82 = eax81;
                eax83 = eax81 >> 24;
                *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&v82) + 3) = 0;
                *reinterpret_cast<void***>(r10_63) = reinterpret_cast<void**>(&(*reinterpret_cast<struct s64**>(&eax83))->f48);
                ++r10_63;
                if (reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r15d61) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r15d61 == 0)) 
                    break;
                *reinterpret_cast<uint16_t*>(&rsi53) = v82;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi53) + 4) = 0;
            }
        }
        r10_84 = r10_63 - 1;
        r10_85 = r10_84 - 1;
        if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(r10_84)) >= reinterpret_cast<signed char>(53)) 
            goto addr_18000e63f_73;
    } else {
        *reinterpret_cast<int32_t*>(&rax18) = 32;
        if (v22 == 0x8000) {
            *reinterpret_cast<int32_t*>(&rax18) = 45;
        }
        goto addr_18000dd05_34;
    }
    while (reinterpret_cast<unsigned char>(r10_85) >= reinterpret_cast<unsigned char>(rdi62) && reinterpret_cast<int1_t>(*reinterpret_cast<void***>(r10_85) == 48)) {
        --r10_85;
    }
    if (reinterpret_cast<unsigned char>(r10_85) < reinterpret_cast<unsigned char>(rdi62)) 
        goto addr_18000e6b3_80;
    addr_18000e662_81:
    r10b86 = reinterpret_cast<void*>(reinterpret_cast<signed char>(reinterpret_cast<signed char>(*reinterpret_cast<void**>(&r10_85)) - *reinterpret_cast<signed char*>(&rbx11)) - 3);
    *reinterpret_cast<void**>(rbx11 + 3) = r10b86;
    *reinterpret_cast<signed char*>(static_cast<int64_t>(reinterpret_cast<signed char>(r10b86)) + reinterpret_cast<unsigned char>(rbx11) + 4) = 0;
    addr_18000e676_82:
    rcx87 = v9 ^ reinterpret_cast<uint64_t>(rsp7);
    rax88 = fun_180002f40(rcx87, rcx87);
    return *reinterpret_cast<int32_t*>(&rax88);
    addr_18000e6b3_80:
    *reinterpret_cast<int32_t*>(&rax89) = 32;
    *reinterpret_cast<void***>(rbx11) = reinterpret_cast<void**>(0);
    *reinterpret_cast<void**>(rbx11 + 3) = reinterpret_cast<void*>(1);
    if (v22 == 0x8000) {
        *reinterpret_cast<int32_t*>(&rax89) = 45;
    }
    *reinterpret_cast<unsigned char*>(rbx11 + 2) = *reinterpret_cast<unsigned char*>(&rax89);
    *reinterpret_cast<void***>(rdi62) = reinterpret_cast<void**>(48);
    addr_18000dd12_85:
    *reinterpret_cast<signed char*>(rbx11 + 5) = 0;
    goto addr_18000e676_82;
    addr_18000e63f_73:
    while (reinterpret_cast<unsigned char>(r10_85) >= reinterpret_cast<unsigned char>(rdi62) && reinterpret_cast<int1_t>(*reinterpret_cast<void***>(r10_85) == 57)) {
        *reinterpret_cast<void***>(r10_85) = reinterpret_cast<void**>(48);
        --r10_85;
    }
    if (reinterpret_cast<unsigned char>(r10_85) < reinterpret_cast<unsigned char>(rdi62)) 
        goto addr_18000e658_89;
    addr_18000e65f_90:
    *reinterpret_cast<void***>(r10_85) = *reinterpret_cast<void***>(r10_85) + 1;
    goto addr_18000e662_81;
    addr_18000e658_89:
    ++r10_85;
    *reinterpret_cast<void***>(rbx11) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rbx11)) + reinterpret_cast<unsigned char>(1));
    goto addr_18000e65f_90;
    addr_18000dd05_34:
    *reinterpret_cast<void***>(rbx11) = reinterpret_cast<void**>(0);
    *reinterpret_cast<unsigned char*>(rbx11 + 2) = *reinterpret_cast<unsigned char*>(&rax18);
    *reinterpret_cast<void**>(rbx11 + 3) = reinterpret_cast<void*>(0x3001);
    goto addr_18000dd12_85;
    addr_18000e491_39:
    edx35 = reinterpret_cast<uint16_t>(0);
    r8d34 = reinterpret_cast<uint16_t>(0);
    goto addr_18000e497_36;
    addr_18000e272_43:
    if (*reinterpret_cast<uint16_t*>(&rcx44) || ((*reinterpret_cast<void**>(&r9d49) = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d49)) + reinterpret_cast<unsigned char>(1)), !!(0x3ffbcccc & *reinterpret_cast<uint32_t*>(&rdi30))) || (1 || !0))) {
        do {
            esi90 = r14d27;
            if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r14d27) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r14d27 == 0))) {
                do {
                    r8d91 = 0;
                    *reinterpret_cast<uint32_t*>(&rax92) = v93;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax92) + 4) = 0;
                    r10d94 = static_cast<uint32_t>(rax92);
                    if (r10d94 < *reinterpret_cast<uint32_t*>(&rax92) || r10d94 < 0) {
                        r8d91 = 1;
                    }
                    v93 = r10d94;
                    if (r8d91) {
                    }
                    --esi90;
                } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(esi90) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(esi90 == 0)));
                r14d27 = v29;
            }
            --r14d27;
            v29 = r14d27;
        } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r14d27) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r14d27 == 0)));
        rbx11 = v20;
        r8d95 = reinterpret_cast<uint16_t>(0);
        r9w96 = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d49)) + 0xc002);
        if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r9w96) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r9w96 == 0))) 
            goto addr_18000e331_102;
    } else {
        addr_18000e248_41:
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) = reinterpret_cast<uint16_t>(0);
        goto addr_18000e491_39;
    }
    addr_18000e36d_103:
    r9w96 = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(r9w96) + 0xffff);
    if (reinterpret_cast<int16_t>(r9w96) >= reinterpret_cast<int16_t>(0)) {
        addr_18000e3d2_104:
        eax97 = 0;
    } else {
        ebx98 = 0;
        eax99 = reinterpret_cast<uint16_t>(r9w96);
        *reinterpret_cast<uint32_t*>(&rdx100) = reinterpret_cast<uint16_t>(-*reinterpret_cast<int16_t*>(&eax99));
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx100) + 4) = 0;
        r9w96 = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(r9w96) + reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&rdx100)));
        do {
            if (!1) {
                ++ebx98;
            }
            r8d95 = reinterpret_cast<uint16_t>(0);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v46) + 4) = 0;
            *reinterpret_cast<int32_t*>(&v46) = 0;
            rdx100 = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(rdx100) - 1);
        } while (rdx100);
        rbx11 = v20;
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 8) = reinterpret_cast<uint16_t>(0);
        if (!ebx98) 
            goto addr_18000e3d2_104; else 
            goto addr_18000e3c0_110;
    }
    addr_18000e3d6_111:
    if (reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&eax97)) > 0x8000 || !1) {
        if (1) {
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 2) = reinterpret_cast<uint16_t>(1);
        } else {
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 2) = reinterpret_cast<uint16_t>(0);
            if (1) {
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 6) = reinterpret_cast<uint16_t>(1);
            } else {
                eax101 = reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(reinterpret_cast<int64_t>(&v46) + 10));
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 6) = reinterpret_cast<uint16_t>(0);
                if (!reinterpret_cast<int1_t>(*reinterpret_cast<void**>(&eax101) == 0xffff)) {
                    *reinterpret_cast<void**>(reinterpret_cast<int64_t>(&v46) + 10) = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&eax101)) + reinterpret_cast<unsigned char>(1));
                } else {
                    *reinterpret_cast<void**>(reinterpret_cast<int64_t>(&v46) + 10) = reinterpret_cast<void*>(0x8000);
                    r9w96 = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(r9w96) + reinterpret_cast<unsigned char>(1));
                }
            }
            r8d95 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 8);
        }
    }
    if (reinterpret_cast<uint16_t>(r9w96) < 0x7fff) {
        eax102 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 2);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 6) = r8d95;
        *reinterpret_cast<void***>(&v24) = *reinterpret_cast<void***>(&eax102);
        *reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10) = reinterpret_cast<void**>(reinterpret_cast<uint16_t>(r9w96) | r13w48);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v24) + 2) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v46) + 4);
        r8d34 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 4);
        edx35 = *reinterpret_cast<uint16_t*>(&v24);
        goto addr_18000e49c_48;
    } else {
        r8d34 = reinterpret_cast<uint16_t>(0);
        edx35 = reinterpret_cast<uint16_t>(0);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) = reinterpret_cast<uint16_t>((0x7fff - (0x7fff + reinterpret_cast<uint1_t>(0x7fff < 0x7fff + reinterpret_cast<uint1_t>(!!r13w48))) & 0x80000000) + 0x7fff8000);
        goto addr_18000e49c_48;
    }
    addr_18000e3c0_110:
    *reinterpret_cast<void**>(&eax97) = reinterpret_cast<void*>(1);
    goto addr_18000e3d6_111;
    do {
        addr_18000e331_102:
        if (0) 
            break;
        r9w96 = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(r9w96) + 0xffff);
        r8d95 = reinterpret_cast<uint16_t>(0);
        *reinterpret_cast<int32_t*>(&v46) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v46) + 4) = 0;
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v46) + 8) = reinterpret_cast<uint16_t>(0);
    } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r9w96) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r9w96 == 0)));
    if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r9w96) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r9w96 == 0))) 
        goto addr_18000e3d2_104; else 
        goto addr_18000e36d_103;
    addr_18000e268_47:
    *reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10) = reinterpret_cast<void**>(0);
    goto addr_18000e497_36;
    addr_18000de71_11:
    r8d34 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 4);
    edx35 = *reinterpret_cast<uint16_t*>(&v24);
    while (1) {
        eax103 = r10d33;
        r9_28 = r9_28 + 42;
        r10d33 = reinterpret_cast<uint32_t>(reinterpret_cast<int32_t>(r10d33) >> 3);
        v104 = r10d33;
        v105 = r9_28;
        eax106 = eax103 & 7;
        if (!eax106) {
            addr_18000e1ad_126:
            if (r10d33) 
                continue; else 
                break;
        } else {
            rax107 = reinterpret_cast<int32_t>(eax106);
            rsi108 = reinterpret_cast<struct s65*>(r9_28 + (rax107 + rax107 * 2) * 2);
            if (rsi108->f0 >= 0x8000) {
                rdi30->f0 = rsi108->f0;
                rdi109 = reinterpret_cast<struct s66*>(&rdi30->f4);
                rdi109->f0 = *reinterpret_cast<uint32_t*>(&v72);
                rdi30 = reinterpret_cast<struct s62*>(&rdi109->f4);
                rsi108 = reinterpret_cast<struct s65*>(reinterpret_cast<int64_t>(rbp6) + 7 + 4);
                rax110 = v72 >> 16;
                *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v72) + 2) = *reinterpret_cast<int32_t*>(&rax110) - 1;
            }
            *reinterpret_cast<uint32_t*>(&rcx111) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(rsi108) + 10);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx111) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&rax112) = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax112) + 4) = 0;
            ebx113 = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(&rcx111));
            *reinterpret_cast<void***>(&rcx111) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rcx111)) & reinterpret_cast<unsigned char>(0x7fff));
            *reinterpret_cast<int64_t*>(&v114) = 0;
            bx115 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&ebx113) ^ reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax112)));
            *reinterpret_cast<void***>(&rax112) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax112)) & reinterpret_cast<unsigned char>(0x7fff));
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 8) = reinterpret_cast<uint16_t>(0);
            bx116 = reinterpret_cast<uint16_t>(bx115 & 0x8000);
            r9d117 = static_cast<int32_t>(rax112 + rcx111);
            v118 = bx116;
            if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax112)) >= reinterpret_cast<unsigned char>(0x7fff)) 
                goto addr_18000e18c_136;
            if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rcx111)) < reinterpret_cast<unsigned char>(0x7fff)) 
                goto addr_18000df19_138;
        }
        addr_18000e18c_136:
        cf119 = reinterpret_cast<uint1_t>(!!bx116);
        addr_18000e18f_139:
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) = reinterpret_cast<uint16_t>((*reinterpret_cast<uint32_t*>(&rax112) - (*reinterpret_cast<uint32_t*>(&rax112) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax112) < *reinterpret_cast<uint32_t*>(&rax112) + cf119)) & 0x80000000) + 0x7fff8000);
        addr_18000e1a0_140:
        edx35 = reinterpret_cast<uint16_t>(0);
        r8d34 = reinterpret_cast<uint16_t>(0);
        addr_18000e1a9_141:
        r9_28 = v105;
        goto addr_18000e1ad_126;
        addr_18000df19_138:
        if (reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d117)) > 0xbffd) {
            goto addr_18000e18c_136;
        } else {
            if (reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d117)) <= 0x3fbf) 
                goto addr_18000df34_144;
            if (*reinterpret_cast<void***>(&rax112)) 
                goto addr_18000df6e_146;
            *reinterpret_cast<void**>(&r9d117) = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d117)) + reinterpret_cast<unsigned char>(1));
            if (*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 8) & *reinterpret_cast<uint32_t*>(&rdi30)) 
                goto addr_18000df6e_146;
            if (r8d34) 
                goto addr_18000df6e_146;
            if (!edx35) 
                goto addr_18000df5e_150;
        }
        addr_18000df6e_146:
        if (*reinterpret_cast<void***>(&rcx111) || ((*reinterpret_cast<void**>(&r9d117) = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d117)) + reinterpret_cast<unsigned char>(1)), !!(rsi108->f8 & *reinterpret_cast<uint32_t*>(&rdi30))) || (rsi108->f4 || rsi108->f0))) {
            edi120 = 5;
            do {
                r13d121 = edi120;
                if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(edi120) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(edi120 == 0))) {
                    do {
                        r10d122 = 0;
                        *reinterpret_cast<uint32_t*>(&rax123) = v124;
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax123) + 4) = 0;
                        r8d125 = static_cast<uint32_t>(rax123);
                        if (r8d125 < *reinterpret_cast<uint32_t*>(&rax123) || r8d125 < 0) {
                            r10d122 = 1;
                        }
                        v124 = r8d125;
                        if (r10d122) {
                        }
                        --r13d121;
                    } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r13d121) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r13d121 == 0)));
                }
                --edi120;
            } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(edi120) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(edi120 == 0)));
            r10d126 = reinterpret_cast<uint16_t>(0);
            *reinterpret_cast<void***>(&r9d127) = reinterpret_cast<void**>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&r9d117)) + 0xc002);
            if (!(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r9d127)) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<void***>(&r9d127) == 0))) 
                goto addr_18000e02a_162;
        } else {
            addr_18000df34_144:
            *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(&v24) + 4) = 0;
            goto addr_18000e1a0_140;
        }
        addr_18000e066_163:
        *reinterpret_cast<void***>(&r9d127) = *reinterpret_cast<void***>(&r9d127) + 0xffff;
        if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r9d127)) >= reinterpret_cast<signed char>(0)) {
            addr_18000e0d3_164:
            eax128 = 0;
        } else {
            eax129 = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(&r9d127));
            *reinterpret_cast<uint32_t*>(&rdx130) = reinterpret_cast<uint16_t>(-*reinterpret_cast<int16_t*>(&eax129));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx130) + 4) = 0;
            v131 = reinterpret_cast<uint16_t>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r9d127)) + *reinterpret_cast<uint16_t*>(&rdx130));
            r9d132 = 0;
            do {
                if (!1) {
                    ++r9d132;
                }
                r10d126 = reinterpret_cast<uint16_t>(0);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v114) + 4) = 0;
                *reinterpret_cast<int32_t*>(&v114) = 0;
                rdx130 = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(rdx130) - 1);
            } while (rdx130);
            r9d127 = v131;
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 8) = reinterpret_cast<uint16_t>(0);
            if (!r9d132) 
                goto addr_18000e0d3_164; else 
                goto addr_18000e0c1_170;
        }
        addr_18000e0d7_171:
        if (reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&eax128)) > 0x8000 || !1) {
            if (1) {
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 2) = reinterpret_cast<uint16_t>(1);
            } else {
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 2) = reinterpret_cast<uint16_t>(0);
                if (1) {
                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 6) = reinterpret_cast<uint16_t>(1);
                } else {
                    eax133 = reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(reinterpret_cast<int64_t>(&v114) + 10));
                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 6) = reinterpret_cast<uint16_t>(0);
                    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void**>(&eax133) == 0xffff)) {
                        *reinterpret_cast<void**>(reinterpret_cast<int64_t>(&v114) + 10) = reinterpret_cast<void*>(reinterpret_cast<uint16_t>(*reinterpret_cast<void**>(&eax133)) + reinterpret_cast<unsigned char>(1));
                    } else {
                        *reinterpret_cast<void**>(reinterpret_cast<int64_t>(&v114) + 10) = reinterpret_cast<void*>(0x8000);
                        *reinterpret_cast<void***>(&r9d127) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r9d127)) + reinterpret_cast<unsigned char>(1));
                    }
                }
                r10d126 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 8);
            }
        }
        r14d27 = 5;
        *reinterpret_cast<uint32_t*>(&rdi30) = 0x7fffffff;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi30) + 4) = 0;
        if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r9d127)) < reinterpret_cast<unsigned char>(0x7fff)) {
            eax134 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 2);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 6) = r10d126;
            r10d33 = v104;
            *reinterpret_cast<void***>(&v24) = *reinterpret_cast<void***>(&eax134);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v24) + 2) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v114) + 4);
            r8d34 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v24) + 4);
            edx35 = *reinterpret_cast<uint16_t*>(&v24);
            *reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&r9d127)) | v118);
            goto addr_18000e1a9_141;
        } else {
            *reinterpret_cast<uint32_t*>(&rax112) = v118;
            r10d33 = v104;
            cf119 = reinterpret_cast<uint1_t>(!!*reinterpret_cast<void***>(&rax112));
            *reinterpret_cast<void***>(&rax112) = reinterpret_cast<void**>(-reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax112)));
            goto addr_18000e18f_139;
        }
        addr_18000e0c1_170:
        *reinterpret_cast<void**>(&eax128) = reinterpret_cast<void*>(1);
        goto addr_18000e0d7_171;
        do {
            addr_18000e02a_162:
            if (0) 
                break;
            *reinterpret_cast<void***>(&r9d127) = *reinterpret_cast<void***>(&r9d127) + 0xffff;
            r10d126 = reinterpret_cast<uint16_t>(0);
            *reinterpret_cast<int32_t*>(&v114) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v114) + 4) = 0;
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v114) + 8) = reinterpret_cast<uint16_t>(0);
        } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r9d127)) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<void***>(&r9d127) == 0)));
        if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r9d127)) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<void***>(&r9d127) == 0))) 
            goto addr_18000e0d3_164; else 
            goto addr_18000e066_163;
        addr_18000df5e_150:
        *reinterpret_cast<void***>(reinterpret_cast<int64_t>(&v24) + 10) = reinterpret_cast<void**>(0);
        goto addr_18000e1a9_141;
    }
    rbx11 = v20;
    ecx31 = v32;
    goto addr_18000e1cb_35;
    addr_18000e730_17:
    goto IsProcessorFeaturePresent;
    addr_18000dde2_19:
    goto addr_18000e676_82;
    addr_18000e6f1_26:
    fun_18000391c();
    goto addr_18000e706_21;
}

int64_t fun_180004e94(void** ecx, void** rdx, void** r8) {
    void** rsi4;
    void** rax5;
    void** rbx6;
    void** rdx7;
    void** rcx8;
    void** r8_9;
    int64_t rax10;
    void** rbp11;
    int64_t rcx12;
    void* rdx13;
    void** edi14;
    int64_t rdx15;

    if (!reinterpret_cast<int1_t>(ecx == 0xe06d7363)) {
        return 0;
    }
    rsi4 = rdx;
    rax5 = fun_18000503c();
    rbx6 = rax5;
    if (!rax5) 
        goto addr_180004e7d_5;
    rdx7 = *reinterpret_cast<void***>(rax5 + 0xa0);
    rcx8 = rdx7;
    do {
        if (*reinterpret_cast<void***>(rcx8) == 0xe06d7363) 
            break;
        rcx8 = rcx8 + 16;
    } while (reinterpret_cast<unsigned char>(rcx8) < reinterpret_cast<unsigned char>(rdx7 + 0xc0));
    if (reinterpret_cast<unsigned char>(rcx8) >= reinterpret_cast<unsigned char>(rdx7 + 0xc0)) 
        goto addr_180004d23_10;
    if (*reinterpret_cast<void***>(rcx8) == 0xe06d7363) 
        goto addr_180004d26_12;
    addr_180004d23_10:
    rcx8 = reinterpret_cast<void**>(0);
    addr_180004d26_12:
    if (!rcx8 || (r8_9 = *reinterpret_cast<void***>(rcx8 + 8), r8_9 == 0)) {
        addr_180004e7d_5:
        *reinterpret_cast<uint32_t*>(&rax10) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax10) + 4) = 0;
    } else {
        if (!reinterpret_cast<int1_t>(r8_9 == 5)) {
            if (!reinterpret_cast<int1_t>(r8_9 == 1)) {
                rbp11 = *reinterpret_cast<void***>(rbx6 + 0xa8);
                *reinterpret_cast<void***>(rbx6 + 0xa8) = rsi4;
                if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8 + 4) == 8)) {
                    *reinterpret_cast<void***>(rcx8 + 8) = reinterpret_cast<void**>(0);
                    *reinterpret_cast<void***>(&rcx12) = *reinterpret_cast<void***>(rcx8 + 4);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx12) + 4) = 0;
                    r8_9(rcx12);
                    goto addr_180004e71_17;
                } else {
                    *reinterpret_cast<int32_t*>(&rdx13) = 48;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx13) + 4) = 0;
                    do {
                        rdx13 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rdx13) + 16);
                        *reinterpret_cast<void***>(reinterpret_cast<int64_t>(rdx13) + reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rbx6 + 0xa0)) + 0xfffffffffffffff8) = reinterpret_cast<void**>(0);
                    } while (reinterpret_cast<int64_t>(rdx13) < 0xc0);
                    edi14 = *reinterpret_cast<void***>(rbx6 + 0xb0);
                    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc000008e)) 
                        goto addr_180004db0_21; else 
                        goto addr_180004da1_22;
                }
            } else {
                addr_180004d55_23:
                *reinterpret_cast<uint32_t*>(&rax10) = 0xffffffff;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax10) + 4) = 0;
            }
        } else {
            *reinterpret_cast<void***>(rcx8 + 8) = reinterpret_cast<void**>(0);
            *reinterpret_cast<uint32_t*>(&rax10) = static_cast<uint32_t>(reinterpret_cast<uint64_t>(r8_9 + 0xfffffffffffffffc));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax10) + 4) = 0;
        }
    }
    return rax10;
    addr_180004e71_17:
    *reinterpret_cast<void***>(rbx6 + 0xa8) = rbp11;
    goto addr_180004d55_23;
    addr_180004db0_21:
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc0000090)) {
        if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc0000091)) {
            if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc0000093)) {
                if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc000008d)) {
                    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc000008f)) {
                        if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc0000092)) {
                            if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc00002b5)) {
                                if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx8) == 0xc00002b4)) {
                                    *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x8e);
                                }
                            } else {
                                *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x8d);
                            }
                        } else {
                            *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x8a);
                        }
                    } else {
                        *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x86);
                    }
                } else {
                    *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x82);
                }
            } else {
                *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x85);
            }
        } else {
            *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x84);
        }
    } else {
        *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x81);
    }
    addr_180004e51_41:
    *reinterpret_cast<void***>(&rdx15) = *reinterpret_cast<void***>(rbx6 + 0xb0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx15) + 4) = 0;
    r8_9(8, rdx15);
    *reinterpret_cast<void***>(rbx6 + 0xb0) = edi14;
    goto addr_180004e71_17;
    addr_180004da1_22:
    *reinterpret_cast<void***>(rbx6 + 0xb0) = reinterpret_cast<void**>(0x83);
    goto addr_180004e51_41;
}

uint32_t fun_180002e1c(unsigned char* rcx, void* rdx, void* r8, int64_t r9);

uint32_t fun_180002d10(unsigned char* rcx, void* rdx, void* r8, void* r9, ...) {
    uint32_t eax5;

    eax5 = fun_180002e1c(rcx, rdx, r8, 0);
    return eax5;
}

uint32_t fun_180002e8c(unsigned char* rcx, void* rdx, void* r8, void** r9) {
    uint32_t eax5;

    eax5 = fun_180002e1c(rcx, rdx, r8, 0);
    return eax5;
}

struct s68 {
    struct s68* f0;
    signed char[39] pad40;
    struct s68* f40;
    signed char[7] pad48;
    struct s68* f48;
    signed char[7] pad56;
    signed char* f56;
    struct s68* f64;
};

struct s67 {
    int64_t f0;
    signed char[40] pad48;
    struct s68* f48;
};

int64_t CancelIoEx = 0x163ee;

int64_t fun_1800027f0(struct s67* rcx, int64_t rdx, void** r8, void** r9) {
    int64_t v5;
    int32_t ebx6;
    int32_t eax7;
    int32_t eax8;
    void** r8_9;
    int64_t v10;
    int64_t rax11;

    fun_1800010e0(2, ">>> SensorAdapterCancel", r8, r9, v5);
    ebx6 = 0;
    if (rcx) {
        if (rcx->f0 != -1) {
            eax7 = reinterpret_cast<int32_t>(CancelIoEx());
            if (!eax7 && ((eax8 = reinterpret_cast<int32_t>(GetLastError()), eax8 != 0x490) && (eax8 == 0x4c7 || (ebx6 = 0x80098036, eax8 == 0x3e3)))) {
                ebx6 = 0x80098004;
            }
        } else {
            ebx6 = 0x8009800f;
        }
    } else {
        ebx6 = 0x80004003;
    }
    *reinterpret_cast<int32_t*>(&r8_9) = ebx6;
    *reinterpret_cast<int32_t*>(&r8_9 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterCancel : ErrorCode [0x%08X]", r8_9, r9, v10);
    *reinterpret_cast<int32_t*>(&rax11) = ebx6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax11) + 4) = 0;
    return rax11;
}

int64_t g18001cd68;

void** fun_180003894(int64_t rcx, int64_t rdx, int64_t r8, int32_t r9d) {
    int64_t rcx5;
    int64_t rax6;
    int64_t v7;

    rcx5 = g18001cd68;
    rax6 = reinterpret_cast<int64_t>(DecodePointer(rcx5));
    if (!rax6) {
        fun_18000391c();
        fun_180003894(0, 0, 0, 0);
        goto v7;
    } else {
        goto rax6;
    }
}

struct s69 {
    signed char[8] pad8;
    unsigned char f8;
};

uint32_t fun_180003a38(int32_t ecx, void** rdx, void** r8, void** r9) {
    int32_t v5;
    void** rax6;
    void* rsp7;
    void** ecx8;
    int64_t rsi9;
    void** edi10;
    void** eax11;
    void** eax12;
    struct s8* rax13;
    struct s8* rax14;
    uint32_t eax15;
    void** ebp16;
    void** rdx17;
    struct s69* rdx18;
    int64_t rcx19;
    int64_t rcx20;
    void** r8_21;
    uint32_t eax22;

    v5 = ecx;
    rax6 = fun_180006ca8(rdx, rdx);
    rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 32 - 8 + 8);
    ecx8 = *reinterpret_cast<void***>(rdx + 24);
    rsi9 = reinterpret_cast<int32_t>(rax6);
    if (!(*reinterpret_cast<unsigned char*>(&ecx8) & 0x82)) {
        rax6 = fun_1800039c8();
        *reinterpret_cast<void***>(rax6) = reinterpret_cast<void**>(9);
        goto addr_180003a70_3;
    }
    if (*reinterpret_cast<unsigned char*>(&ecx8) & 64) {
        rax6 = fun_1800039c8();
        *reinterpret_cast<void***>(rax6) = reinterpret_cast<void**>(34);
        goto addr_180003a70_3;
    }
    edi10 = reinterpret_cast<void**>(0);
    if (*reinterpret_cast<unsigned char*>(&ecx8) & 1) 
        goto addr_180003a95_7;
    addr_180003aae_8:
    eax11 = *reinterpret_cast<void***>(rdx + 24);
    *reinterpret_cast<void***>(rdx + 8) = reinterpret_cast<void**>(0);
    eax12 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(eax11) & 0xffffffef | 2);
    *reinterpret_cast<void***>(rdx + 24) = eax12;
    if (!(reinterpret_cast<unsigned char>(eax12) & 0x10c) && ((rax13 = fun_180006b94(), rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 8 + 8), rdx != &rax13->f48) && (rax14 = fun_180006b94(), rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 8 + 8), !reinterpret_cast<int1_t>(rdx == &rax14->f96)) || (eax15 = fun_180006cd0(*reinterpret_cast<void***>(&rsi9)), rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 8 + 8), !eax15))) {
        fun_180007784(rdx, rdx);
        rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 8 + 8);
    }
    if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx + 24)) & 0x108)) {
        ebp16 = reinterpret_cast<void**>(1);
        rax6 = fun_180006d30(*reinterpret_cast<void***>(&rsi9), reinterpret_cast<int64_t>(rsp7) + 48, 1);
        edi10 = rax6;
    } else {
        rdx17 = *reinterpret_cast<void***>(rdx + 16);
        ebp16 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx)) - reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx + 16)));
        *reinterpret_cast<void***>(rdx) = rdx17 + 1;
        *reinterpret_cast<void***>(rdx + 8) = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(rdx + 36)) - 1);
        if (reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(ebp16) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(ebp16 == 0)) {
            if (reinterpret_cast<unsigned char>(static_cast<uint32_t>(rsi9 + 2)) <= reinterpret_cast<unsigned char>(1)) {
                rdx18 = reinterpret_cast<struct s69*>(0x180017240);
            } else {
                rcx19 = rsi9;
                *reinterpret_cast<uint32_t*>(&rcx20) = *reinterpret_cast<uint32_t*>(&rcx19) & 31;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx20) + 4) = 0;
                rdx18 = reinterpret_cast<struct s69*>(rcx20 * 88 + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x18001d350 + reinterpret_cast<unsigned char>(rsi9 >> 5) * 8)));
            }
            if (!(rdx18->f8 & 32)) 
                goto addr_180003b7f_17;
            rax6 = fun_180007608(*reinterpret_cast<void***>(&rsi9), 0, 2);
            if (rax6 == 0xffffffffffffffff) 
                goto addr_180003a70_3;
        } else {
            r8_21 = ebp16;
            *reinterpret_cast<int32_t*>(&r8_21 + 4) = 0;
            rax6 = fun_180006d30(*reinterpret_cast<void***>(&rsi9), rdx17, r8_21);
            edi10 = rax6;
        }
        addr_180003b7f_17:
        *reinterpret_cast<void***>(*reinterpret_cast<void***>(rdx + 16)) = *reinterpret_cast<void***>(&v5);
    }
    if (edi10 != ebp16) {
        addr_180003a70_3:
        *reinterpret_cast<void***>(rdx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx + 24)) | 32);
    } else {
        eax22 = reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&v5));
        goto addr_180003bae_22;
    }
    addr_180003a74_23:
    eax22 = 0xffffffff;
    addr_180003bae_22:
    return eax22;
    addr_180003a95_7:
    *reinterpret_cast<void***>(rdx + 8) = reinterpret_cast<void**>(0);
    if (!(*reinterpret_cast<unsigned char*>(&ecx8) & 16)) {
        *reinterpret_cast<void***>(rdx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(ecx8) | 32);
        goto addr_180003a74_23;
    } else {
        *reinterpret_cast<void***>(rdx) = *reinterpret_cast<void***>(rdx + 16);
        *reinterpret_cast<void***>(rdx + 24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(ecx8) & 0xfffffffe);
        goto addr_180003aae_8;
    }
}

void fun_1800054a8();

int32_t fun_180008a74();

int32_t fun_180005184() {
    int32_t eax1;
    uint32_t eax2;
    void** r8_3;
    void** rax4;
    int64_t rcx5;
    int32_t eax6;
    int32_t eax7;
    void** r8_8;
    void** eax9;

    fun_1800054a8();
    eax1 = fun_180008a74();
    if (!eax1 || ((eax2 = fun_1800061c4(fun_180004ea8), g180017238 = eax2, eax2 == 0xffffffff) || ((rax4 = fun_1800066f0(1, 0x478, r8_3), rax4 == 0) || (*reinterpret_cast<uint32_t*>(&rcx5) = g180017238, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx5) + 4) = 0, eax6 = fun_180006218(rcx5, rcx5), eax6 == 0)))) {
        fun_180005204();
        eax7 = 0;
    } else {
        fun_1800050c0(rax4, 0, r8_8);
        eax9 = reinterpret_cast<void**>(GetCurrentThreadId(rax4));
        *reinterpret_cast<void***>(rax4 + 8) = reinterpret_cast<void**>(0xffffffffffffffff);
        *reinterpret_cast<void***>(rax4) = eax9;
        eax7 = 1;
    }
    return eax7;
}

void fun_180006870() {
    int64_t* rbx1;
    int64_t rax2;

    rbx1 = reinterpret_cast<int64_t*>(0x1800154c0);
    while (reinterpret_cast<uint64_t>(rbx1) < 0x1800154c0) {
        rax2 = *rbx1;
        if (rax2) {
            rax2();
        }
        ++rbx1;
    }
    return;
}

int64_t GetStartupInfoW = 0x1654a;

struct s70 {
    void** f0;
    signed char[3] pad4;
    unsigned char f4;
};

struct s71 {
    void** f0;
    signed char[7] pad8;
    signed char f8;
    signed char[3] pad12;
    int32_t f12;
    void** f16;
};

int64_t GetFileType = 0x16524;

struct s72 {
    void** f0;
    signed char[7] pad8;
    unsigned char f8;
    signed char[3] pad12;
    int32_t f12;
    void** f16;
};

uint32_t fun_18000576c() {
    void** rdx1;
    void** r8_2;
    void** rdx3;
    void** r8_4;
    void** rax5;
    void* rsp6;
    void** rcx7;
    void** rcx8;
    int16_t v9;
    struct s70* v10;
    uint32_t eax11;
    int64_t rdi12;
    int64_t rsi13;
    struct s71* tmp64_14;
    int64_t rcx15;
    void** rax16;
    int32_t eax17;
    int32_t eax18;
    uint32_t eax19;
    void** rax20;
    uint32_t eax21;
    uint32_t eax22;
    unsigned char* r14_23;
    void*** rsi24;
    void** r15d25;
    int32_t ebx26;
    int1_t less27;
    void** rax28;
    void** tmp32_29;
    void** edi30;
    int32_t eax31;
    int64_t rcx32;
    int64_t rcx33;
    struct s72* rbx34;

    fun_1800088e8(11, rdx1, r8_2);
    *reinterpret_cast<int32_t*>(&rdx3) = 88;
    *reinterpret_cast<int32_t*>(&rdx3 + 4) = 0;
    rax5 = fun_1800066f0(32, 88, r8_4);
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 0xc0 - 8 + 8 - 8 + 8);
    rcx7 = rax5;
    if (rax5) {
        g18001d350 = rax5;
        g18001f0e8 = reinterpret_cast<void**>(32);
        while (reinterpret_cast<unsigned char>(rcx7) < reinterpret_cast<unsigned char>(rax5 + 0xb00)) {
            *reinterpret_cast<void***>(rcx7 + 8) = reinterpret_cast<void**>(0xa00);
            *reinterpret_cast<void***>(rcx7) = reinterpret_cast<void**>(0xffffffffffffffff);
            *reinterpret_cast<void***>(rcx7 + 12) = reinterpret_cast<void**>(0);
            *reinterpret_cast<void***>(rcx7 + 56) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx7 + 56)) & 0x80);
            *reinterpret_cast<void***>(rcx7 + 56) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx7 + 56)) & 0x7f);
            *reinterpret_cast<int16_t*>(rcx7 + 57) = 0xa0a;
            *reinterpret_cast<void***>(rcx7 + 80) = reinterpret_cast<void**>(0);
            *reinterpret_cast<signed char*>(rcx7 + 76) = 0;
            rcx7 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rcx7) + reinterpret_cast<unsigned char>(88));
            rax5 = g18001d350;
        }
        rcx8 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rsp6) + 80);
        GetStartupInfoW();
        if (!v9) 
            goto addr_180005986_6;
        if (v10) 
            goto addr_180005855_8;
    } else {
        fun_180009320(rsp6, 0x1800057d0);
        eax11 = 0xffffffff;
        goto addr_180005a77_10;
    }
    addr_180005986_6:
    *reinterpret_cast<void***>(&rdi12) = reinterpret_cast<void**>(0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi12) + 4) = 0;
    while (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&rdi12)) < reinterpret_cast<signed char>(3)) {
        rsi13 = reinterpret_cast<int32_t>(*reinterpret_cast<void***>(&rdi12));
        tmp64_14 = reinterpret_cast<struct s71*>(g18001d350 + rsi13 * 88);
        if (reinterpret_cast<uint64_t>(tmp64_14->f0 + 2) <= 1) {
            tmp64_14->f8 = 0x81;
            *reinterpret_cast<uint32_t*>(&rcx15) = *reinterpret_cast<uint32_t*>(&rcx8) - (*reinterpret_cast<uint32_t*>(&rcx8) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rcx8) < *reinterpret_cast<uint32_t*>(&rcx8) + reinterpret_cast<uint1_t>(!!static_cast<int32_t>(rdi12 - 1)))) - 11;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx15) + 4) = 0;
            if (!*reinterpret_cast<void***>(&rdi12)) {
                *reinterpret_cast<uint32_t*>(&rcx15) = 0xfffffff6;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx15) + 4) = 0;
            }
            rax16 = reinterpret_cast<void**>(GetStdHandle(rcx15, rdx3));
            rcx8 = rax16 + 1;
            if (reinterpret_cast<unsigned char>(rcx8) <= reinterpret_cast<unsigned char>(1)) 
                goto addr_180005a3f_16;
            rcx8 = rax16;
            eax17 = reinterpret_cast<int32_t>(GetFileType());
            if (eax17) 
                goto addr_180005a06_18;
        } else {
            eax18 = tmp64_14->f8;
            __asm__("bts eax, 0x7");
            tmp64_14->f8 = *reinterpret_cast<signed char*>(&eax18);
            goto addr_180005a60_20;
        }
        addr_180005a3f_16:
        eax19 = reinterpret_cast<uint32_t>(static_cast<int32_t>(tmp64_14->f8)) | 64;
        tmp64_14->f8 = *reinterpret_cast<signed char*>(&eax19);
        tmp64_14->f0 = reinterpret_cast<void**>(0xfffffffffffffffe);
        rax20 = g18001dfa0;
        if (rax20) {
            *reinterpret_cast<void***>(*reinterpret_cast<void***>(rax20 + rsi13 * 8) + 28) = reinterpret_cast<void**>(0xfffffffe);
        }
        addr_180005a60_20:
        *reinterpret_cast<void***>(&rdi12) = *reinterpret_cast<void***>(&rdi12) + 1;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi12) + 4) = 0;
        continue;
        addr_180005a06_18:
        tmp64_14->f0 = rax16;
        eax21 = *reinterpret_cast<unsigned char*>(&eax17);
        if (eax21 != 2) {
            if (eax21 != 3) {
                addr_180005a29_23:
                rcx8 = reinterpret_cast<void**>(&tmp64_14->f16);
                *reinterpret_cast<int32_t*>(&rdx3) = 0xfa0;
                *reinterpret_cast<int32_t*>(&rdx3 + 4) = 0;
                fun_180006234(rcx8, 0xfa0);
                tmp64_14->f12 = tmp64_14->f12 + 1;
                goto addr_180005a60_20;
            } else {
                eax22 = reinterpret_cast<uint32_t>(static_cast<int32_t>(tmp64_14->f8)) | 8;
            }
        } else {
            eax22 = reinterpret_cast<uint32_t>(static_cast<int32_t>(tmp64_14->f8)) | 64;
        }
        tmp64_14->f8 = *reinterpret_cast<signed char*>(&eax22);
        goto addr_180005a29_23;
    }
    fun_180008ad8(11, 11);
    eax11 = 0;
    addr_180005a77_10:
    return eax11;
    addr_180005855_8:
    r14_23 = &v10->f4;
    rsi24 = reinterpret_cast<void***>(reinterpret_cast<int32_t>(v10->f0) + reinterpret_cast<int64_t>(r14_23));
    r15d25 = reinterpret_cast<void**>(0x800);
    if (reinterpret_cast<signed char>(v10->f0) < reinterpret_cast<signed char>(0x800)) {
        r15d25 = v10->f0;
    }
    ebx26 = 1;
    while (less27 = reinterpret_cast<signed char>(g18001f0e8) < reinterpret_cast<signed char>(r15d25), less27) {
        rdx3 = reinterpret_cast<void**>(88);
        rax28 = fun_1800066f0(32, 88, 0x18001d350);
        rcx8 = rax28;
        if (!rax28) 
            goto addr_1800058a0_32;
        rdx3 = reinterpret_cast<void**>(static_cast<int64_t>(ebx26));
        *reinterpret_cast<void***>(reinterpret_cast<unsigned char>(0x18001d350) + reinterpret_cast<unsigned char>(rdx3) * 8) = rax28;
        tmp32_29 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(g18001f0e8) + reinterpret_cast<unsigned char>(32));
        g18001f0e8 = tmp32_29;
        while (reinterpret_cast<unsigned char>(rcx8) < reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(reinterpret_cast<unsigned char>(0x18001d350) + reinterpret_cast<unsigned char>(rdx3) * 8) + 0xb00)) {
            *reinterpret_cast<void***>(rcx8 + 8) = reinterpret_cast<void**>(0xa00);
            *reinterpret_cast<void***>(rcx8) = reinterpret_cast<void**>(0xffffffffffffffff);
            *reinterpret_cast<void***>(rcx8 + 12) = reinterpret_cast<void**>(0);
            *reinterpret_cast<void***>(rcx8 + 56) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx8 + 56)) & 0x80);
            *reinterpret_cast<int16_t*>(rcx8 + 57) = 0xa0a;
            *reinterpret_cast<void***>(rcx8 + 80) = reinterpret_cast<void**>(0);
            *reinterpret_cast<signed char*>(rcx8 + 76) = 0;
            rcx8 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rcx8) + reinterpret_cast<unsigned char>(88));
        }
        ++ebx26;
    }
    addr_1800058fb_37:
    edi30 = reinterpret_cast<void**>(0);
    while (reinterpret_cast<signed char>(edi30) < reinterpret_cast<signed char>(r15d25)) {
        rcx8 = *rsi24;
        if (reinterpret_cast<uint64_t>(rcx8 + 2) > 1 && (*r14_23 & 1 && (*r14_23 & 8 || (eax31 = reinterpret_cast<int32_t>(GetFileType()), !!eax31)))) {
            rcx32 = reinterpret_cast<int32_t>(edi30);
            *reinterpret_cast<uint32_t*>(&rcx33) = *reinterpret_cast<uint32_t*>(&rcx32) & 31;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx33) + 4) = 0;
            rbx34 = reinterpret_cast<struct s72*>(*reinterpret_cast<void****>(0x18001d350 + (rcx32 >> 5) * 8) + rcx33 * 88);
            rbx34->f0 = *rsi24;
            rbx34->f8 = *r14_23;
            rcx8 = reinterpret_cast<void**>(&rbx34->f16);
            *reinterpret_cast<int32_t*>(&rdx3) = 0xfa0;
            *reinterpret_cast<int32_t*>(&rdx3 + 4) = 0;
            fun_180006234(rcx8, 0xfa0);
            rbx34->f12 = rbx34->f12 + 1;
        }
        ++edi30;
        ++r14_23;
        rsi24 = rsi24 + 8;
    }
    goto addr_180005986_6;
    addr_1800058a0_32:
    r15d25 = g18001f0e8;
    goto addr_1800058fb_37;
}

signed char g18001d654;

int64_t GetModuleFileNameA = 0x1655c;

void*** g18001d310;

int32_t g18001d2ec;

uint32_t fun_180005b10() {
    void* rsp1;
    int1_t zf2;
    void* rsp3;
    void*** rbx4;
    uint64_t rsi5;
    int32_t v6;
    void** rcx7;
    int32_t v8;
    void** rdx9;
    void** rax10;
    uint32_t eax11;
    int32_t v12;

    rsp1 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 48);
    zf2 = g18001f108 == 0;
    if (zf2) {
        fun_180007b7c();
        rsp1 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp1) - 8 + 8);
    }
    g18001d654 = 0;
    GetModuleFileNameA();
    rsp3 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp1) - 8 + 8);
    rbx4 = g18001f110;
    g18001d310 = reinterpret_cast<void***>(0x18001d550);
    if (!rbx4 || !*rbx4) {
        rbx4 = reinterpret_cast<void***>(0x18001d550);
    }
    fun_180005c04(rbx4, 0, 0, reinterpret_cast<int64_t>(rsp3) + 64);
    rsi5 = reinterpret_cast<uint64_t>(static_cast<int64_t>(v6));
    if (rsi5 >= 0x1fffffffffffffff || ((rcx7 = reinterpret_cast<void**>(static_cast<int64_t>(v8)), reinterpret_cast<unsigned char>(rcx7) >= reinterpret_cast<unsigned char>(0xffffffffffffffff)) || ((rdx9 = rcx7 + rsi5 * 8, reinterpret_cast<unsigned char>(rdx9) < reinterpret_cast<unsigned char>(rcx7)) || (rax10 = fun_180006770(rdx9, rdx9), rax10 == 0)))) {
        eax11 = 0xffffffff;
    } else {
        fun_180005c04(rbx4, rax10, rax10 + rsi5 * 8, reinterpret_cast<int64_t>(rsp3) - 8 + 8 - 8 + 8 + 64);
        g18001d2f0 = rax10;
        g18001d2ec = v12 - 1;
        eax11 = 0;
    }
    return eax11;
}

void** fun_180005284() {
    void** rcx1;
    void** rax2;
    void** rbx3;
    void** rdi4;
    void** rcx5;
    void** rbx6;
    void** rcx7;
    void** rcx8;
    void** rcx9;
    int1_t zf10;
    void** rax11;
    void** rcx12;
    void** rcx13;
    void** rax14;
    void** rcx15;

    rcx1 = g18001f100;
    rax2 = reinterpret_cast<void**>(DecodePointer(rcx1));
    rbx3 = g18001d308;
    rdi4 = rax2;
    if (rbx3) {
        do {
            rcx5 = *reinterpret_cast<void***>(rbx3);
            if (!rcx5) 
                break;
            fun_180005f00(rcx5);
            rbx3 = rbx3 + 8;
        } while (rbx3);
        rbx3 = g18001d308;
    }
    fun_180005f00(rbx3);
    rbx6 = g18001d300;
    g18001d308 = reinterpret_cast<void**>(0);
    if (rbx6) {
        do {
            rcx7 = *reinterpret_cast<void***>(rbx6);
            if (!rcx7) 
                break;
            fun_180005f00(rcx7);
            rbx6 = rbx6 + 8;
        } while (rbx6);
        rbx6 = g18001d300;
    }
    fun_180005f00(rbx6);
    rcx8 = g18001d2f8;
    g18001d300 = reinterpret_cast<void**>(0);
    fun_180005f00(rcx8);
    rcx9 = g18001d2f0;
    fun_180005f00(rcx9);
    g18001d2f8 = reinterpret_cast<void**>(0);
    g18001d2f0 = reinterpret_cast<void**>(0);
    if (rdi4 != 0xffffffffffffffff && (zf10 = g18001f100 == 0, !zf10)) {
        fun_180005f00(rdi4);
    }
    rax11 = reinterpret_cast<void**>(EncodePointer(-1));
    rcx12 = g18001df40;
    g18001f100 = rax11;
    if (rcx12) {
        fun_180005f00(rcx12);
        g18001df40 = reinterpret_cast<void**>(0);
    }
    rcx13 = g18001df48;
    if (rcx13) {
        fun_180005f00(rcx13);
        g18001df48 = reinterpret_cast<void**>(0);
    }
    rax14 = g180017b90;
    __asm__("lock xadd [rax], ecx");
    if (!1 && (rcx15 = g180017b90, rcx15 != 0x180017870)) {
        rax14 = fun_180005f00(rcx15);
        g180017b90 = reinterpret_cast<void**>(0x180017870);
    }
    return rax14;
}

void fun_1800055a8(int32_t ecx, void** rdx, void** r8) {
    int32_t r14d4;
    int32_t r13d5;
    int1_t zf6;
    void** rcx7;
    int64_t* rax8;
    int64_t* rsi9;
    void** rcx10;
    int64_t* rax11;
    int64_t* rdi12;
    int64_t* r12_13;
    int64_t* r15_14;
    int64_t rax15;
    int64_t rcx16;
    int64_t rax17;
    int64_t rax18;
    void** rcx19;
    int64_t* rax20;
    void** rcx21;
    int64_t* rax22;
    int64_t rcx23;

    r14d4 = *reinterpret_cast<int32_t*>(&r8);
    r13d5 = ecx;
    fun_1800088e8(8, rdx, r8);
    zf6 = g18001d2e8 == 1;
    if (!zf6) {
        g18001d328 = 1;
        g18001d324 = *reinterpret_cast<signed char*>(&r14d4);
        if (!*reinterpret_cast<int32_t*>(&rdx)) {
            rcx7 = g18001f100;
            rax8 = reinterpret_cast<int64_t*>(DecodePointer(rcx7));
            rsi9 = rax8;
            if (rax8) {
                rcx10 = g18001f0f8;
                rax11 = reinterpret_cast<int64_t*>(DecodePointer(rcx10));
                rdi12 = rax11;
                r12_13 = rsi9;
                r15_14 = rax11;
                while (--rdi12, reinterpret_cast<uint64_t>(rdi12) >= reinterpret_cast<uint64_t>(rsi9)) {
                    rax15 = reinterpret_cast<int64_t>(EncodePointer());
                    if (*rdi12 != rax15) {
                        if (reinterpret_cast<uint64_t>(rdi12) < reinterpret_cast<uint64_t>(rsi9)) 
                            break;
                        rcx16 = *rdi12;
                        rax17 = reinterpret_cast<int64_t>(DecodePointer(rcx16));
                        rax18 = reinterpret_cast<int64_t>(EncodePointer());
                        *rdi12 = rax18;
                        rax17();
                        rcx19 = g18001f100;
                        rax20 = reinterpret_cast<int64_t*>(DecodePointer(rcx19));
                        rcx21 = g18001f0f8;
                        rax22 = reinterpret_cast<int64_t*>(DecodePointer(rcx21));
                        if (r12_13 != rax20) 
                            goto addr_1800056a2_9;
                        if (r15_14 == rax22) 
                            goto addr_18000565b_11;
                    } else {
                        addr_18000565b_11:
                        continue;
                    }
                    addr_1800056a2_9:
                    r12_13 = rax20;
                    rsi9 = rax20;
                    r15_14 = rax22;
                    rdi12 = rax22;
                    goto addr_18000565b_11;
                }
            }
            fun_1800054f4(0x18000f2b0, 0x18000f2d0);
        }
        rdx = reinterpret_cast<void**>(0x18000f2e0);
        fun_1800054f4(0x18000f2d8, 0x18000f2e0);
    }
    if (!r14d4 || (fun_180008ad8(8, 8), !r14d4)) {
        g18001d2e8 = 1;
        fun_180008ad8(8, 8);
        fun_180005228(r13d5, rdx);
        *reinterpret_cast<int32_t*>(&rcx23) = r13d5;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx23) + 4) = 0;
        ExitProcess(rcx23, rdx);
    }
    return;
}

void fun_18000391c() {
    int32_t eax1;

    eax1 = fun_18000e730(23);
    if (eax1) {
        __asm__("int 0x29");
    }
    fun_180003798(2, 0xc0000417, 1);
    GetCurrentProcess();
    goto TerminateProcess;
}

void fun_180006b9c(void** rcx) {
    void** rdx2;
    void* rcx3;
    void** r8_4;

    if (reinterpret_cast<unsigned char>(rcx) < reinterpret_cast<unsigned char>(0x1800172a0) || reinterpret_cast<unsigned char>(rcx) > reinterpret_cast<unsigned char>(0x180017630)) {
        goto EnterCriticalSection;
    } else {
        rdx2 = reinterpret_cast<void**>(__intrinsic() >> 3);
        rcx3 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(reinterpret_cast<unsigned char>(rdx2) >> 63) + reinterpret_cast<unsigned char>(rdx2));
        fun_1800088e8(*reinterpret_cast<int32_t*>(&rcx3) + 16, rdx2, r8_4);
        __asm__("bts dword [rbx+0x18], 0xf");
        return;
    }
}

struct s73 {
    signed char[4] pad4;
    int32_t f4;
    signed char[304] pad312;
    int64_t f312;
};

struct s74 {
    signed char[200] pad200;
    uint32_t f200;
};

void** fun_1800085b0(uint32_t* rcx, void** rdx, void** r8, uint16_t r9w) {
    void** eax5;
    void** v6;
    struct s73* v7;
    int64_t rcx8;
    uint32_t eax9;
    int32_t eax10;
    void** rax11;
    void** rax12;
    void** ebx13;
    uint32_t eax14;
    signed char v15;
    struct s74* v16;
    void** rax17;
    void** rax18;

    if (rdx || !r8) {
        if (rcx) {
            *rcx = 0xffffffff;
        }
        if (reinterpret_cast<unsigned char>(r8) > reinterpret_cast<unsigned char>(0x7fffffff)) 
            goto addr_1800085f7_5;
    } else {
        if (rcx) {
            *rcx = *rcx & *reinterpret_cast<uint32_t*>(&rdx);
        }
        eax5 = reinterpret_cast<void**>(0);
        goto addr_18000867b_9;
    }
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 96 + 64, v6);
    if (v7->f312) {
        *reinterpret_cast<int32_t*>(&rcx8) = v7->f4;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx8) + 4) = 0;
        eax9 = reinterpret_cast<uint32_t>(WideCharToMultiByte(rcx8));
        if (!eax9) {
            eax10 = reinterpret_cast<int32_t>(GetLastError(rcx8));
            if (eax10 != 0x7a) {
                addr_180008654_13:
                rax11 = fun_1800039c8();
                *reinterpret_cast<void***>(rax11) = reinterpret_cast<void**>(42);
                rax12 = fun_1800039c8();
                ebx13 = *reinterpret_cast<void***>(rax12);
            } else {
                if (rdx && r8) {
                    fun_180003c80(rdx, 0, r8, rdx, 0, r8);
                    goto addr_180008724_16;
                }
            }
        } else {
            if (0) 
                goto addr_180008654_13;
            if (rcx) {
                *rcx = eax9;
                goto addr_1800086f7_20;
            }
        }
    } else {
        eax14 = r9w;
        if (*reinterpret_cast<uint16_t*>(&eax14) > 0xff) {
            if (rdx && r8) {
                fun_180003c80(rdx, 0, r8);
                goto addr_180008654_13;
            }
        }
        if (!rdx) 
            goto addr_18000869d_25; else 
            goto addr_180008692_26;
    }
    addr_180008666_27:
    if (v15) {
        v16->f200 = v16->f200 & 0xfffffffd;
    }
    addr_180008679_29:
    eax5 = ebx13;
    addr_18000867b_9:
    return eax5;
    addr_1800086f7_20:
    ebx13 = reinterpret_cast<void**>(0);
    goto addr_180008666_27;
    addr_18000869d_25:
    if (rcx) {
        *rcx = 1;
        goto addr_1800086f7_20;
    }
    addr_180008692_26:
    if (!r8) {
        addr_180008724_16:
        rax17 = fun_1800039c8();
        ebx13 = reinterpret_cast<void**>(34);
        *reinterpret_cast<void***>(rax17) = reinterpret_cast<void**>(34);
        fun_1800038fc();
        goto addr_180008666_27;
    } else {
        *reinterpret_cast<void***>(rdx) = *reinterpret_cast<void***>(&eax14);
        goto addr_18000869d_25;
    }
    addr_1800085f7_5:
    rax18 = fun_1800039c8();
    ebx13 = reinterpret_cast<void**>(22);
    *reinterpret_cast<void***>(rax18) = reinterpret_cast<void**>(22);
    fun_1800038fc();
    goto addr_180008679_29;
}

void fun_180008750(int64_t rcx) {
    int32_t edi2;
    int64_t* rbx3;
    int64_t rcx4;
    int64_t rax5;

    edi2 = 0;
    rbx3 = reinterpret_cast<int64_t*>(0x180017fe0);
    do {
        rcx4 = *rbx3;
        rax5 = reinterpret_cast<int64_t>(EncodePointer(rcx4));
        ++edi2;
        *rbx3 = rax5;
        ++rbx3;
    } while (reinterpret_cast<uint64_t>(static_cast<int64_t>(edi2)) < 10);
    return;
}

uint64_t g18001d688;

int32_t fun_180008598() {
    uint64_t rcx1;
    int32_t eax2;
    uint1_t zf3;

    rcx1 = g1800170a0;
    eax2 = 0;
    zf3 = reinterpret_cast<uint1_t>(g18001d688 == (rcx1 | 1));
    *reinterpret_cast<unsigned char*>(&eax2) = zf3;
    return eax2;
}

int32_t fun_180004ea8(void** rcx, void** rdx, void** r8) {
    void** rcx4;
    void** rcx5;
    void** rcx6;
    void** rcx7;
    void** rcx8;
    void** rcx9;
    void** rcx10;
    void** rcx11;
    void** rcx12;
    void** rdi13;
    int1_t zf14;
    void** rax15;

    if (rcx) {
        rcx4 = *reinterpret_cast<void***>(rcx + 56);
        if (rcx4) {
            fun_180005f00(rcx4);
        }
        rcx5 = *reinterpret_cast<void***>(rcx + 72);
        if (rcx5) {
            fun_180005f00(rcx5);
        }
        rcx6 = *reinterpret_cast<void***>(rcx + 88);
        if (rcx6) {
            fun_180005f00(rcx6);
        }
        rcx7 = *reinterpret_cast<void***>(rcx + 0x68);
        if (rcx7) {
            fun_180005f00(rcx7);
        }
        rcx8 = *reinterpret_cast<void***>(rcx + 0x70);
        if (rcx8) {
            fun_180005f00(rcx8);
        }
        rcx9 = *reinterpret_cast<void***>(rcx + 0x78);
        if (rcx9) {
            fun_180005f00(rcx9);
        }
        rcx10 = *reinterpret_cast<void***>(rcx + 0x80);
        if (rcx10) {
            fun_180005f00(rcx10);
        }
        rcx11 = *reinterpret_cast<void***>(rcx + 0xa0);
        if (rcx11 != 0x180010370) {
            fun_180005f00(rcx11);
        }
        fun_1800088e8(13, rdx, r8);
        rcx12 = *reinterpret_cast<void***>(rcx + 0xb8);
        if (rcx12 && ((*reinterpret_cast<void***>(rcx12) = *reinterpret_cast<void***>(rcx12) - 1, !*reinterpret_cast<void***>(rcx12)) && rcx12 != 0x180017870)) {
            fun_180005f00(rcx12);
        }
        fun_180008ad8(13);
        fun_1800088e8(12, rdx, r8);
        rdi13 = *reinterpret_cast<void***>(rcx + 0xc0);
        if (rdi13 && ((fun_1800079fc(rdi13), zf14 = rdi13 == g180017e70, !zf14) && (rdi13 != 0x180017e80 && !*reinterpret_cast<void***>(rdi13)))) {
            fun_180007864(rdi13);
        }
        fun_180008ad8(12);
        rax15 = fun_180005f00(rcx);
    }
    return *reinterpret_cast<int32_t*>(&rax15);
}

struct s75 {
    int32_t f0;
    signed char[20] pad24;
    int16_t f24;
};

uint32_t fun_180008e80(struct s9* rcx) {
    struct s75* rcx2;
    uint32_t eax3;

    if (rcx->f0 == 0x5a4d) {
        rcx2 = reinterpret_cast<struct s75*>(rcx->f60 + reinterpret_cast<int64_t>(rcx));
        eax3 = 0;
        if (rcx2->f0 == 0x4550) {
            *reinterpret_cast<unsigned char*>(&eax3) = reinterpret_cast<uint1_t>(rcx2->f24 == 0x20b);
        }
        return eax3;
    } else {
        return 0;
    }
}

void fun_180005590();

struct s76 {
    signed char[8] pad8;
    void** f8;
};

void fun_18000559c(void** rcx);

int64_t fun_180008ef4(int64_t rcx) {
    void** rcx2;
    void** rax3;
    void** rcx4;
    void** rax5;
    void** rbx6;
    struct s76* rdi7;
    void** r15_8;
    int64_t rbx9;
    void** rax10;
    void** rax11;
    void** rax12;
    void** rdx13;
    void** rdx14;
    void** rdx15;
    void** rax16;
    void** rax17;

    fun_180005590();
    rcx2 = g18001f100;
    rax3 = reinterpret_cast<void**>(DecodePointer(rcx2));
    rcx4 = g18001f0f8;
    rax5 = reinterpret_cast<void**>(DecodePointer(rcx4));
    rbx6 = rax5;
    if (reinterpret_cast<unsigned char>(rax5) < reinterpret_cast<unsigned char>(rax3) || (rdi7 = reinterpret_cast<struct s76*>(reinterpret_cast<unsigned char>(rax5) - reinterpret_cast<unsigned char>(rax3)), r15_8 = reinterpret_cast<void**>(&rdi7->f8), reinterpret_cast<unsigned char>(r15_8) < reinterpret_cast<unsigned char>(8))) {
        *reinterpret_cast<int32_t*>(&rbx9) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx9) + 4) = 0;
        goto addr_180008fdc_3;
    }
    rcx4 = rax3;
    rax10 = fun_18000ab80(rcx4);
    if (reinterpret_cast<unsigned char>(rax10) >= reinterpret_cast<unsigned char>(r15_8)) {
        addr_180008fb8_5:
        rax11 = reinterpret_cast<void**>(EncodePointer(rcx));
        *reinterpret_cast<void***>(rbx6) = rax11;
        rcx4 = rbx6 + 8;
        rax12 = reinterpret_cast<void**>(EncodePointer(rcx4));
        g18001f0f8 = rax12;
        rbx9 = rcx;
        goto addr_180008fdc_3;
    } else {
        *reinterpret_cast<int32_t*>(&rdx13) = 0x1000;
        *reinterpret_cast<int32_t*>(&rdx13 + 4) = 0;
        if (reinterpret_cast<unsigned char>(rax10) < reinterpret_cast<unsigned char>(0x1000)) {
            rdx13 = rax10;
        }
        rdx14 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rdx13) + reinterpret_cast<unsigned char>(rax10));
        if (reinterpret_cast<unsigned char>(rdx14) >= reinterpret_cast<unsigned char>(rax10)) 
            goto addr_180008f77_9;
    }
    *reinterpret_cast<int32_t*>(&rbx9) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx9) + 4) = 0;
    addr_180008f8a_11:
    rdx15 = rax10 + 32;
    if (reinterpret_cast<unsigned char>(rdx15) < reinterpret_cast<unsigned char>(rax10) || (rcx4 = rax3, rax16 = fun_1800067ec(rcx4, rdx15), rax16 == 0)) {
        addr_180008fdc_3:
        fun_18000559c(rcx4);
        return rbx9;
    } else {
        addr_180008fa0_12:
        rbx6 = rax16 + (reinterpret_cast<int64_t>(rdi7) >> 3) * 8;
        rax17 = reinterpret_cast<void**>(EncodePointer(rax16));
        g18001f100 = rax17;
        goto addr_180008fb8_5;
    }
    addr_180008f77_9:
    rcx4 = rax3;
    rax16 = fun_1800067ec(rcx4, rdx14);
    *reinterpret_cast<int32_t*>(&rbx9) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx9) + 4) = 0;
    if (rax16) 
        goto addr_180008fa0_12;
    goto addr_180008f8a_11;
}

int64_t RtlUnwindEx = 0x166f4;

uint32_t fun_18000e736() {
    goto RtlUnwindEx;
}

void** fun_1800095a0(void* rcx, void** rdx, int32_t* r8) {
    int32_t* rdi4;
    void** rbx5;
    void** rax6;
    uint64_t rcx7;
    int1_t zf8;
    int32_t eax9;
    void** rax10;

    rdi4 = r8;
    if (!rcx || reinterpret_cast<unsigned char>(-32 / reinterpret_cast<uint64_t>(rcx)) >= reinterpret_cast<unsigned char>(rdx)) {
        rbx5 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rdx) * reinterpret_cast<uint64_t>(rcx));
        if (!rbx5) {
            rbx5 = reinterpret_cast<void**>(1);
        }
        do {
            *reinterpret_cast<int32_t*>(&rax6) = 0;
            *reinterpret_cast<int32_t*>(&rax6 + 4) = 0;
            if (reinterpret_cast<unsigned char>(rbx5) > reinterpret_cast<unsigned char>(0xffffffffffffffe0)) 
                goto addr_180009602_5;
            rcx7 = g18001d340;
            rax6 = reinterpret_cast<void**>(HeapAlloc(rcx7, 8, rbx5));
            if (rax6) 
                break;
            addr_180009602_5:
            zf8 = g18001df90 == 0;
            if (zf8) 
                goto addr_180009624_7;
            eax9 = fun_180009058(rbx5, rbx5);
        } while (eax9);
        goto addr_180009617_9;
    } else {
        rax10 = fun_1800039c8();
        *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(12);
        goto addr_1800095ce_11;
    }
    addr_18000962f_12:
    return rax6;
    addr_180009624_7:
    if (rdi4) {
        *rdi4 = 12;
        goto addr_18000962f_12;
    }
    addr_180009617_9:
    if (rdi4) {
        *rdi4 = 12;
    }
    addr_1800095ce_11:
    *reinterpret_cast<int32_t*>(&rax6) = 0;
    *reinterpret_cast<int32_t*>(&rax6 + 4) = 0;
    goto addr_18000962f_12;
}

int64_t HeapReAlloc = 0x167c4;

void** fun_1800094cc(void** rcx, void** rdx) {
    void** rbx3;
    void** rax4;
    uint64_t rcx5;
    void** rax6;
    int1_t zf7;
    int32_t eax8;
    void** rax9;
    void** rax10;
    int32_t eax11;
    int64_t rcx12;
    void** rax13;
    void** rax14;
    int32_t eax15;
    int64_t rcx16;
    void** rax17;

    rbx3 = rdx;
    if (rcx) {
        if (rdx) {
            if (reinterpret_cast<unsigned char>(rdx) > reinterpret_cast<unsigned char>(0xffffffffffffffe0)) {
                addr_180009545_4:
                fun_180009058(rbx3);
                rax4 = fun_1800039c8();
                *reinterpret_cast<void***>(rax4) = reinterpret_cast<void**>(12);
            } else {
                do {
                    rcx5 = g18001d340;
                    if (!rbx3) {
                        rbx3 = reinterpret_cast<void**>(1);
                    }
                    rax6 = reinterpret_cast<void**>(HeapReAlloc(rcx5));
                    if (rax6) 
                        goto addr_18000959a_8;
                    zf7 = g18001df90 == *reinterpret_cast<int32_t*>(&rax6);
                    if (zf7) 
                        goto addr_180009583_10;
                    eax8 = fun_180009058(rbx3);
                    if (!eax8) 
                        goto addr_18000956a_12;
                } while (reinterpret_cast<unsigned char>(rbx3) <= reinterpret_cast<unsigned char>(0xffffffffffffffe0));
                goto addr_180009545_4;
            }
        } else {
            fun_180005f00(rcx);
        }
    } else {
        rax9 = fun_180009414(rdx);
        goto addr_18000955a_16;
    }
    addr_180009558_17:
    *reinterpret_cast<int32_t*>(&rax9) = 0;
    *reinterpret_cast<int32_t*>(&rax9 + 4) = 0;
    addr_18000955a_16:
    return rax9;
    addr_18000959a_8:
    rax9 = rax6;
    goto addr_18000955a_16;
    addr_180009583_10:
    rax10 = fun_1800039c8();
    eax11 = reinterpret_cast<int32_t>(GetLastError(rcx5));
    *reinterpret_cast<int32_t*>(&rcx12) = eax11;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx12) + 4) = 0;
    rax13 = fun_1800039e8(rcx12, rcx12);
    *reinterpret_cast<void***>(rax10) = rax13;
    goto addr_18000959a_8;
    addr_18000956a_12:
    rax14 = fun_1800039c8();
    eax15 = reinterpret_cast<int32_t>(GetLastError(rbx3));
    *reinterpret_cast<int32_t*>(&rcx16) = eax15;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx16) + 4) = 0;
    rax17 = fun_1800039e8(rcx16, rcx16);
    *reinterpret_cast<void***>(rax14) = rax17;
    goto addr_180009558_17;
}

void fun_180009350(uint64_t rcx, void** rdx, int32_t r8d, struct s6* r9) {
    return;
}

void fun_180009380(void** rcx) {
    return;
}

signed char* g10;

uint64_t fun_180009af0() {
    void* r10_1;
    signed char* r10_2;
    int64_t rax3;
    void* rax4;
    signed char* r11_5;
    uint64_t rax6;

    r10_1 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 16 + 24);
    r10_2 = reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(r10_1) - rax3);
    if (reinterpret_cast<uint64_t>(r10_1) < reinterpret_cast<uint64_t>(rax4)) {
        r10_2 = reinterpret_cast<signed char*>(0);
    }
    r11_5 = g10;
    if (reinterpret_cast<uint64_t>(r10_2) < reinterpret_cast<uint64_t>(r11_5)) {
        *reinterpret_cast<uint16_t*>(&r10_2) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r10_2) & 0xf000);
        do {
            r11_5 = r11_5 - 0x1000;
            *r11_5 = 0;
        } while (r10_2 != r11_5);
    }
    return rax6;
}

void fun_180009a58(void** ecx, void** rdx, void** r8) {
    goto LeaveCriticalSection;
}

struct s77 {
    signed char[264] pad264;
    uint16_t* f264;
};

struct s78 {
    signed char[200] pad200;
    uint32_t f200;
};

uint32_t fun_18000848c(int32_t ecx) {
    int32_t ebx2;
    int64_t rdx3;
    uint32_t eax4;
    struct s77* v5;
    signed char v6;
    struct s78* v7;

    ebx2 = ecx;
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 + 32, 0);
    *reinterpret_cast<uint32_t*>(&rdx3) = *reinterpret_cast<unsigned char*>(&ebx2);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx3) + 4) = 0;
    eax4 = static_cast<uint32_t>(v5->f264[rdx3]) & 0x8000;
    if (v6) {
        v7->f200 = v7->f200 & 0xfffffffd;
    }
    return eax4;
}

struct s12* fun_180003bc4(struct s12* rcx, void** rdx) {
    void** rax3;
    void** rdx4;
    int1_t zf5;
    int1_t zf6;
    void** rax7;
    void** rax8;
    int1_t zf9;
    void** rax10;
    void** eax11;

    rcx->f24 = 0;
    if (rdx) {
        __asm__("movups xmm0, [rdx]");
        __asm__("movdqu [rcx], xmm0");
    } else {
        rax3 = fun_180005018();
        rcx->f16 = rax3;
        rdx4 = *reinterpret_cast<void***>(rax3 + 0xc0);
        rcx->f0 = rdx4;
        rcx->f8 = *reinterpret_cast<void***>(rax3 + 0xb8);
        zf5 = rdx4 == g180017e70;
        if (!zf5 && (zf6 = (g180017fd8 & reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rax3 + 0xc8))) == 0, zf6)) {
            rax7 = fun_180007aa0();
            rcx->f0 = rax7;
        }
        rax8 = g180017b90;
        if (rcx->f8 != rax8 && (zf9 = (g180017fd8 & reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx->f16 + 0xc8))) == 0, zf9)) {
            rax10 = fun_180007e98();
            rcx->f8 = rax10;
        }
        eax11 = *reinterpret_cast<void***>(rcx->f16 + 0xc8);
        if (!(*reinterpret_cast<unsigned char*>(&eax11) & 2)) {
            *reinterpret_cast<void***>(rcx->f16 + 0xc8) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(eax11) | 2);
            rcx->f24 = 1;
        }
    }
    return rcx;
}

struct s79 {
    signed char[32] pad32;
    void** f32;
    signed char[7] pad40;
    int32_t f40;
    signed char[4] pad48;
    void** f48;
};

int64_t GetStringTypeW = 0x167f2;

int32_t fun_18000a438(struct s21** rcx, int32_t edx, void* r8, int32_t r9d) {
    void* rsp5;
    uint64_t* rbp6;
    uint64_t rax7;
    int32_t r14d8;
    int32_t v9;
    int64_t rcx10;
    int32_t eax11;
    struct s79* rsp12;
    void* rsi13;
    uint1_t zf14;
    void* rcx15;
    void** rbx16;
    void** rcx17;
    void** rax18;
    int64_t* rsp19;
    struct s79* rsp20;
    int64_t r9_21;
    int64_t rcx22;
    int64_t* rsp23;
    int32_t eax24;
    int64_t r8_25;
    int64_t rcx26;
    int64_t* rsp27;
    int64_t v28;
    void** rcx29;
    int64_t* rsp30;
    uint64_t rax31;
    uint64_t rcx32;
    struct s0* rax33;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 64);
    rbp6 = reinterpret_cast<uint64_t*>(reinterpret_cast<int64_t>(rsp5) + 48);
    rax7 = g1800170a0;
    r14d8 = v9;
    if (!r14d8) {
        r14d8 = (*rcx)->f4;
    }
    *reinterpret_cast<int32_t*>(&rcx10) = r14d8;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx10) + 4) = 0;
    eax11 = reinterpret_cast<int32_t>(MultiByteToWideChar(rcx10));
    rsp12 = reinterpret_cast<struct s79*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8);
    rsi13 = reinterpret_cast<void*>(static_cast<int64_t>(eax11));
    zf14 = reinterpret_cast<uint1_t>(eax11 == 0);
    if (zf14) 
        goto addr_18000a4a3_4;
    if (reinterpret_cast<uint1_t>(eax11 < 0) | zf14 || (reinterpret_cast<uint64_t>(rsi13) > 0x7ffffffffffffff0 || (rcx15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsi13) + reinterpret_cast<uint64_t>(rsi13)), reinterpret_cast<uint64_t>(rcx15) + 16 <= reinterpret_cast<uint64_t>(rcx15)))) {
        rbx16 = reinterpret_cast<void**>(0);
        goto addr_18000a526_7;
    }
    rcx17 = reinterpret_cast<void**>(reinterpret_cast<uint64_t>(rsi13) * 2 + 16);
    if (reinterpret_cast<unsigned char>(rcx17) > reinterpret_cast<unsigned char>(0x400)) {
        rax18 = fun_180009414(rcx17);
        rsp12 = reinterpret_cast<struct s79*>(reinterpret_cast<uint64_t>(rsp12) - 8 + 8);
        rbx16 = rax18;
        if (!rax18) {
            addr_18000a526_7:
            if (!rbx16) {
                addr_18000a4a3_4:
            } else {
                rsp19 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp12) - 8);
                *rsp19 = 0x18000a53f;
                fun_180003c80(rbx16, 0, reinterpret_cast<uint64_t>(rsi13) + reinterpret_cast<uint64_t>(rsi13));
                rsp20 = reinterpret_cast<struct s79*>(rsp19 + 1);
                *reinterpret_cast<int32_t*>(&r9_21) = r9d;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_21) + 4) = 0;
                *reinterpret_cast<int32_t*>(&rcx22) = r14d8;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx22) + 4) = 0;
                rsp20->f40 = *reinterpret_cast<int32_t*>(&rsi13);
                rsp20->f32 = rbx16;
                rsp23 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp20) - 8);
                *rsp23 = 0x18000a55c;
                eax24 = reinterpret_cast<int32_t>(MultiByteToWideChar(rcx22, 1, r8, r9_21));
                rsp12 = reinterpret_cast<struct s79*>(rsp23 + 1);
                if (eax24) {
                    *reinterpret_cast<int32_t*>(&r8_25) = eax24;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_25) + 4) = 0;
                    *reinterpret_cast<int32_t*>(&rcx26) = edx;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx26) + 4) = 0;
                    rsp27 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp12) - 8);
                    *rsp27 = 0x18000a573;
                    GetStringTypeW(rcx26, rbx16, r8_25, v28);
                    rsp12 = reinterpret_cast<struct s79*>(rsp27 + 1);
                }
                rcx29 = rbx16 + 0xfffffffffffffff0;
                if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx29) == 0xdddd)) {
                    rsp30 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp12) - 8);
                    *rsp30 = 0x18000a586;
                    fun_180005f00(rcx29, rcx29);
                    rsp12 = reinterpret_cast<struct s79*>(rsp30 + 1);
                }
            }
        } else {
            *reinterpret_cast<void***>(rax18) = reinterpret_cast<void**>(0xdddd);
            goto addr_18000a51d_16;
        }
    } else {
        if (reinterpret_cast<unsigned char>(rcx17 + 15) <= reinterpret_cast<unsigned char>(rcx17)) {
        }
        rax31 = fun_180009af0();
        rsp12 = reinterpret_cast<struct s79*>(reinterpret_cast<uint64_t>(rsp12) - 8 + 8 - rax31);
        rbx16 = reinterpret_cast<void**>(&rsp12->f48);
        if (!rbx16) 
            goto addr_18000a4a3_4;
        *reinterpret_cast<void***>(rbx16) = reinterpret_cast<void**>(0xcccc);
        goto addr_18000a51d_16;
    }
    rcx32 = rax7 ^ reinterpret_cast<uint64_t>(rbp6) ^ reinterpret_cast<uint64_t>(rbp6);
    *reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp12) - 8) = 0x18000a594;
    rax33 = fun_180002f40(rcx32, rcx32);
    return *reinterpret_cast<int32_t*>(&rax33);
    addr_18000a51d_16:
    rbx16 = rbx16 + 16;
    goto addr_18000a526_7;
}

struct s80 {
    signed char[32] pad32;
    void** f32;
    signed char[7] pad40;
    uint32_t f40;
    signed char[4] pad48;
    void** f48;
    signed char[7] pad56;
    void** f56;
    signed char[7] pad64;
    void** f64;
};

int32_t fun_18000a0b4(struct s23** rcx, void** rdx, uint32_t r8d, signed char* r9) {
    void* rsp5;
    void*** rbp6;
    uint64_t rax7;
    uint64_t v8;
    uint32_t ebx9;
    uint32_t v10;
    void** rdi11;
    signed char* r12_12;
    uint32_t r13d13;
    void** v14;
    int32_t r14d15;
    int32_t v16;
    uint32_t r10d17;
    signed char* rax18;
    int64_t rcx19;
    int32_t eax20;
    struct s80* rsp21;
    uint64_t r15_22;
    uint64_t rcx23;
    void** rcx24;
    void** rax25;
    int64_t r9_26;
    int64_t rcx27;
    int64_t* rsp28;
    int32_t eax29;
    int64_t* rsp30;
    int32_t eax31;
    uint64_t rsi32;
    void** rcx33;
    int64_t* rsp34;
    uint64_t rcx35;
    void** rbx36;
    void** rcx37;
    uint32_t v38;
    void** v39;
    int64_t* rsp40;
    uint64_t rax41;
    uint64_t rcx42;
    struct s0* rax43;
    int64_t* rsp44;
    void** rax45;
    int64_t* rsp46;
    int32_t eax47;
    uint32_t v48;
    void** v49;
    int64_t rcx50;
    int64_t* rsp51;
    void** rcx52;
    int64_t* rsp53;
    int64_t* rsp54;
    uint64_t rax55;
    int64_t rax56;
    int1_t less57;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 80);
    rbp6 = reinterpret_cast<void***>(reinterpret_cast<int64_t>(rsp5) + 64);
    rax7 = g1800170a0;
    v8 = rax7 ^ reinterpret_cast<uint64_t>(rbp6);
    ebx9 = v10;
    *reinterpret_cast<int32_t*>(&rdi11) = 0;
    *reinterpret_cast<int32_t*>(&rdi11 + 4) = 0;
    r12_12 = r9;
    r13d13 = r8d;
    v14 = rdx;
    if (reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(ebx9) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(ebx9 == 0)) {
        addr_18000a11e_2:
        r14d15 = v16;
        if (!r14d15) {
            r14d15 = (*rcx)->f4;
        }
    } else {
        r10d17 = ebx9;
        rax18 = r9;
        do {
            --r10d17;
            if (!*rax18) 
                goto addr_18000a10e_6;
            ++rax18;
        } while (r10d17);
        goto addr_18000a10a_8;
    }
    *reinterpret_cast<int32_t*>(&rcx19) = r14d15;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx19) + 4) = 0;
    eax20 = reinterpret_cast<int32_t>(MultiByteToWideChar(rcx19));
    rsp21 = reinterpret_cast<struct s80*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8);
    r15_22 = reinterpret_cast<uint64_t>(static_cast<int64_t>(eax20));
    if (!eax20) 
        goto addr_18000a15c_10;
    if (reinterpret_cast<uint1_t>(eax20 < 0) | reinterpret_cast<uint1_t>(eax20 == 0)) 
        goto addr_18000a1df_12;
    if (-32 / r15_22 < 2) 
        goto addr_18000a1df_12;
    rcx23 = r15_22 + r15_22;
    if (rcx23 + 16 <= rcx23) 
        goto addr_18000a1df_12;
    rcx24 = reinterpret_cast<void**>(r15_22 * 2 + 16);
    if (reinterpret_cast<unsigned char>(rcx24) > reinterpret_cast<unsigned char>(0x400)) {
        rax25 = fun_180009414(rcx24, rcx24);
        rsp21 = reinterpret_cast<struct s80*>(reinterpret_cast<uint64_t>(rsp21) - 8 + 8);
        rdi11 = rax25;
        if (!rax25) {
            addr_18000a1df_12:
            if (!rdi11) {
                addr_18000a15c_10:
            } else {
                *reinterpret_cast<uint32_t*>(&r9_26) = ebx9;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_26) + 4) = 0;
                *reinterpret_cast<int32_t*>(&rcx27) = r14d15;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx27) + 4) = 0;
                rsp21->f40 = *reinterpret_cast<uint32_t*>(&r15_22);
                rsp21->f32 = rdi11;
                rsp28 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
                *rsp28 = 0x18000a206;
                eax29 = reinterpret_cast<int32_t>(MultiByteToWideChar(rcx27, 1, r12_12, r9_26));
                rsp21 = reinterpret_cast<struct s80*>(rsp28 + 1);
                if (!eax29 || (rsp21->f40 = 0, rsp21->f32 = reinterpret_cast<void**>(0), rsp30 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8), *rsp30 = 0x18000a22c, eax31 = fun_18000acd4(v14, r13d13, rdi11, *reinterpret_cast<uint32_t*>(&r15_22)), rsp21 = reinterpret_cast<struct s80*>(rsp30 + 1), rsi32 = reinterpret_cast<uint64_t>(static_cast<int64_t>(eax31)), eax31 == 0)) {
                    addr_18000a367_18:
                    rcx33 = rdi11 + 0xfffffffffffffff0;
                    if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx33) == 0xdddd)) {
                        rsp34 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
                        *rsp34 = 0x18000a378;
                        fun_180005f00(rcx33, rcx33);
                        rsp21 = reinterpret_cast<struct s80*>(rsp34 + 1);
                        goto addr_18000a378_20;
                    }
                } else {
                    if (!(0x400 & r13d13)) {
                        if (reinterpret_cast<uint1_t>(eax31 < 0) | reinterpret_cast<uint1_t>(eax31 == 0) || (-32 / rsi32 < 2 || (rcx35 = rsi32 + rsi32, rcx35 + 16 <= rcx35))) {
                            *reinterpret_cast<int32_t*>(&rbx36) = 0;
                            *reinterpret_cast<int32_t*>(&rbx36 + 4) = 0;
                            goto addr_18000a2f5_24;
                        }
                        rcx37 = reinterpret_cast<void**>(rsi32 * 2 + 16);
                        if (reinterpret_cast<unsigned char>(rcx37) > reinterpret_cast<unsigned char>(0x400)) 
                            goto addr_18000a2da_26; else 
                            goto addr_18000a2a5_27;
                    } else {
                        if (v38 && *reinterpret_cast<int32_t*>(&rsi32) <= reinterpret_cast<int32_t>(v38)) {
                            rsp21->f40 = v38;
                            rsp21->f32 = v39;
                            rsp40 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
                            *rsp40 = 0x18000a273;
                            fun_18000acd4(v14, r13d13, rdi11, *reinterpret_cast<uint32_t*>(&r15_22));
                            rsp21 = reinterpret_cast<struct s80*>(rsp40 + 1);
                            goto addr_18000a367_18;
                        }
                    }
                }
            }
        } else {
            *reinterpret_cast<void***>(rax25) = reinterpret_cast<void**>(0xdddd);
            goto addr_18000a1db_31;
        }
    } else {
        if (reinterpret_cast<unsigned char>(rcx24 + 15) <= reinterpret_cast<unsigned char>(rcx24)) {
        }
        rax41 = fun_180009af0();
        rsp21 = reinterpret_cast<struct s80*>(reinterpret_cast<uint64_t>(rsp21) - 8 + 8 - rax41);
        rdi11 = reinterpret_cast<void**>(&rsp21->f64);
        if (!rdi11) 
            goto addr_18000a15c_10;
        *reinterpret_cast<void***>(rdi11) = reinterpret_cast<void**>(0xcccc);
        goto addr_18000a1db_31;
    }
    addr_18000a37a_36:
    rcx42 = v8 ^ reinterpret_cast<uint64_t>(rbp6);
    *reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8) = 0x18000a386;
    rax43 = fun_180002f40(rcx42, rcx42);
    return *reinterpret_cast<int32_t*>(&rax43);
    addr_18000a378_20:
    goto addr_18000a37a_36;
    addr_18000a2da_26:
    rsp44 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
    *rsp44 = 0x18000a2df;
    rax45 = fun_180009414(rcx37, rcx37);
    rsp21 = reinterpret_cast<struct s80*>(rsp44 + 1);
    rbx36 = rax45;
    if (!rax45) {
        addr_18000a2f5_24:
        if (rbx36) {
            rsp21->f40 = *reinterpret_cast<uint32_t*>(&rsi32);
            rsp21->f32 = rbx36;
            rsp46 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
            *rsp46 = 0x18000a314;
            eax47 = fun_18000acd4(v14, r13d13, rdi11, *reinterpret_cast<uint32_t*>(&r15_22));
            rsp21 = reinterpret_cast<struct s80*>(rsp46 + 1);
            if (eax47) {
                rsp21->f56 = reinterpret_cast<void**>(0);
                rsp21->f48 = reinterpret_cast<void**>(0);
                if (v48) {
                    rsp21->f40 = v48;
                    rsp21->f32 = v49;
                } else {
                    rsp21->f40 = 0;
                    rsp21->f32 = reinterpret_cast<void**>(0);
                }
                *reinterpret_cast<int32_t*>(&rcx50) = r14d15;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx50) + 4) = 0;
                rsp51 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
                *rsp51 = 0x18000a354;
                WideCharToMultiByte(rcx50);
                rsp21 = reinterpret_cast<struct s80*>(rsp51 + 1);
            }
            rcx52 = rbx36 + 0xfffffffffffffff0;
            if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rcx52) == 0xdddd)) {
                rsp53 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
                *rsp53 = 0x18000a367;
                fun_180005f00(rcx52, rcx52);
                rsp21 = reinterpret_cast<struct s80*>(rsp53 + 1);
                goto addr_18000a367_18;
            }
        }
    } else {
        *reinterpret_cast<void***>(rax45) = reinterpret_cast<void**>(0xdddd);
    }
    addr_18000a2ed_45:
    rbx36 = rbx36 + 16;
    goto addr_18000a2f5_24;
    addr_18000a2a5_27:
    if (reinterpret_cast<unsigned char>(rcx37 + 15) <= reinterpret_cast<unsigned char>(rcx37)) {
    }
    rsp54 = reinterpret_cast<int64_t*>(reinterpret_cast<uint64_t>(rsp21) - 8);
    *rsp54 = 0x18000a2c1;
    rax55 = fun_180009af0();
    rsp21 = reinterpret_cast<struct s80*>(reinterpret_cast<uint64_t>(rsp54 + 1) - rax55);
    rbx36 = reinterpret_cast<void**>(&rsp21->f64);
    if (!rbx36) 
        goto addr_18000a367_18;
    *reinterpret_cast<void***>(rbx36) = reinterpret_cast<void**>(0xcccc);
    goto addr_18000a2ed_45;
    addr_18000a1db_31:
    rdi11 = rdi11 + 16;
    goto addr_18000a1df_12;
    addr_18000a10e_6:
    *reinterpret_cast<uint32_t*>(&rax56) = ebx9 - r10d17 - 1;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax56) + 4) = 0;
    less57 = *reinterpret_cast<int32_t*>(&rax56) < reinterpret_cast<int32_t>(ebx9);
    ebx9 = static_cast<uint32_t>(rax56 + 1);
    if (!less57) {
        ebx9 = *reinterpret_cast<uint32_t*>(&rax56);
        goto addr_18000a11e_2;
    }
    addr_18000a10a_8:
    r10d17 = 0xffffffff;
    goto addr_18000a10e_6;
}

uint16_t* fun_180008b34(int32_t ecx) {
    int32_t edx2;
    int32_t* r8_3;
    int64_t rax4;

    edx2 = 0;
    r8_3 = reinterpret_cast<int32_t*>(0x180010bb0);
    do {
        if (ecx == *r8_3) 
            break;
        ++edx2;
        r8_3 = r8_3 + 4;
    } while (reinterpret_cast<uint64_t>(static_cast<int64_t>(edx2)) < 23);
    goto addr_180008b54_4;
    rax4 = edx2;
    return *reinterpret_cast<uint16_t**>(0x180010bb0 + (rax4 + rax4) * 8 + 8);
    addr_180008b54_4:
    return 0;
}

int32_t g180017298 = -1;

uint64_t g18001f0c8;

int32_t fun_180006260() {
    int32_t eax1;
    int64_t rbx2;
    int1_t sf3;
    uint1_t less_or_equal4;
    uint64_t rax5;
    uint64_t rax6;
    int32_t eax7;
    int32_t eax8;

    eax1 = g180017298;
    *reinterpret_cast<int32_t*>(&rbx2) = 0;
    sf3 = eax1 < 0;
    less_or_equal4 = reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(sf3) | reinterpret_cast<uint1_t>(eax1 == 0));
    if (sf3) {
        rax5 = g18001f0c8;
        rax6 = rax5 ^ g1800170a0;
        if (!rax6 || (eax7 = reinterpret_cast<int32_t>(rax6(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 32 + 48)), eax8 = 1, eax7 != 0x7a)) {
            eax8 = 0;
        }
        g180017298 = eax8;
        less_or_equal4 = reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax8 < 0) | reinterpret_cast<uint1_t>(eax8 == 0));
    }
    *reinterpret_cast<unsigned char*>(&rbx2) = reinterpret_cast<uint1_t>(!less_or_equal4);
    return *reinterpret_cast<int32_t*>(&rbx2);
}

void fun_18000559c(void** rcx) {
    goto LeaveCriticalSection;
}

int64_t fun_18000909c();

unsigned char g180018330 = 2;

void fun_18000abbc() {
    int64_t rax1;
    int1_t zf2;
    int32_t eax3;
    uint16_t* rdx4;
    int64_t rdi5;
    int64_t rsi6;
    int64_t rbx7;
    uint32_t eax8;
    int64_t v9;

    rax1 = fun_18000909c();
    if (rax1) {
        fun_1800090cc(22);
    }
    zf2 = (g180018330 & 2) == 0;
    if (!zf2) {
        eax3 = fun_18000e730(23);
        if (eax3) {
            __asm__("int 0x29");
        }
        *reinterpret_cast<int32_t*>(&rdx4) = 0x40000015;
        fun_180003798(3, 0x40000015, 1);
    }
    fun_18000549c(3);
    *reinterpret_cast<int32_t*>(&rdi5) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi5) + 4) = 0;
    *reinterpret_cast<int32_t*>(&rsi6) = 0xe3;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi6) + 4) = 0;
    do {
        __asm__("cdq ");
        rbx7 = static_cast<int32_t>(rsi6 + rdi5) - *reinterpret_cast<int32_t*>(&rdx4) >> 1;
        rdx4 = *reinterpret_cast<uint16_t**>(0x180012e80 + (rbx7 + rbx7) * 8);
        eax8 = fun_18000ad64(3, rdx4, 85);
        if (!eax8) 
            break;
        if (reinterpret_cast<int32_t>(eax8) >= reinterpret_cast<int32_t>(0)) {
            *reinterpret_cast<int32_t*>(&rdi5) = static_cast<int32_t>(rbx7 + 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi5) + 4) = 0;
        } else {
            *reinterpret_cast<int32_t*>(&rsi6) = static_cast<int32_t>(rbx7 - 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi6) + 4) = 0;
        }
    } while (*reinterpret_cast<int32_t*>(&rdi5) <= *reinterpret_cast<int32_t*>(&rsi6));
    goto addr_18000ac73_14;
    addr_18000ac83_16:
    goto v9;
    addr_18000ac73_14:
    goto addr_18000ac83_16;
}

void fun_18000908c(int64_t rcx);

void fun_18000388c(int64_t rcx);

void fun_180009094(int64_t rcx);

void fun_1800090ac(int64_t rcx);

void fun_180009038(int64_t rcx);

void fun_180009300(int64_t rcx);

int64_t GetModuleHandleW = 0x166e0;

uint64_t g18001f008;

uint64_t g18001f010;

uint64_t g18001f018;

uint64_t g18001f020;

uint64_t g18001f028;

uint64_t g18001f030;

uint64_t g18001f038;

uint64_t g18001f040;

uint64_t g18001f048;

uint64_t g18001f050;

uint64_t g18001f058;

uint64_t g18001f060;

uint64_t g18001f068;

uint64_t g18001f070;

uint64_t g18001f078;

uint64_t g18001f080;

uint64_t g18001f090;

uint64_t g18001f088;

uint64_t g18001f098;

uint64_t g18001f0a0;

uint64_t g18001f0a8;

uint64_t g18001f0b0;

uint64_t g18001f0b8;

uint64_t g18001f0d0;

uint64_t g18001f0d8;

uint64_t g18001f0e0;

void fun_1800054a8() {
    int64_t rax1;
    int64_t rax2;
    uint64_t rax3;
    uint64_t rax4;
    uint64_t rax5;
    uint64_t rax6;
    uint64_t rax7;
    uint64_t rax8;
    uint64_t rax9;
    uint64_t rax10;
    uint64_t rax11;
    uint64_t rax12;
    uint64_t rax13;
    uint64_t rax14;
    uint64_t rax15;
    uint64_t rax16;
    uint64_t rax17;
    uint64_t rax18;
    uint64_t rax19;
    uint64_t rax20;
    uint64_t rax21;
    uint64_t rax22;
    uint64_t rax23;
    uint64_t rax24;
    uint64_t rax25;
    uint64_t rax26;
    uint64_t rax27;
    uint64_t rax28;
    uint64_t rax29;
    uint64_t rax30;
    uint64_t rax31;
    uint64_t rax32;
    uint64_t rax33;
    uint64_t rax34;
    uint64_t rax35;
    uint64_t rax36;
    uint64_t rax37;
    uint64_t rax38;
    uint64_t rax39;
    uint64_t rax40;
    uint64_t rax41;
    uint64_t rax42;
    uint64_t rax43;
    uint64_t rax44;
    uint64_t rax45;
    uint64_t rax46;
    uint64_t rax47;
    uint64_t rax48;
    uint64_t rax49;
    uint64_t rax50;
    uint64_t rax51;
    uint64_t rax52;
    uint64_t rax53;
    uint64_t rax54;
    uint64_t rax55;
    uint64_t rax56;
    uint64_t rax57;
    uint64_t rax58;
    uint64_t rax59;
    uint64_t rax60;
    uint64_t rax61;
    uint64_t rax62;
    uint64_t rax63;
    uint64_t rax64;
    uint64_t rax65;
    uint64_t rax66;
    uint64_t rax67;
    uint64_t rax68;

    rax1 = reinterpret_cast<int64_t>(EncodePointer());
    fun_18000908c(rax1);
    fun_18000388c(rax1);
    fun_180009094(rax1);
    fun_1800090ac(rax1);
    fun_180009038(rax1);
    fun_180009300(rax1);
    rax2 = reinterpret_cast<int64_t>(GetModuleHandleW("k"));
    rax3 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "FlsAlloc"));
    rax4 = rax3 ^ g1800170a0;
    g18001efe0 = rax4;
    rax5 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "FlsFree"));
    rax6 = rax5 ^ g1800170a0;
    g18001efe8 = rax6;
    rax7 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "FlsGetValue"));
    rax8 = rax7 ^ g1800170a0;
    g18001eff0 = rax8;
    rax9 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "FlsSetValue"));
    rax10 = rax9 ^ g1800170a0;
    g18001eff8 = rax10;
    rax11 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "InitializeCriticalSectionEx"));
    rax12 = rax11 ^ g1800170a0;
    g18001f000 = rax12;
    rax13 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CreateEventExW"));
    rax14 = rax13 ^ g1800170a0;
    g18001f008 = rax14;
    rax15 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CreateSemaphoreExW"));
    rax16 = rax15 ^ g1800170a0;
    g18001f010 = rax16;
    rax17 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "SetThreadStackGuarantee"));
    rax18 = rax17 ^ g1800170a0;
    g18001f018 = rax18;
    rax19 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CreateThreadpoolTimer"));
    rax20 = rax19 ^ g1800170a0;
    g18001f020 = rax20;
    rax21 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "SetThreadpoolTimer"));
    rax22 = rax21 ^ g1800170a0;
    g18001f028 = rax22;
    rax23 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "WaitForThreadpoolTimerCallbacks"));
    rax24 = rax23 ^ g1800170a0;
    g18001f030 = rax24;
    rax25 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CloseThreadpoolTimer"));
    rax26 = rax25 ^ g1800170a0;
    g18001f038 = rax26;
    rax27 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CreateThreadpoolWait"));
    rax28 = rax27 ^ g1800170a0;
    g18001f040 = rax28;
    rax29 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "SetThreadpoolWait"));
    rax30 = rax29 ^ g1800170a0;
    g18001f048 = rax30;
    rax31 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CloseThreadpoolWait"));
    rax32 = rax31 ^ g1800170a0;
    g18001f050 = rax32;
    rax33 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "FlushProcessWriteBuffers"));
    rax34 = rax33 ^ g1800170a0;
    g18001f058 = rax34;
    rax35 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "FreeLibraryWhenCallbackReturns"));
    rax36 = rax35 ^ g1800170a0;
    g18001f060 = rax36;
    rax37 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetCurrentProcessorNumber"));
    rax38 = rax37 ^ g1800170a0;
    g18001f068 = rax38;
    rax39 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetLogicalProcessorInformation"));
    rax40 = rax39 ^ g1800170a0;
    g18001f070 = rax40;
    rax41 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CreateSymbolicLinkW"));
    rax42 = rax41 ^ g1800170a0;
    g18001f078 = rax42;
    rax43 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "SetDefaultDllDirectories"));
    rax44 = rax43 ^ g1800170a0;
    g18001f080 = rax44;
    rax45 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "EnumSystemLocalesEx"));
    rax46 = rax45 ^ g1800170a0;
    g18001f090 = rax46;
    rax47 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "CompareStringEx"));
    rax48 = rax47 ^ g1800170a0;
    g18001f088 = rax48;
    rax49 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetDateFormatEx"));
    rax50 = rax49 ^ g1800170a0;
    g18001f098 = rax50;
    rax51 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetLocaleInfoEx"));
    rax52 = rax51 ^ g1800170a0;
    g18001f0a0 = rax52;
    rax53 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetTimeFormatEx"));
    rax54 = rax53 ^ g1800170a0;
    g18001f0a8 = rax54;
    rax55 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetUserDefaultLocaleName"));
    rax56 = rax55 ^ g1800170a0;
    g18001f0b0 = rax56;
    rax57 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "IsValidLocaleName"));
    rax58 = rax57 ^ g1800170a0;
    g18001f0b8 = rax58;
    rax59 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "LCMapStringEx"));
    rax60 = rax59 ^ g1800170a0;
    g18001f0c0 = rax60;
    rax61 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetCurrentPackageId"));
    rax62 = rax61 ^ g1800170a0;
    g18001f0c8 = rax62;
    rax63 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetTickCount64"));
    rax64 = rax63 ^ g1800170a0;
    g18001f0d0 = rax64;
    rax65 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "GetFileInformationByHandleExW"));
    rax66 = rax65 ^ g1800170a0;
    g18001f0d8 = rax66;
    rax67 = reinterpret_cast<uint64_t>(GetProcAddress(rax2, "SetFileInformationByHandleW"));
    rax68 = rax67 ^ g1800170a0;
    g18001f0e0 = rax68;
    return;
}

void fun_180006c88(int32_t ecx, void** rdx) {
    if (ecx >= 20) {
        goto LeaveCriticalSection;
    } else {
        __asm__("btr dword [rdx+0x18], 0xf");
        goto LeaveCriticalSection;
    }
}

int32_t fun_18000aca0(void** rcx) {
    uint32_t eax2;
    uint64_t rax3;
    int32_t eax4;

    if (!rcx || ((eax2 = fun_18000ac14(rcx), reinterpret_cast<int32_t>(eax2) < reinterpret_cast<int32_t>(0)) || (rax3 = reinterpret_cast<uint64_t>(static_cast<int64_t>(reinterpret_cast<int32_t>(eax2))), rax3 >= 0xe4))) {
        eax4 = 0;
    } else {
        eax4 = *reinterpret_cast<int32_t*>(0x180012040 + (rax3 + rax3) * 8);
    }
    return eax4;
}

uint32_t fun_18000adbc(void** rcx, void** rdx, void** r8) {
    uint32_t edi4;
    uint32_t eax5;
    void** eax6;
    uint32_t eax7;
    void** rcx8;
    uint32_t eax9;
    void** rax10;

    edi4 = 0xffffffff;
    if (rcx) {
        if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 0x83) {
            eax5 = fun_180009730(rcx, rdx);
            edi4 = eax5;
            fun_18000b238(rcx);
            eax6 = fun_180006ca8(rcx, rdx);
            eax7 = fun_18000b0b8(eax6, rdx, r8);
            if (reinterpret_cast<int32_t>(eax7) >= reinterpret_cast<int32_t>(0)) {
                rcx8 = *reinterpret_cast<void***>(rcx + 40);
                if (rcx8) {
                    fun_180005f00(rcx8);
                    *reinterpret_cast<void***>(rcx + 40) = reinterpret_cast<void**>(0);
                }
            } else {
                edi4 = 0xffffffff;
            }
        }
        *reinterpret_cast<void***>(rcx + 24) = reinterpret_cast<void**>(0);
        eax9 = edi4;
    } else {
        rax10 = fun_1800039c8();
        *reinterpret_cast<void***>(rax10) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        eax9 = 0xffffffff;
    }
    return eax9;
}

void fun_180006c38(void** rcx) {
    if (reinterpret_cast<unsigned char>(rcx) < reinterpret_cast<unsigned char>(0x1800172a0) || reinterpret_cast<unsigned char>(rcx) > reinterpret_cast<unsigned char>(0x180017630)) {
        goto LeaveCriticalSection;
    } else {
        __asm__("btr dword [rcx+0x18], 0xf");
        goto LeaveCriticalSection;
    }
}

int64_t SetStdHandle = 0x167d2;

int64_t fun_180009938(void** ecx) {
    int1_t cf2;
    int64_t rax3;
    int64_t rax4;
    int64_t rdi5;
    int64_t rbx6;
    void** rax7;
    void** rax8;
    int64_t rax9;
    int1_t zf10;
    int64_t rcx11;
    void** ecx12;

    if (reinterpret_cast<signed char>(ecx) < reinterpret_cast<signed char>(0) || ((cf2 = reinterpret_cast<unsigned char>(ecx) < reinterpret_cast<unsigned char>(g18001f0e8), !cf2) || ((rax3 = reinterpret_cast<int32_t>(ecx), *reinterpret_cast<uint32_t*>(&rax4) = *reinterpret_cast<uint32_t*>(&rax3) & 31, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax4) + 4) = 0, rdi5 = rax3 >> 5, rbx6 = rax4 * 88, (*reinterpret_cast<unsigned char*>(reinterpret_cast<int64_t>(*reinterpret_cast<uint64_t**>(0x18001d350 + rdi5 * 8)) + rbx6 + 8) & 1) == 0) || *reinterpret_cast<uint64_t*>(reinterpret_cast<int64_t>(*reinterpret_cast<uint64_t**>(0x18001d350 + rdi5 * 8)) + rbx6) == 0xffffffffffffffff))) {
        rax7 = fun_1800039c8();
        *reinterpret_cast<void***>(rax7) = reinterpret_cast<void**>(9);
        rax8 = fun_180003958();
        *reinterpret_cast<void***>(rax8) = reinterpret_cast<void**>(0);
        *reinterpret_cast<uint32_t*>(&rax9) = 0xffffffff;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax9) + 4) = 0;
    } else {
        zf10 = g18001d8c0 == 1;
        if (!zf10) 
            goto addr_1800099ae_4;
        if (!ecx) 
            goto addr_1800099a1_6; else 
            goto addr_18000998b_7;
    }
    addr_1800099d1_8:
    return rax9;
    addr_1800099a1_6:
    *reinterpret_cast<int32_t*>(&rcx11) = -10;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx11) + 4) = 0;
    addr_1800099a6_9:
    SetStdHandle(rcx11);
    goto addr_1800099ae_4;
    addr_18000998b_7:
    ecx12 = ecx - 1;
    if (!ecx12) {
        *reinterpret_cast<int32_t*>(&rcx11) = -11;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx11) + 4) = 0;
        goto addr_1800099a6_9;
    } else {
        if (ecx12 - 1) {
            addr_1800099ae_4:
            *reinterpret_cast<uint64_t*>(rbx6 + reinterpret_cast<int64_t>(*reinterpret_cast<uint64_t**>(0x18001d350 + rdi5 * 8))) = 0xffffffffffffffff;
            *reinterpret_cast<uint32_t*>(&rax9) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax9) + 4) = 0;
            goto addr_1800099d1_8;
        } else {
            *reinterpret_cast<int32_t*>(&rcx11) = -12;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx11) + 4) = 0;
            goto addr_1800099a6_9;
        }
    }
}

struct s81 {
    uint32_t f0;
    uint32_t f4;
    uint16_t f8;
};

struct s82 {
    uint32_t f0;
    uint32_t f4;
    uint16_t f6;
};

void fun_18000dad0(struct s81* rcx, struct s82* rdx);

struct s83 {
    int32_t f0;
    int32_t f4;
};

struct s84 {
    int32_t f0;
    void** f4;
};

struct s85 {
    int32_t f0;
    int32_t f4;
    int32_t f8;
    signed char[4] pad16;
    void** f16;
};

uint16_t g8;

struct s86 {
    uint16_t f0;
    signed char[2] pad4;
    uint32_t f4;
};

struct s87 {
    signed char f0;
    signed char[3] pad4;
    int32_t f4;
};

struct s88 {
    signed char f0;
    signed char[3] pad4;
    int32_t f4;
};

struct s89 {
    int32_t f0;
    signed char f4;
};

struct s90 {
    uint16_t f0;
    signed char[2] pad4;
    uint16_t f4;
    signed char[2] pad8;
    uint32_t f8;
    uint16_t f10;
};

struct s91 {
    uint32_t f0;
    uint16_t f4;
};

struct s0* fun_18000dba0(uint64_t rcx, struct s36* rdx, struct s37* r8, void* r9) {
    void* rsp5;
    void* rbp6;
    void* rsp7;
    uint64_t rax8;
    struct s83* rdi9;
    struct s84* rsi10;
    struct s85* rdi11;
    void** rsi12;
    void** r9_13;
    int32_t eax14;
    signed char v15;
    int16_t v16;
    void** eax17;
    void* rsp18;
    uint64_t rcx19;
    struct s0* rax20;
    void* rsp21;
    void* rbp22;
    void* rsp23;
    uint64_t rax24;
    uint64_t v25;
    uint32_t r10d26;
    void** r9_27;
    uint16_t r8d28;
    uint32_t ecx29;
    uint16_t cx30;
    int64_t rax31;
    uint16_t r10w32;
    uint32_t v33;
    uint16_t v34;
    uint32_t edx35;
    uint96_t v36;
    int64_t rcx37;
    int64_t rax38;
    uint32_t r14d39;
    uint16_t* r9_40;
    uint32_t v41;
    struct s86* rdi42;
    int32_t ecx43;
    int32_t v44;
    uint32_t r10d45;
    uint16_t r8d46;
    uint16_t edx47;
    int1_t zf48;
    void** eax49;
    void* rdx50;
    void** eax51;
    void* rdx52;
    void** eax53;
    void** eax54;
    int64_t rax55;
    int64_t rcx56;
    uint32_t r13d57;
    uint96_t v58;
    uint16_t r13w59;
    uint16_t r13w60;
    int32_t r9d61;
    int32_t eax62;
    int64_t r14_63;
    uint16_t r9d64;
    struct s87* rsi65;
    int64_t r10_66;
    uint32_t r9d67;
    uint32_t ecx68;
    int32_t r9d69;
    uint32_t r10d70;
    uint32_t eax71;
    uint32_t ecx72;
    uint32_t r15d73;
    struct s88* rdi74;
    struct s88* r10_75;
    struct s89* rdi76;
    int32_t* rsi77;
    uint32_t edx78;
    void* rsi79;
    uint32_t r8d80;
    uint32_t r9d81;
    int64_t r8_82;
    int64_t rax83;
    uint64_t v84;
    int64_t rdx85;
    int64_t r12_86;
    uint32_t r9d87;
    uint32_t eax88;
    uint32_t ecx89;
    uint64_t rax90;
    int64_t r14_91;
    int64_t r9_92;
    uint16_t eax93;
    uint16_t v94;
    uint32_t eax95;
    signed char* r10_96;
    struct s88* r10_97;
    signed char r10b98;
    uint64_t rcx99;
    int64_t v100;
    int64_t rax101;
    uint16_t tmp16_102;
    uint32_t esi103;
    uint32_t r8d104;
    int64_t rax105;
    uint32_t v106;
    uint32_t r10d107;
    uint16_t r8d108;
    uint16_t r9w109;
    uint32_t eax110;
    uint32_t ebx111;
    uint32_t eax112;
    uint32_t* rdx113;
    uint32_t eax114;
    uint32_t eax115;
    uint32_t eax116;
    uint32_t v117;
    uint16_t* v118;
    uint32_t eax119;
    int64_t rax120;
    struct s90* rsi121;
    struct s91* rdi122;
    uint64_t rax123;
    int64_t rcx124;
    int64_t rax125;
    uint32_t ebx126;
    uint96_t v127;
    uint16_t bx128;
    uint16_t bx129;
    int32_t r9d130;
    uint16_t v131;
    uint1_t cf132;
    uint32_t edi133;
    uint32_t r13d134;
    uint32_t r10d135;
    int64_t rax136;
    uint32_t v137;
    uint32_t r8d138;
    uint16_t r10d139;
    uint32_t r9d140;
    uint32_t eax141;
    uint32_t eax142;
    uint32_t* rdx143;
    uint16_t v144;
    uint32_t r9d145;
    uint32_t eax146;
    uint32_t eax147;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8);
    rbp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 63);
    rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 0x88);
    rax8 = g1800170a0;
    fun_18000dad0(reinterpret_cast<int64_t>(rbp6) - 9, reinterpret_cast<int64_t>(rbp6) - 25);
    rdx->f0 = r8->f0;
    rdi9 = reinterpret_cast<struct s83*>(&rdx->f4);
    rsi10 = reinterpret_cast<struct s84*>(&r8->f4);
    rdi9->f0 = rsi10->f0;
    rdi11 = reinterpret_cast<struct s85*>(&rdi9->f4);
    rsi12 = reinterpret_cast<void**>(&rsi10->f4);
    r9_13 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp6) + 7);
    eax14 = fun_18000dc58(reinterpret_cast<int64_t>(rbp6) - 25, 17, 0, r9_13);
    rdi11->f0 = v15;
    rdi11->f4 = v16;
    rdi11->f8 = eax14;
    eax17 = fun_180002c40(rsi12, r9, reinterpret_cast<int64_t>(rbp6) + 11, r9_13);
    rsp18 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp7) - 8 + 8 - 8 + 8 - 8 + 8);
    if (!eax17) {
        rdi11->f16 = rsi12;
        rcx19 = rax8 ^ reinterpret_cast<uint64_t>(rsp7) ^ reinterpret_cast<uint64_t>(rsp18);
        rax20 = fun_180002f40(rcx19, rcx19);
        return rax20;
    }
    fun_18000391c();
    rsp21 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp18) - 8 + 8 - 8 - 8 - 8 - 8 - 8 - 8 - 8);
    rbp22 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp21) - 39);
    rsp23 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp21) - 0xc0);
    rax24 = g1800170a0;
    v25 = rax24 ^ reinterpret_cast<uint64_t>(rsp23);
    r10d26 = g8;
    *reinterpret_cast<int32_t*>(&r9_27) = *reinterpret_cast<int32_t*>(&g0);
    *reinterpret_cast<int32_t*>(&r9_27 + 4) = 0;
    r8d28 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&g0) + 4);
    ecx29 = *reinterpret_cast<uint16_t*>(&r10d26);
    cx30 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&ecx29) & 0x8000);
    *reinterpret_cast<int32_t*>(&rax31) = 32;
    r10w32 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r10d26) & 0x7fff);
    v33 = 0x3ffbcccc;
    v34 = cx30;
    if (cx30) 
        goto addr_18000dcde_11;
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 2) = 32;
    addr_18000dce7_13:
    if (r10w32) {
        if (r10w32 != 0x7fff) {
            addr_18000ddea_15:
            edx35 = r10w32;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v36) + 2) = *reinterpret_cast<int32_t*>(&r9_27);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10) = r10w32;
            *reinterpret_cast<uint32_t*>(&rcx37) = r8d28 >> 24;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx37) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&rax38) = edx35 >> 8;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax38) + 4) = 0;
            r14d39 = 5;
            r9_40 = reinterpret_cast<uint16_t*>(0x180018330);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 6) = r8d28;
            *reinterpret_cast<uint16_t*>(&v36) = 0;
            v41 = 5;
            *reinterpret_cast<uint32_t*>(&rdi42) = 0x7fffffff;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi42) + 4) = 0;
            ecx43 = reinterpret_cast<int32_t>(static_cast<int32_t>(rax38 + rcx37 * 2) * 77 + (edx35 * 0x4d10 + 0xecbced0c)) >> 16;
            v44 = ecx43;
            r10d45 = reinterpret_cast<uint32_t>(-static_cast<int32_t>(*reinterpret_cast<int16_t*>(&ecx43)));
            if (!r10d45) {
                addr_18000e1c4_16:
                r8d46 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 4);
                edx47 = *reinterpret_cast<uint16_t*>(&v36);
            } else {
                zf48 = r10d45 == 0;
                if (reinterpret_cast<int32_t>(r10d45) < reinterpret_cast<int32_t>(0)) {
                    r10d45 = -r10d45;
                    r9_40 = reinterpret_cast<uint16_t*>(0x180018490);
                    zf48 = r10d45 == 0;
                }
                if (zf48) 
                    goto addr_18000e1c4_16; else 
                    goto addr_18000de71_20;
            }
        } else {
            *reinterpret_cast<uint16_t*>(&g0) = 1;
            if (r8d28 == 0x80000000 && !*reinterpret_cast<int32_t*>(&r9_27) || static_cast<int1_t>(r8d28 >> 30)) {
                if (!cx30 || r8d28 != 0xc0000000) {
                    if (r8d28 != 0x80000000 || *reinterpret_cast<int32_t*>(&r9_27)) {
                        addr_18000ddc1_24:
                        eax49 = fun_180002c40(4, 22, "1#QNAN", r9_27);
                        rsp23 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp23) - 8 + 8);
                        if (eax49) {
                            addr_18000e71b_25:
                            fun_18000391c();
                            goto addr_18000e730_26;
                        } else {
                            addr_18000ddde_27:
                            *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 3) = 6;
                            goto addr_18000dde2_28;
                        }
                    } else {
                        *reinterpret_cast<int32_t*>(&rdx50) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r9_27 + 22));
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx50) + 4) = 0;
                        eax51 = fun_180002c40(4, rdx50, "1#INF", r9_27);
                        rsp23 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp23) - 8 + 8);
                        if (eax51) {
                            addr_18000e706_30:
                            fun_18000391c();
                            goto addr_18000e71b_25;
                        } else {
                            addr_18000ddb7_31:
                            *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 3) = 5;
                            goto addr_18000dde2_28;
                        }
                    }
                } else {
                    if (*reinterpret_cast<int32_t*>(&r9_27)) 
                        goto addr_18000ddc1_24;
                    *reinterpret_cast<int32_t*>(&rdx52) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r9_27 + 22));
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx52) + 4) = 0;
                    eax53 = fun_180002c40(4, rdx52, "1#IND", r9_27);
                    rsp23 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp23) - 8 + 8);
                    if (!eax53) 
                        goto addr_18000ddb7_31;
                    goto addr_18000e6f1_35;
                }
            } else {
                eax54 = fun_180002c40(4, 22, "1#SNAN", r9_27);
                rsp23 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp23) - 8 + 8);
                if (!eax54) 
                    goto addr_18000ddde_27;
                fun_18000391c();
                goto addr_18000e6f1_35;
            }
        }
    } else {
        if (r8d28) 
            goto addr_18000ddea_15;
        if (*reinterpret_cast<int32_t*>(&r9_27)) 
            goto addr_18000ddea_15;
        if (cx30 == 0x8000) {
            *reinterpret_cast<int32_t*>(&rax31) = 45;
            goto addr_18000dd05_43;
        }
    }
    addr_18000e1cb_44:
    *reinterpret_cast<uint32_t*>(&rax55) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) >> 16;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax55) + 4) = 0;
    if (*reinterpret_cast<uint16_t*>(&rax55) < 0x3fff) {
        addr_18000e497_45:
    } else {
        *reinterpret_cast<uint16_t*>(&ecx43) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&ecx43) + 1);
        v44 = ecx43;
        *reinterpret_cast<uint32_t*>(&rcx56) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v33) + 2);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx56) + 4) = 0;
        r13d57 = *reinterpret_cast<uint16_t*>(&rcx56);
        *reinterpret_cast<uint16_t*>(&rcx56) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rcx56) & 0x7fff);
        *reinterpret_cast<int64_t*>(&v58) = 0;
        r13w59 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r13d57) ^ *reinterpret_cast<uint16_t*>(&rax55));
        *reinterpret_cast<uint16_t*>(&rax55) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax55) & 0x7fff);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 8) = reinterpret_cast<uint16_t>(0);
        r13w60 = reinterpret_cast<uint16_t>(r13w59 & 0x8000);
        r9d61 = static_cast<int32_t>(rax55 + rcx56);
        if (*reinterpret_cast<uint16_t*>(&rax55) >= 0x7fff || (*reinterpret_cast<uint16_t*>(&rcx56) >= 0x7fff || *reinterpret_cast<uint16_t*>(&r9d61) > 0xbffd)) {
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) = reinterpret_cast<uint16_t>((*reinterpret_cast<uint32_t*>(&rax55) - (*reinterpret_cast<uint32_t*>(&rax55) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax55) < *reinterpret_cast<uint32_t*>(&rax55) + reinterpret_cast<uint1_t>(!!r13w60))) & 0x80000000) + 0x7fff8000);
            goto addr_18000e491_48;
        } else {
            if (*reinterpret_cast<uint16_t*>(&r9d61) <= 0x3fbf) 
                goto addr_18000e248_50;
            if (*reinterpret_cast<uint16_t*>(&rax55)) 
                goto addr_18000e272_52;
            *reinterpret_cast<uint16_t*>(&r9d61) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d61) + 1);
            if (*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) & *reinterpret_cast<uint32_t*>(&rdi42)) 
                goto addr_18000e272_52;
            if (r8d46) 
                goto addr_18000e272_52;
            if (edx47) 
                goto addr_18000e272_52; else 
                goto addr_18000e268_56;
        }
    }
    addr_18000e49c_57:
    eax62 = v44;
    *reinterpret_cast<int32_t*>(&r14_63) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_63) + 4) = 0;
    *reinterpret_cast<uint16_t*>(&g0) = *reinterpret_cast<uint16_t*>(&eax62);
    if (1 || (*reinterpret_cast<int32_t*>(&r14_63) = *reinterpret_cast<int16_t*>(&eax62), *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_63) + 4) = 0, !reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&r14_63) < 0) | reinterpret_cast<uint1_t>(*reinterpret_cast<int32_t*>(&r14_63) == 0)))) {
        r9d64 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10) = 0;
        *reinterpret_cast<uint16_t*>(&rsi65) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8);
        *reinterpret_cast<int32_t*>(&r10_66) = 8;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_66) + 4) = 0;
        if (*reinterpret_cast<int32_t*>(&r14_63) > 21) {
            *reinterpret_cast<int32_t*>(&r14_63) = 21;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_63) + 4) = 0;
        }
        r9d67 = (r9d64 >> 16) - 0x3ffe;
        do {
            ecx68 = r8d46 >> 31;
            r8d46 = reinterpret_cast<uint16_t>(r8d46 + r8d46 | edx47 >> 31);
            *reinterpret_cast<uint16_t*>(&rsi65) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rsi65) + *reinterpret_cast<uint16_t*>(&rsi65) | ecx68);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi65) + 4) = 0;
            edx47 = reinterpret_cast<uint16_t>(edx47 + edx47);
            --r10_66;
        } while (r10_66);
        if (reinterpret_cast<int32_t>(r9d67) < reinterpret_cast<int32_t>(0) && (r9d69 = reinterpret_cast<int32_t>(-r9d67), r10d70 = *reinterpret_cast<unsigned char*>(&r9d69), !(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r10d70) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r10d70 == 0)))) {
            do {
                eax71 = *reinterpret_cast<uint16_t*>(&rsi65) << 31;
                ecx72 = r8d46 << 31;
                --r10d70;
                *reinterpret_cast<uint16_t*>(&rsi65) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rsi65) >> 1);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi65) + 4) = 0;
                r8d46 = reinterpret_cast<uint16_t>(r8d46 >> 1 | eax71);
                edx47 = reinterpret_cast<uint16_t>(edx47 >> 1 | ecx72);
            } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r10d70) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r10d70 == 0)));
        }
        r15d73 = static_cast<uint32_t>(r14_63 + 1);
        rdi74 = reinterpret_cast<struct s88*>(4);
        r10_75 = reinterpret_cast<struct s88*>(4);
        if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r15d73) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r15d73 == 0))) {
            while (1) {
                rdi74->f0 = rsi65->f0;
                rdi76 = reinterpret_cast<struct s89*>(&rdi74->f4);
                rsi77 = &rsi65->f4;
                edx78 = edx47 + edx47;
                rdi76->f0 = *rsi77;
                rdi74 = reinterpret_cast<struct s88*>(&rdi76->f4);
                rsi79 = reinterpret_cast<void*>(rsi77 + 1);
                r8d80 = r8d46 + r8d46 | edx47 >> 31;
                r9d81 = static_cast<uint32_t>(reinterpret_cast<int64_t>(rsi77) + reinterpret_cast<int64_t>(rsi77)) | r8d46 >> 31;
                *reinterpret_cast<uint32_t*>(&r8_82) = r8d80 + r8d80 | edx78 >> 31;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_82) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rax83) = *reinterpret_cast<uint32_t*>(&v84);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax83) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rdx85) = edx78 + edx78;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx85) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&r12_86) = static_cast<uint32_t>(rax83 + rdx85);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_86) + 4) = 0;
                r9d87 = r9d81 + r9d81 | r8d80 >> 31;
                if (*reinterpret_cast<uint32_t*>(&r12_86) < *reinterpret_cast<uint32_t*>(&rdx85) || *reinterpret_cast<uint32_t*>(&r12_86) < *reinterpret_cast<uint32_t*>(&rax83)) {
                    eax88 = static_cast<uint32_t>(r8_82 + 1);
                    ecx89 = 0;
                    if (eax88 < *reinterpret_cast<uint32_t*>(&r8_82) || eax88 < 1) {
                        ecx89 = 1;
                    }
                    *reinterpret_cast<uint32_t*>(&r8_82) = eax88;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_82) + 4) = 0;
                    if (ecx89) {
                        ++r9d87;
                    }
                }
                rax90 = v84 >> 32;
                *reinterpret_cast<uint32_t*>(&r14_91) = static_cast<uint32_t>(r8_82 + rax90);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_91) + 4) = 0;
                if (*reinterpret_cast<uint32_t*>(&r14_91) < *reinterpret_cast<uint32_t*>(&r8_82) || *reinterpret_cast<uint32_t*>(&r14_91) < *reinterpret_cast<uint32_t*>(&rax90)) {
                    ++r9d87;
                }
                *reinterpret_cast<uint32_t*>(&r9_92) = r9d87 + *reinterpret_cast<int32_t*>(&rsi79);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_92) + 4) = 0;
                edx47 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r12_86 + r12_86));
                r8d46 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r14_91 + r14_91) | *reinterpret_cast<uint32_t*>(&r12_86) >> 31);
                --r15d73;
                eax93 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r9_92 + r9_92) | *reinterpret_cast<uint32_t*>(&r14_91) >> 31);
                v94 = eax93;
                eax95 = eax93 >> 24;
                *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&v94) + 3) = 0;
                r10_75->f0 = reinterpret_cast<signed char>(*reinterpret_cast<signed char*>(&eax95) + 48);
                r10_75 = reinterpret_cast<struct s88*>(&r10_75->pad4);
                if (reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r15d73) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r15d73 == 0)) 
                    break;
                *reinterpret_cast<uint16_t*>(&rsi65) = v94;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsi65) + 4) = 0;
            }
        }
        r10_96 = reinterpret_cast<signed char*>(reinterpret_cast<uint64_t>(r10_75) - 1);
        r10_97 = reinterpret_cast<struct s88*>(r10_96 - 1);
        if (*r10_96 >= 53) 
            goto addr_18000e63f_82;
    } else {
        *reinterpret_cast<int32_t*>(&rax31) = 32;
        if (v34 == 0x8000) {
            *reinterpret_cast<int32_t*>(&rax31) = 45;
        }
        goto addr_18000dd05_43;
    }
    while (reinterpret_cast<uint64_t>(r10_97) >= reinterpret_cast<uint64_t>(rdi74) && r10_97->f0 == 48) {
        r10_97 = reinterpret_cast<struct s88*>(reinterpret_cast<uint64_t>(r10_97) - 1);
    }
    if (reinterpret_cast<uint64_t>(r10_97) < reinterpret_cast<uint64_t>(rdi74)) 
        goto addr_18000e6b3_89;
    addr_18000e662_90:
    r10b98 = reinterpret_cast<signed char>(reinterpret_cast<signed char>(static_cast<int32_t>(*reinterpret_cast<signed char*>(&r10_97))) - 3);
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 3) = r10b98;
    *reinterpret_cast<signed char*>(r10b98 + 4) = 0;
    addr_18000e676_91:
    rcx99 = v25 ^ reinterpret_cast<uint64_t>(rsp23);
    fun_180002f40(rcx99, rcx99);
    goto v100;
    addr_18000e6b3_89:
    *reinterpret_cast<int32_t*>(&rax101) = 32;
    *reinterpret_cast<uint16_t*>(&g0) = 0;
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 3) = 1;
    if (v34 == 0x8000) {
        *reinterpret_cast<int32_t*>(&rax101) = 45;
    }
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 2) = *reinterpret_cast<signed char*>(&rax101);
    rdi74->f0 = 48;
    addr_18000dd12_94:
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 5) = 0;
    goto addr_18000e676_91;
    addr_18000e63f_82:
    while (reinterpret_cast<uint64_t>(r10_97) >= reinterpret_cast<uint64_t>(rdi74) && r10_97->f0 == 57) {
        r10_97->f0 = 48;
        r10_97 = reinterpret_cast<struct s88*>(reinterpret_cast<uint64_t>(r10_97) - 1);
    }
    if (reinterpret_cast<uint64_t>(r10_97) < reinterpret_cast<uint64_t>(rdi74)) 
        goto addr_18000e658_98;
    addr_18000e65f_99:
    r10_97->f0 = reinterpret_cast<signed char>(r10_97->f0 + 1);
    goto addr_18000e662_90;
    addr_18000e658_98:
    r10_97 = reinterpret_cast<struct s88*>(&r10_97->pad4);
    tmp16_102 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&g0) + 1);
    *reinterpret_cast<uint16_t*>(&g0) = tmp16_102;
    goto addr_18000e65f_99;
    addr_18000dd05_43:
    *reinterpret_cast<uint16_t*>(&g0) = 0;
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 2) = *reinterpret_cast<signed char*>(&rax31);
    *reinterpret_cast<int16_t*>(reinterpret_cast<int64_t>(&g0) + 3) = 0x3001;
    goto addr_18000dd12_94;
    addr_18000e491_48:
    edx47 = reinterpret_cast<uint16_t>(0);
    r8d46 = reinterpret_cast<uint16_t>(0);
    goto addr_18000e497_45;
    addr_18000e272_52:
    if (*reinterpret_cast<uint16_t*>(&rcx56) || ((*reinterpret_cast<uint16_t*>(&r9d61) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d61) + 1), !!(0x3ffbcccc & *reinterpret_cast<uint32_t*>(&rdi42))) || (1 || !0))) {
        do {
            esi103 = r14d39;
            if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r14d39) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r14d39 == 0))) {
                do {
                    r8d104 = 0;
                    *reinterpret_cast<uint32_t*>(&rax105) = v106;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax105) + 4) = 0;
                    r10d107 = static_cast<uint32_t>(rax105);
                    if (r10d107 < *reinterpret_cast<uint32_t*>(&rax105) || r10d107 < 0) {
                        r8d104 = 1;
                    }
                    v106 = r10d107;
                    if (r8d104) {
                    }
                    --esi103;
                } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(esi103) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(esi103 == 0)));
                r14d39 = v41;
            }
            --r14d39;
            v41 = r14d39;
        } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r14d39) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r14d39 == 0)));
        r8d108 = reinterpret_cast<uint16_t>(0);
        r9w109 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d61) + 0xc002);
        if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r9w109) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r9w109 == 0))) 
            goto addr_18000e331_111;
    } else {
        addr_18000e248_50:
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) = reinterpret_cast<uint16_t>(0);
        goto addr_18000e491_48;
    }
    addr_18000e36d_112:
    r9w109 = reinterpret_cast<uint16_t>(r9w109 + 0xffff);
    if (reinterpret_cast<int16_t>(r9w109) >= reinterpret_cast<int16_t>(0)) {
        addr_18000e3d2_113:
        eax110 = 0;
    } else {
        ebx111 = 0;
        eax112 = r9w109;
        *reinterpret_cast<uint32_t*>(&rdx113) = reinterpret_cast<uint16_t>(-*reinterpret_cast<int16_t*>(&eax112));
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx113) + 4) = 0;
        r9w109 = reinterpret_cast<uint16_t>(r9w109 + *reinterpret_cast<uint16_t*>(&rdx113));
        do {
            if (!1) {
                ++ebx111;
            }
            r8d108 = reinterpret_cast<uint16_t>(0);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v58) + 4) = 0;
            *reinterpret_cast<int32_t*>(&v58) = 0;
            rdx113 = reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rdx113) - 1);
        } while (rdx113);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 8) = reinterpret_cast<uint16_t>(0);
        if (!ebx111) 
            goto addr_18000e3d2_113; else 
            goto addr_18000e3c0_119;
    }
    addr_18000e3d6_120:
    if (*reinterpret_cast<uint16_t*>(&eax110) > 0x8000 || !1) {
        if (1) {
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 2) = reinterpret_cast<uint16_t>(1);
        } else {
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 2) = reinterpret_cast<uint16_t>(0);
            if (1) {
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 6) = reinterpret_cast<uint16_t>(1);
            } else {
                eax114 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 10);
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 6) = reinterpret_cast<uint16_t>(0);
                if (*reinterpret_cast<uint16_t*>(&eax114) != 0xffff) {
                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 10) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&eax114) + 1);
                } else {
                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 10) = 0x8000;
                    r9w109 = reinterpret_cast<uint16_t>(r9w109 + 1);
                }
            }
            r8d108 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 8);
        }
    }
    if (r9w109 < 0x7fff) {
        eax115 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 2);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 6) = r8d108;
        *reinterpret_cast<uint16_t*>(&v36) = *reinterpret_cast<uint16_t*>(&eax115);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10) = reinterpret_cast<uint16_t>(r9w109 | r13w60);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v36) + 2) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v58) + 4);
        r8d46 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 4);
        edx47 = *reinterpret_cast<uint16_t*>(&v36);
        goto addr_18000e49c_57;
    } else {
        r8d46 = reinterpret_cast<uint16_t>(0);
        edx47 = reinterpret_cast<uint16_t>(0);
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) = reinterpret_cast<uint16_t>((0x7fff - (0x7fff + reinterpret_cast<uint1_t>(0x7fff < 0x7fff + reinterpret_cast<uint1_t>(!!r13w60))) & 0x80000000) + 0x7fff8000);
        goto addr_18000e49c_57;
    }
    addr_18000e3c0_119:
    *reinterpret_cast<uint16_t*>(&eax110) = 1;
    goto addr_18000e3d6_120;
    do {
        addr_18000e331_111:
        if (0) 
            break;
        r9w109 = reinterpret_cast<uint16_t>(r9w109 + 0xffff);
        r8d108 = reinterpret_cast<uint16_t>(0);
        *reinterpret_cast<int32_t*>(&v58) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v58) + 4) = 0;
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v58) + 8) = reinterpret_cast<uint16_t>(0);
    } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r9w109) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r9w109 == 0)));
    if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r9w109) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r9w109 == 0))) 
        goto addr_18000e3d2_113; else 
        goto addr_18000e36d_112;
    addr_18000e268_56:
    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10) = 0;
    goto addr_18000e497_45;
    addr_18000de71_20:
    r8d46 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 4);
    edx47 = *reinterpret_cast<uint16_t*>(&v36);
    while (1) {
        eax116 = r10d45;
        r9_40 = r9_40 + 42;
        r10d45 = reinterpret_cast<uint32_t>(reinterpret_cast<int32_t>(r10d45) >> 3);
        v117 = r10d45;
        v118 = r9_40;
        eax119 = eax116 & 7;
        if (!eax119) {
            addr_18000e1ad_135:
            if (r10d45) 
                continue; else 
                break;
        } else {
            rax120 = reinterpret_cast<int32_t>(eax119);
            rsi121 = reinterpret_cast<struct s90*>(r9_40 + (rax120 + rax120 * 2) * 2);
            if (rsi121->f0 >= 0x8000) {
                rdi42->f0 = rsi121->f0;
                rdi122 = reinterpret_cast<struct s91*>(&rdi42->f4);
                rdi122->f0 = *reinterpret_cast<uint32_t*>(&v84);
                rdi42 = reinterpret_cast<struct s86*>(&rdi122->f4);
                rsi121 = reinterpret_cast<struct s90*>(reinterpret_cast<uint64_t>(rbp22) + 7 + 4);
                rax123 = v84 >> 16;
                *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v84) + 2) = *reinterpret_cast<int32_t*>(&rax123) - 1;
            }
            *reinterpret_cast<uint32_t*>(&rcx124) = *reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(rsi121) + 10);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx124) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&rax125) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax125) + 4) = 0;
            ebx126 = *reinterpret_cast<uint16_t*>(&rcx124);
            *reinterpret_cast<uint16_t*>(&rcx124) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rcx124) & 0x7fff);
            *reinterpret_cast<int64_t*>(&v127) = 0;
            bx128 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&ebx126) ^ *reinterpret_cast<uint16_t*>(&rax125));
            *reinterpret_cast<uint16_t*>(&rax125) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax125) & 0x7fff);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 8) = reinterpret_cast<uint16_t>(0);
            bx129 = reinterpret_cast<uint16_t>(bx128 & 0x8000);
            r9d130 = static_cast<int32_t>(rax125 + rcx124);
            v131 = bx129;
            if (*reinterpret_cast<uint16_t*>(&rax125) >= 0x7fff) 
                goto addr_18000e18c_145;
            if (*reinterpret_cast<uint16_t*>(&rcx124) < 0x7fff) 
                goto addr_18000df19_147;
        }
        addr_18000e18c_145:
        cf132 = reinterpret_cast<uint1_t>(!!bx129);
        addr_18000e18f_148:
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) = reinterpret_cast<uint16_t>((*reinterpret_cast<uint32_t*>(&rax125) - (*reinterpret_cast<uint32_t*>(&rax125) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax125) < *reinterpret_cast<uint32_t*>(&rax125) + cf132)) & 0x80000000) + 0x7fff8000);
        addr_18000e1a0_149:
        edx47 = reinterpret_cast<uint16_t>(0);
        r8d46 = reinterpret_cast<uint16_t>(0);
        addr_18000e1a9_150:
        r9_40 = v118;
        goto addr_18000e1ad_135;
        addr_18000df19_147:
        if (*reinterpret_cast<uint16_t*>(&r9d130) > 0xbffd) {
            goto addr_18000e18c_145;
        } else {
            if (*reinterpret_cast<uint16_t*>(&r9d130) <= 0x3fbf) 
                goto addr_18000df34_153;
            if (*reinterpret_cast<uint16_t*>(&rax125)) 
                goto addr_18000df6e_155;
            *reinterpret_cast<uint16_t*>(&r9d130) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d130) + 1);
            if (*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 8) & *reinterpret_cast<uint32_t*>(&rdi42)) 
                goto addr_18000df6e_155;
            if (r8d46) 
                goto addr_18000df6e_155;
            if (!edx47) 
                goto addr_18000df5e_159;
        }
        addr_18000df6e_155:
        if (*reinterpret_cast<uint16_t*>(&rcx124) || ((*reinterpret_cast<uint16_t*>(&r9d130) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d130) + 1), !!(rsi121->f8 & *reinterpret_cast<uint32_t*>(&rdi42))) || (rsi121->f4 || rsi121->f0))) {
            edi133 = 5;
            do {
                r13d134 = edi133;
                if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(edi133) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(edi133 == 0))) {
                    do {
                        r10d135 = 0;
                        *reinterpret_cast<uint32_t*>(&rax136) = v137;
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax136) + 4) = 0;
                        r8d138 = static_cast<uint32_t>(rax136);
                        if (r8d138 < *reinterpret_cast<uint32_t*>(&rax136) || r8d138 < 0) {
                            r10d135 = 1;
                        }
                        v137 = r8d138;
                        if (r10d135) {
                        }
                        --r13d134;
                    } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r13d134) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r13d134 == 0)));
                }
                --edi133;
            } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(edi133) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(edi133 == 0)));
            r10d139 = reinterpret_cast<uint16_t>(0);
            *reinterpret_cast<uint16_t*>(&r9d140) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d130) + 0xc002);
            if (!(reinterpret_cast<uint1_t>(*reinterpret_cast<int16_t*>(&r9d140) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<uint16_t*>(&r9d140) == 0))) 
                goto addr_18000e02a_171;
        } else {
            addr_18000df34_153:
            *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(&v36) + 4) = 0;
            goto addr_18000e1a0_149;
        }
        addr_18000e066_172:
        *reinterpret_cast<uint16_t*>(&r9d140) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d140) + 0xffff);
        if (*reinterpret_cast<int16_t*>(&r9d140) >= reinterpret_cast<int16_t>(0)) {
            addr_18000e0d3_173:
            eax141 = 0;
        } else {
            eax142 = *reinterpret_cast<uint16_t*>(&r9d140);
            *reinterpret_cast<uint32_t*>(&rdx143) = reinterpret_cast<uint16_t>(-*reinterpret_cast<int16_t*>(&eax142));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx143) + 4) = 0;
            v144 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d140) + *reinterpret_cast<uint16_t*>(&rdx143));
            r9d145 = 0;
            do {
                if (!1) {
                    ++r9d145;
                }
                r10d139 = reinterpret_cast<uint16_t>(0);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v127) + 4) = 0;
                *reinterpret_cast<int32_t*>(&v127) = 0;
                rdx143 = reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rdx143) - 1);
            } while (rdx143);
            r9d140 = v144;
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 8) = reinterpret_cast<uint16_t>(0);
            if (!r9d145) 
                goto addr_18000e0d3_173; else 
                goto addr_18000e0c1_179;
        }
        addr_18000e0d7_180:
        if (*reinterpret_cast<uint16_t*>(&eax141) > 0x8000 || !1) {
            if (1) {
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 2) = reinterpret_cast<uint16_t>(1);
            } else {
                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 2) = reinterpret_cast<uint16_t>(0);
                if (1) {
                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 6) = reinterpret_cast<uint16_t>(1);
                } else {
                    eax146 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 10);
                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 6) = reinterpret_cast<uint16_t>(0);
                    if (*reinterpret_cast<uint16_t*>(&eax146) != 0xffff) {
                        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 10) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&eax146) + 1);
                    } else {
                        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 10) = 0x8000;
                        *reinterpret_cast<uint16_t*>(&r9d140) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d140) + 1);
                    }
                }
                r10d139 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 8);
            }
        }
        r14d39 = 5;
        *reinterpret_cast<uint32_t*>(&rdi42) = 0x7fffffff;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi42) + 4) = 0;
        if (*reinterpret_cast<uint16_t*>(&r9d140) < 0x7fff) {
            eax147 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 2);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 6) = r10d139;
            r10d45 = v117;
            *reinterpret_cast<uint16_t*>(&v36) = *reinterpret_cast<uint16_t*>(&eax147);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v36) + 2) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v127) + 4);
            r8d46 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 4);
            edx47 = *reinterpret_cast<uint16_t*>(&v36);
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d140) | v131);
            goto addr_18000e1a9_150;
        } else {
            *reinterpret_cast<uint32_t*>(&rax125) = v131;
            r10d45 = v117;
            cf132 = reinterpret_cast<uint1_t>(!!*reinterpret_cast<uint16_t*>(&rax125));
            *reinterpret_cast<uint16_t*>(&rax125) = -*reinterpret_cast<uint16_t*>(&rax125);
            goto addr_18000e18f_148;
        }
        addr_18000e0c1_179:
        *reinterpret_cast<uint16_t*>(&eax141) = 1;
        goto addr_18000e0d7_180;
        do {
            addr_18000e02a_171:
            if (0) 
                break;
            *reinterpret_cast<uint16_t*>(&r9d140) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r9d140) + 0xffff);
            r10d139 = reinterpret_cast<uint16_t>(0);
            *reinterpret_cast<int32_t*>(&v127) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&v127) + 4) = 0;
            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v127) + 8) = reinterpret_cast<uint16_t>(0);
        } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(*reinterpret_cast<int16_t*>(&r9d140) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<uint16_t*>(&r9d140) == 0)));
        if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(*reinterpret_cast<int16_t*>(&r9d140) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(*reinterpret_cast<uint16_t*>(&r9d140) == 0))) 
            goto addr_18000e0d3_173; else 
            goto addr_18000e066_172;
        addr_18000df5e_159:
        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v36) + 10) = 0;
        goto addr_18000e1a9_150;
    }
    ecx43 = v44;
    goto addr_18000e1cb_44;
    addr_18000e730_26:
    goto IsProcessorFeaturePresent;
    addr_18000dde2_28:
    goto addr_18000e676_91;
    addr_18000e6f1_35:
    fun_18000391c();
    goto addr_18000e706_30;
    addr_18000dcde_11:
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g0) + 2) = 45;
    goto addr_18000dce7_13;
}

struct s92 {
    signed char[240] pad240;
    void**** f240;
};

struct s93 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s94 {
    signed char[48] pad48;
    void** f48;
};

struct s95 {
    signed char[58] pad58;
    void** f58;
};

struct s0* fun_18000c918(uint64_t* rcx, void** rdx, void* r8, void** r9d) {
    void** rdi5;
    void** rdx6;
    void** v7;
    uint64_t* r14_8;
    void** rbx9;
    uint64_t r12_10;
    uint32_t ebp11;
    void** rax12;
    void** ebx13;
    int32_t r13d14;
    int32_t v15;
    void** rdi16;
    void** rdi17;
    void*** rax18;
    uint32_t edx19;
    void** rdi20;
    uint64_t rax21;
    uint64_t r12_22;
    void** r15_23;
    void** rdi24;
    struct s92* v25;
    void* r8_26;
    uint64_t* rcx27;
    struct s0* rax28;
    void** v29;
    struct s93* v30;
    struct s0* rax31;
    void** rdi32;
    uint64_t rcx33;
    int64_t rcx34;
    uint64_t rcx35;
    void** rdi36;
    void** r8_37;
    uint64_t rdx38;
    uint64_t rdx39;
    int32_t eax40;
    uint64_t rdx41;
    uint64_t rdx42;
    int32_t eax43;
    uint64_t rdx44;
    uint64_t rdx45;
    int32_t eax46;
    uint64_t r8_47;
    uint64_t rax48;
    void** rcx49;
    void** rcx50;
    int32_t v51;
    struct s40* rcx52;
    struct s40* rax53;

    rdi5 = rdx;
    rdx6 = v7;
    r14_8 = rcx;
    rbx9 = r9d;
    *reinterpret_cast<int32_t*>(&rbx9 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&r12_10) = 0x3ff;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_10) + 4) = 0;
    ebp11 = 48;
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 72, rdx6);
    if (reinterpret_cast<signed char>(rbx9) < reinterpret_cast<signed char>(0)) {
        rbx9 = reinterpret_cast<void**>(0);
        *reinterpret_cast<int32_t*>(&rbx9 + 4) = 0;
    }
    if (!rdi5 || !r8) {
        rax12 = fun_1800039c8();
        ebx13 = reinterpret_cast<void**>(22);
    } else {
        *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(0);
        if (reinterpret_cast<uint64_t>(r8) > reinterpret_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(reinterpret_cast<uint64_t>(rbx9 + 11))))) {
            if ((*r14_8 >> 52 & 0x7ff) != 0x7ff) {
                if (*r14_8 & 0x8000000000000000) {
                    *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(45);
                    ++rdi5;
                }
                r13d14 = v15;
                *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(48);
                rdi16 = rdi5 + 1;
                *reinterpret_cast<void***>(rdi16) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(0xff - reinterpret_cast<unsigned char>(0xff + reinterpret_cast<uint1_t>(0xff < reinterpret_cast<unsigned char>(0xff + reinterpret_cast<uint1_t>(!!r13d14))))) & 0xe0) + 0x78);
                rdi17 = rdi16 + 1;
                rax18 = reinterpret_cast<void***>(0x7ff0000000000000);
                edx19 = (*reinterpret_cast<uint32_t*>(&rdx6) - (*reinterpret_cast<uint32_t*>(&rdx6) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rdx6) < *reinterpret_cast<uint32_t*>(&rdx6) + reinterpret_cast<uint1_t>(!!r13d14))) & 0xffffffe0) + 39;
                if (*r14_8 & 0x7ff0000000000000) {
                    *reinterpret_cast<void***>(rdi17) = reinterpret_cast<void**>(49);
                    rdi20 = rdi17 + 1;
                } else {
                    *reinterpret_cast<void***>(rdi17) = reinterpret_cast<void**>(48);
                    rdi20 = rdi17 + 1;
                    rax21 = *r14_8 & 0xfffffffffffff;
                    rax18 = reinterpret_cast<void***>(-rax21);
                    r12_22 = 0x3ff - (0x3ff + reinterpret_cast<uint1_t>(0x3ff < 0x3ff + reinterpret_cast<uint1_t>(!!rax21)));
                    *reinterpret_cast<uint32_t*>(&r12_10) = *reinterpret_cast<uint32_t*>(&r12_22) & 0x3fe;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_10) + 4) = 0;
                }
                r15_23 = rdi20;
                rdi24 = rdi20 + 1;
                if (rbx9) {
                    rax18 = *v25->f240;
                    *reinterpret_cast<void***>(r15_23) = *rax18;
                } else {
                    *reinterpret_cast<void***>(r15_23) = reinterpret_cast<void**>(0);
                }
                if (!(*r14_8 & 0xfffffffffffff)) 
                    goto addr_18000cb89_16; else 
                    goto addr_18000cb01_17;
            } else {
                r8_26 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r8) + 0xfffffffffffffffe);
                if (r8 == 0xffffffffffffffff) {
                    r8_26 = r8;
                }
                rcx27 = r14_8;
                rax28 = fun_18000cec4(rcx27, rdi5 + 2, r8_26, rbx9);
                ebx13 = *reinterpret_cast<void***>(&rax28);
                if (!*reinterpret_cast<void***>(&rax28)) 
                    goto addr_18000c9f5_21; else 
                    goto addr_18000c9ed_22;
            }
        } else {
            rax12 = fun_1800039c8();
            ebx13 = reinterpret_cast<void**>(34);
        }
    }
    *reinterpret_cast<void***>(rax12) = ebx13;
    fun_1800038fc();
    addr_18000cc95_25:
    if (v29) {
        v30->f200 = v30->f200 & 0xfffffffd;
    }
    *reinterpret_cast<void***>(&rax31) = ebx13;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax31) + 4) = 0;
    return rax31;
    addr_18000cb89_16:
    if (!(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(rbx9) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(rbx9 == 0))) {
        *reinterpret_cast<void***>(&rax18) = fun_180003c80(rdi24, 48, rbx9);
        rdi24 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rdi24) + reinterpret_cast<unsigned char>(rbx9));
    }
    if (!*reinterpret_cast<void***>(r15_23)) {
        rdi24 = r15_23;
    }
    *reinterpret_cast<void***>(rdi24) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax18)) - reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax18)) + reinterpret_cast<uint1_t>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax18)) < reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax18)) + reinterpret_cast<uint1_t>(!!r13d14))))) & 0xe0) + 0x70);
    rdi32 = rdi24 + 1;
    rcx33 = *r14_8 >> 52;
    *reinterpret_cast<uint32_t*>(&rcx34) = *reinterpret_cast<uint32_t*>(&rcx33) & 0x7ff;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx34) + 4) = 0;
    rcx35 = rcx34 - r12_10;
    if (reinterpret_cast<int64_t>(rcx35) < reinterpret_cast<int64_t>(0)) {
        *reinterpret_cast<void***>(rdi32) = reinterpret_cast<void**>(45);
        rdi36 = rdi32 + 1;
        rcx35 = -rcx35;
    } else {
        *reinterpret_cast<void***>(rdi32) = reinterpret_cast<void**>(43);
        rdi36 = rdi32 + 1;
    }
    r8_37 = rdi36;
    *reinterpret_cast<void***>(rdi36) = reinterpret_cast<void**>(48);
    if (reinterpret_cast<int64_t>(rcx35) >= reinterpret_cast<int64_t>(0x3e8) && (rdx38 = reinterpret_cast<uint64_t>(__intrinsic() >> 7), rdx39 = rdx38 + (rdx38 >> 63), eax40 = static_cast<int32_t>(48 + rdx39), *reinterpret_cast<void***>(rdi36) = *reinterpret_cast<void***>(&eax40), ++rdi36, rcx35 = rcx35 + rdx39 * 0xfffffffffffffc18, rdi36 != r8_37) || reinterpret_cast<int64_t>(rcx35) >= reinterpret_cast<int64_t>(100)) {
        rdx41 = reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(__intrinsic() + rcx35) >> 6);
        rdx42 = rdx41 + (rdx41 >> 63);
        eax43 = static_cast<int32_t>(48 + rdx42);
        *reinterpret_cast<void***>(rdi36) = *reinterpret_cast<void***>(&eax43);
        ++rdi36;
        rcx35 = rcx35 + rdx42 * 0xffffffffffffff9c;
    }
    if (rdi36 != r8_37 || reinterpret_cast<int64_t>(rcx35) >= reinterpret_cast<int64_t>(10)) {
        rdx44 = reinterpret_cast<uint64_t>(__intrinsic() >> 2);
        rdx45 = rdx44 + (rdx44 >> 63);
        eax46 = static_cast<int32_t>(48 + rdx45);
        *reinterpret_cast<void***>(rdi36) = *reinterpret_cast<void***>(&eax46);
        ++rdi36;
        rcx35 = rcx35 + rdx45 * 0xfffffffffffffff6;
    }
    *reinterpret_cast<void***>(rdi36) = reinterpret_cast<void**>(&(*reinterpret_cast<struct s94**>(&rcx35))->f48);
    *reinterpret_cast<void***>(rdi36 + 1) = reinterpret_cast<void**>(0);
    addr_18000cc92_39:
    ebx13 = reinterpret_cast<void**>(0);
    goto addr_18000cc95_25;
    addr_18000cb01_17:
    r8_47 = 0xf000000000000;
    do {
        if (reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(rbx9) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(rbx9 == 0)) 
            break;
        rax48 = (*r14_8 & r8_47 & 0xfffffffffffff) >> *reinterpret_cast<signed char*>(&ebp11);
        *reinterpret_cast<uint16_t*>(&rax18) = reinterpret_cast<uint16_t>(*reinterpret_cast<int16_t*>(&rax48) + 48);
        if (*reinterpret_cast<uint16_t*>(&rax18) > 57) {
            *reinterpret_cast<uint16_t*>(&rax18) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax18) + *reinterpret_cast<int16_t*>(&edx19));
        }
        *reinterpret_cast<void***>(rdi24) = *reinterpret_cast<void***>(&rax18);
        r8_47 = r8_47 >> 4;
        --rbx9;
        *reinterpret_cast<int32_t*>(&rbx9 + 4) = 0;
        ++rdi24;
        *reinterpret_cast<int16_t*>(&ebp11) = reinterpret_cast<int16_t>(*reinterpret_cast<int16_t*>(&ebp11) - 4);
    } while (*reinterpret_cast<int16_t*>(&ebp11) >= 0);
    if (*reinterpret_cast<int16_t*>(&ebp11) < 0) 
        goto addr_18000cb89_16;
    rax18 = reinterpret_cast<void***>((*r14_8 & r8_47 & 0xfffffffffffff) >> *reinterpret_cast<signed char*>(&ebp11));
    if (*reinterpret_cast<uint16_t*>(&rax18) <= 8) 
        goto addr_18000cb89_16;
    rcx49 = rdi24 + 0xffffffffffffffff;
    while (*reinterpret_cast<void***>(&rax18) = *reinterpret_cast<void***>(rcx49) - 70, !(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax18)) & 0xdf)) {
        *reinterpret_cast<void***>(rcx49) = reinterpret_cast<void**>(48);
        --rcx49;
    }
    if (rcx49 != r15_23) 
        goto addr_18000cb6f_50;
    rcx50 = rcx49 - 1;
    *reinterpret_cast<void***>(rcx50) = *reinterpret_cast<void***>(rcx50) + 1;
    goto addr_18000cb89_16;
    addr_18000cb6f_50:
    *reinterpret_cast<void***>(&rax18) = *reinterpret_cast<void***>(rcx49);
    if (!reinterpret_cast<int1_t>(*reinterpret_cast<void***>(&rax18) == 57)) {
        *reinterpret_cast<void***>(&rax18) = *reinterpret_cast<void***>(&rax18) + 1;
        *reinterpret_cast<void***>(rcx49) = *reinterpret_cast<void***>(&rax18);
        goto addr_18000cb89_16;
    } else {
        *reinterpret_cast<void***>(rcx49) = reinterpret_cast<void**>(&(*reinterpret_cast<struct s95**>(&edx19))->f58);
        goto addr_18000cb89_16;
    }
    addr_18000c9f5_21:
    if (*reinterpret_cast<unsigned char*>(rdi5 + 2) == 45) {
        *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(45);
        ++rdi5;
    }
    *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(48);
    *reinterpret_cast<void***>(rdi5 + 1) = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx27) - reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx27) + reinterpret_cast<uint1_t>(*reinterpret_cast<unsigned char*>(&rcx27) < reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx27) + reinterpret_cast<uint1_t>(!!v51))))) & 0xe0) + 0x78);
    rcx52 = reinterpret_cast<struct s40*>(rdi5 + 2);
    rax53 = fun_18000d8c0(rcx52, 0x65, r8_26);
    if (rax53) {
        rax53->f0 = reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx52) - reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx52) + reinterpret_cast<uint1_t>(*reinterpret_cast<unsigned char*>(&rcx52) < reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rcx52) + reinterpret_cast<uint1_t>(!!v51))))) & 0xe0) + 0x70);
        rax53->f3 = reinterpret_cast<void**>(0);
        goto addr_18000cc92_39;
    }
    addr_18000c9ed_22:
    *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(0);
    goto addr_18000cc95_25;
}

struct s96 {
    signed char[240] pad240;
    void**** f240;
};

struct s97 {
    signed char[200] pad200;
    uint32_t f200;
};

int64_t fun_18000cfbc(void** rcx, void* rdx, void** r8d, struct s39* r9) {
    void** rdi5;
    void** ebx6;
    void** v7;
    void** rax8;
    void** ebx9;
    signed char v10;
    int64_t rax11;
    void** rdi12;
    void* rax13;
    void** rsi14;
    void* rax15;
    struct s96* v16;
    void** ebx17;
    signed char v18;
    void** eax19;
    void* rax20;
    signed char v21;
    struct s97* v22;
    int64_t rax23;

    rdi5 = rcx;
    ebx6 = reinterpret_cast<void**>(reinterpret_cast<int32_t>(r9->f4) - 1);
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 40, v7);
    if (!rdi5 || !rdx) {
        rax8 = fun_1800039c8();
        ebx9 = reinterpret_cast<void**>(22);
        *reinterpret_cast<void***>(rax8) = reinterpret_cast<void**>(22);
        fun_1800038fc();
    } else {
        if (v10 && ebx6 == r8d) {
            *reinterpret_cast<int32_t*>(&rax11) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax11) + 4) = 0;
            *reinterpret_cast<unsigned char*>(&rax11) = reinterpret_cast<uint1_t>(r9->f0 == 45);
            *reinterpret_cast<int16_t*>(reinterpret_cast<int32_t>(ebx6) + reinterpret_cast<uint64_t>(rax11 + reinterpret_cast<unsigned char>(rdi5))) = 48;
        }
        if (r9->f0 == 45) {
            *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(45);
            ++rdi5;
        }
        if (reinterpret_cast<int32_t>(r9->f4) > 0) {
            rdi12 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(rdi5) + reinterpret_cast<uint64_t>(static_cast<int64_t>(reinterpret_cast<int32_t>(r9->f4))));
        } else {
            rax13 = fun_1800084f0(rdi5, rdi5);
            fun_180002f70(rdi5 + 1, rdi5, reinterpret_cast<uint64_t>(rax13) + 1);
            *reinterpret_cast<void***>(rdi5) = reinterpret_cast<void**>(48);
            rdi12 = rdi5 + 1;
        }
        if (!(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(r8d) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(r8d == 0)) && (rsi14 = rdi12 + 1, rax15 = fun_1800084f0(rdi12, rdi12), fun_180002f70(rsi14, rdi12, reinterpret_cast<uint64_t>(rax15) + 1), *reinterpret_cast<void***>(rdi12) = **v16->f240, reinterpret_cast<int32_t>(r9->f4) < 0)) {
            ebx17 = reinterpret_cast<void**>(-reinterpret_cast<int32_t>(r9->f4));
            if (!v18 && (eax19 = ebx17, ebx17 = r8d, reinterpret_cast<signed char>(r8d) >= reinterpret_cast<signed char>(eax19))) {
                ebx17 = eax19;
            }
            if (ebx17) {
                rax20 = fun_1800084f0(rsi14, rsi14);
                fun_180002f70(static_cast<int64_t>(reinterpret_cast<int32_t>(ebx17)) + reinterpret_cast<unsigned char>(rsi14), rsi14, reinterpret_cast<uint64_t>(rax20) + 1);
            }
            fun_180003c80(rsi14, 48, static_cast<int64_t>(reinterpret_cast<int32_t>(ebx17)));
        }
        ebx9 = reinterpret_cast<void**>(0);
    }
    if (v21) {
        v22->f200 = v22->f200 & 0xfffffffd;
    }
    *reinterpret_cast<void***>(&rax23) = ebx9;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax23) + 4) = 0;
    return rax23;
}

struct s98 {
    signed char[240] pad240;
    unsigned char** f240;
};

struct s99 {
    uint16_t f0;
    signed char[2] pad4;
    int32_t f4;
};

struct s100 {
    uint16_t f0;
    signed char[2] pad4;
    int32_t f4;
};

struct s101 {
    uint16_t f0;
    signed char[2] pad4;
    uint16_t f4;
    signed char[2] pad8;
    uint16_t f8;
    uint16_t f10;
};

struct s102 {
    int32_t f0;
    uint16_t f4;
};

struct s103 {
    int32_t f0;
    uint16_t f4;
};

int32_t fun_18000c010(struct s46* rcx, unsigned char** rdx, unsigned char* r8, uint16_t r9d) {
    int64_t v5;
    int64_t r14_6;
    void* rsp7;
    void* rbp8;
    void* rsp9;
    uint64_t rax10;
    uint64_t v11;
    struct s98** r14_12;
    struct s98** v13;
    uint16_t v14;
    struct s46* v15;
    unsigned char** v16;
    int32_t v17;
    uint16_t r11d18;
    uint16_t v19;
    uint16_t r15d20;
    uint16_t v21;
    uint16_t r12d22;
    int64_t r13_23;
    uint16_t esi24;
    uint16_t ecx25;
    unsigned char* rdi26;
    uint32_t r9d27;
    int32_t eax28;
    uint32_t r9d29;
    int32_t eax30;
    uint32_t r9d31;
    uint32_t r9d32;
    int32_t eax33;
    uint32_t r9d34;
    int32_t eax35;
    int32_t eax36;
    uint32_t r9d37;
    int32_t eax38;
    uint32_t r9d39;
    uint16_t v40;
    int32_t eax41;
    void** rax42;
    uint16_t edx43;
    uint32_t eax44;
    uint16_t edi45;
    uint16_t ecx46;
    signed char v47;
    uint64_t rcx48;
    struct s0* rax49;
    uint32_t r13d50;
    uint32_t v51;
    uint32_t v52;
    struct s99* rsi53;
    uint96_t v54;
    struct s100* rdi55;
    uint32_t eax56;
    struct s99* v57;
    uint32_t eax58;
    int64_t rax59;
    struct s101* rdx60;
    struct s101* v61;
    struct s102* rdi62;
    struct s103* rsi63;
    int64_t rax64;
    int64_t rcx65;
    uint96_t v66;
    uint32_t r12d67;
    uint16_t r12w68;
    uint16_t r12w69;
    int32_t r8d70;
    int64_t r15_71;
    uint32_t r10d72;
    uint32_t v73;
    uint16_t* rsi74;
    uint16_t* rdi75;
    uint16_t r11d76;
    int64_t rax77;
    uint32_t v78;
    uint32_t r14d79;
    uint32_t r11d80;
    uint16_t r10d81;
    uint32_t r9d82;
    uint16_t r8w83;
    uint32_t eax84;
    uint16_t edi85;
    int64_t rdx86;
    uint16_t r11d87;
    uint16_t eax88;
    uint32_t eax89;
    int64_t r11_90;
    uint32_t edx91;
    int64_t r13_92;
    int64_t rax93;
    int64_t r13_94;

    v5 = r14_6;
    rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 8 - 8);
    rbp8 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 7);
    rsp9 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp7) - 0xa0);
    rax10 = g1800170a0;
    v11 = rax10 ^ reinterpret_cast<uint64_t>(rsp9);
    r14_12 = v13;
    v14 = r9d;
    v15 = rcx;
    v16 = rdx;
    *reinterpret_cast<uint16_t*>(&v17) = 0;
    r11d18 = reinterpret_cast<uint16_t>(0);
    v19 = reinterpret_cast<uint16_t>(1);
    r15d20 = reinterpret_cast<uint16_t>(0);
    v21 = reinterpret_cast<uint16_t>(0);
    r12d22 = reinterpret_cast<uint16_t>(0);
    *reinterpret_cast<uint16_t*>(&r13_23) = reinterpret_cast<uint16_t>(0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r13_23) + 4) = 0;
    esi24 = reinterpret_cast<uint16_t>(0);
    ecx25 = reinterpret_cast<uint16_t>(0);
    if (r14_12) {
        rdi26 = r8;
        while (*r8 <= 32 && (rdx = reinterpret_cast<unsigned char**>(0x100002600), static_cast<int1_t>(0x100002600 >> static_cast<int64_t>(reinterpret_cast<signed char>(*r8))))) {
            ++r8;
        }
        while (1) {
            *reinterpret_cast<unsigned char*>(&rdx) = *r8;
            ++r8;
            if (reinterpret_cast<int16_t>(ecx25) > reinterpret_cast<int16_t>(5)) {
                r9d27 = ecx25 - 6;
                if (!r9d27) {
                    eax28 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 49);
                    rdi26 = r8 - 2;
                    if (*reinterpret_cast<unsigned char*>(&eax28) <= 8) {
                        addr_18000c352_8:
                        ecx25 = reinterpret_cast<uint16_t>(9);
                    } else {
                        if (*reinterpret_cast<unsigned char*>(&rdx) == 43) {
                            ecx25 = reinterpret_cast<uint16_t>(7);
                            goto addr_18000c38b_11;
                        } else {
                            if (*reinterpret_cast<unsigned char*>(&rdx) == 45) {
                                addr_18000c307_13:
                                v19 = reinterpret_cast<uint16_t>(0xffffffff);
                                ecx25 = reinterpret_cast<uint16_t>(7);
                                goto addr_18000c1ee_14;
                            } else {
                                goto addr_18000c35c_16;
                            }
                        }
                    }
                } else {
                    r9d29 = r9d27 - 1;
                    if (!r9d29) {
                        eax30 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 49);
                        if (*reinterpret_cast<unsigned char*>(&eax30) > 8) 
                            goto addr_18000c35c_16; else 
                            goto addr_18000c352_8;
                    } else {
                        r9d31 = r9d29 - 1;
                        if (!r9d31) {
                            r12d22 = reinterpret_cast<uint16_t>(1);
                            while (*reinterpret_cast<unsigned char*>(&rdx) == 48) {
                                *reinterpret_cast<unsigned char*>(&rdx) = *r8;
                                ++r8;
                            }
                            if (reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rdx) - 49) > 8) 
                                goto addr_18000c285_24;
                            ecx25 = reinterpret_cast<uint16_t>(9);
                            goto addr_18000c1d0_26;
                        } else {
                            r9d32 = r9d31 - 1;
                            if (!r9d32) 
                                goto addr_18000c39a_28;
                            if (r9d32 != 2) 
                                goto addr_18000c38b_11; else 
                                goto addr_18000c2f0_30;
                        }
                    }
                }
            } else {
                if (ecx25 == 5) {
                    v21 = reinterpret_cast<uint16_t>(1);
                    if (reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rdx) - 48) > 9) 
                        goto addr_18000c395_33;
                    ecx25 = reinterpret_cast<uint16_t>(4);
                    goto addr_18000c1d0_26;
                } else {
                    if (!ecx25) {
                        eax33 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 49);
                        if (*reinterpret_cast<unsigned char*>(&eax33) <= 8) {
                            addr_18000c1c5_37:
                            ecx25 = reinterpret_cast<uint16_t>(3);
                        } else {
                            if (*reinterpret_cast<unsigned char*>(&rdx) == **(*r14_12)->f240) {
                                addr_18000c1e9_39:
                                ecx25 = reinterpret_cast<uint16_t>(5);
                                goto addr_18000c1ee_14;
                            } else {
                                if (*reinterpret_cast<unsigned char*>(&rdx) == 43) {
                                    ecx25 = reinterpret_cast<uint16_t>(2);
                                    *reinterpret_cast<uint16_t*>(&v17) = 0;
                                    goto addr_18000c1ee_14;
                                } else {
                                    if (*reinterpret_cast<unsigned char*>(&rdx) == 45) {
                                        ecx25 = reinterpret_cast<uint16_t>(2);
                                        v17 = 0x8000;
                                        goto addr_18000c1ee_14;
                                    } else {
                                        if (*reinterpret_cast<unsigned char*>(&rdx) == 48) 
                                            goto addr_18000c202_45; else 
                                            goto addr_18000c27f_46;
                                    }
                                }
                            }
                        }
                    } else {
                        r9d34 = ecx25 - 1;
                        if (!r9d34) {
                            eax35 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 49);
                            r15d20 = reinterpret_cast<uint16_t>(1);
                            if (*reinterpret_cast<unsigned char*>(&eax35) > 8) {
                                if (*reinterpret_cast<unsigned char*>(&rdx) == **(*r14_12)->f240) {
                                    addr_18000c1b4_50:
                                    ecx25 = reinterpret_cast<uint16_t>(4);
                                    continue;
                                } else {
                                    eax36 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 43);
                                    if (!(*reinterpret_cast<unsigned char*>(&eax36) & 0xfd)) {
                                        addr_18000c164_52:
                                        --r8;
                                        ecx25 = reinterpret_cast<uint16_t>(11);
                                        continue;
                                    } else {
                                        if (*reinterpret_cast<unsigned char*>(&rdx) == 48) {
                                            addr_18000c208_54:
                                            ecx25 = reinterpret_cast<uint16_t>(1);
                                            continue;
                                        } else {
                                            goto addr_18000c140_56;
                                        }
                                    }
                                }
                            } else {
                                ecx25 = reinterpret_cast<uint16_t>(3);
                                goto addr_18000c1d0_26;
                            }
                        } else {
                            r9d37 = r9d34 - 1;
                            if (!r9d37) {
                                eax38 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 49);
                                if (*reinterpret_cast<unsigned char*>(&eax38) <= 8) 
                                    goto addr_18000c1c5_37;
                                if (*reinterpret_cast<unsigned char*>(&rdx) == **(*r14_12)->f240) 
                                    goto addr_18000c1e9_39;
                                if (*reinterpret_cast<unsigned char*>(&rdx) != 48) 
                                    goto addr_18000c3f4_62; else 
                                    goto addr_18000c202_45;
                            } else {
                                r9d39 = r9d37 - 1;
                                if (!r9d39) {
                                    r15d20 = reinterpret_cast<uint16_t>(1);
                                    while (*reinterpret_cast<signed char*>(&rdx) >= reinterpret_cast<signed char>(48) && *reinterpret_cast<signed char*>(&rdx) <= reinterpret_cast<signed char>(57)) {
                                        if (r11d18 >= reinterpret_cast<uint16_t>(25)) {
                                            esi24 = reinterpret_cast<uint16_t>(esi24 + reinterpret_cast<uint16_t>(1));
                                        } else {
                                            r11d18 = reinterpret_cast<uint16_t>(r11d18 + reinterpret_cast<uint16_t>(1));
                                        }
                                        *reinterpret_cast<unsigned char*>(&rdx) = *r8;
                                        ++r8;
                                    }
                                    if (*reinterpret_cast<unsigned char*>(&rdx) != **(*r14_12)->f240) 
                                        goto addr_18000c139_71; else 
                                        goto addr_18000c1b4_50;
                                } else {
                                    if (r9d39 - 1) {
                                        addr_18000c38b_11:
                                        if (ecx25 == 10) 
                                            break; else 
                                            goto addr_18000c390_73;
                                    } else {
                                        r15d20 = reinterpret_cast<uint16_t>(1);
                                        v21 = reinterpret_cast<uint16_t>(1);
                                        if (!r11d18) {
                                            while (*reinterpret_cast<unsigned char*>(&rdx) == 48) {
                                                *reinterpret_cast<unsigned char*>(&rdx) = *r8;
                                                esi24 = reinterpret_cast<uint16_t>(esi24 - reinterpret_cast<uint16_t>(1));
                                                ++r8;
                                            }
                                        }
                                        while (*reinterpret_cast<signed char*>(&rdx) >= reinterpret_cast<signed char>(48) && *reinterpret_cast<signed char*>(&rdx) <= reinterpret_cast<signed char>(57)) {
                                            if (r11d18 < reinterpret_cast<uint16_t>(25)) {
                                                r11d18 = reinterpret_cast<uint16_t>(r11d18 + reinterpret_cast<uint16_t>(1));
                                                esi24 = reinterpret_cast<uint16_t>(esi24 - reinterpret_cast<uint16_t>(1));
                                            }
                                            *reinterpret_cast<unsigned char*>(&rdx) = *r8;
                                            ++r8;
                                        }
                                        goto addr_18000c139_71;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            addr_18000c1d0_26:
            --r8;
            continue;
            addr_18000c1ee_14:
            continue;
            addr_18000c35c_16:
            if (*reinterpret_cast<unsigned char*>(&rdx) != 48) 
                goto addr_18000c3f4_62;
            ecx25 = reinterpret_cast<uint16_t>(8);
            goto addr_18000c1ee_14;
            addr_18000c2f0_30:
            if (!v40) 
                goto addr_18000c27f_46;
            rdi26 = r8 - 1;
            if (*reinterpret_cast<unsigned char*>(&rdx) != 43) 
                goto addr_18000c2fe_86;
            ecx25 = reinterpret_cast<uint16_t>(7);
            goto addr_18000c1ee_14;
            addr_18000c2fe_86:
            if (*reinterpret_cast<unsigned char*>(&rdx) != 45) 
                goto addr_18000c3f4_62; else 
                goto addr_18000c307_13;
            addr_18000c202_45:
            goto addr_18000c208_54;
            addr_18000c140_56:
            if (*reinterpret_cast<signed char*>(&rdx) <= reinterpret_cast<signed char>(67)) 
                goto addr_18000c285_24;
            if (*reinterpret_cast<signed char*>(&rdx) <= reinterpret_cast<signed char>(69)) 
                goto addr_18000c15a_89;
            if (reinterpret_cast<unsigned char>(*reinterpret_cast<unsigned char*>(&rdx) - 100) > 1) 
                goto addr_18000c285_24;
            addr_18000c15a_89:
            ecx25 = reinterpret_cast<uint16_t>(6);
            continue;
            addr_18000c139_71:
            eax41 = static_cast<int32_t>(reinterpret_cast<uint64_t>(rdx) - 43);
            if (!(*reinterpret_cast<unsigned char*>(&eax41) & 0xfd)) 
                goto addr_18000c164_52; else 
                goto addr_18000c140_56;
            addr_18000c390_73:
            goto addr_18000c1ee_14;
        }
    } else {
        rax42 = fun_1800039c8();
        *reinterpret_cast<void***>(rax42) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        rsp9 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp9) - 8 + 8 - 8 + 8);
        goto addr_18000c84a_92;
    }
    addr_18000c3f7_93:
    addr_18000c3fd_94:
    *v16 = r8;
    if (!r15d20) {
        edx43 = reinterpret_cast<uint16_t>(0);
        eax44 = 0;
        edi45 = reinterpret_cast<uint16_t>(0);
        ecx46 = reinterpret_cast<uint16_t>(0);
    } else {
        if (r11d18 > reinterpret_cast<uint16_t>(24)) {
            if (v47 >= 5) {
            }
            r11d18 = reinterpret_cast<uint16_t>(24);
            esi24 = reinterpret_cast<uint16_t>(esi24 + reinterpret_cast<uint16_t>(1));
        }
        if (r11d18) 
            goto addr_18000c446_101; else 
            goto addr_18000c431_102;
    }
    addr_18000c82f_103:
    v15->f10 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&eax44) | *reinterpret_cast<uint16_t*>(&v17));
    v15->f0 = *reinterpret_cast<int16_t*>(&edx43);
    v15->f2 = ecx46;
    v15->f6 = edi45;
    addr_18000c84a_92:
    rcx48 = v11 ^ reinterpret_cast<uint64_t>(rsp9);
    rax49 = fun_180002f40(rcx48, rcx48);
    return *reinterpret_cast<int32_t*>(&rax49);
    addr_18000c446_101:
    while (!*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&v5) + 4)) {
        r11d18 = reinterpret_cast<uint16_t>(r11d18 - 1);
        esi24 = reinterpret_cast<uint16_t>(esi24 + reinterpret_cast<uint16_t>(1));
    }
    fun_18000d4ac(reinterpret_cast<int64_t>(rbp8) - 33, r11d18, reinterpret_cast<int64_t>(rbp8) - 65);
    rsp9 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp9) - 8 + 8);
    if (reinterpret_cast<int16_t>(v19) < reinterpret_cast<int16_t>(0)) 
        goto addr_18000c463_106;
    addr_18000c466_107:
    r13d50 = *reinterpret_cast<uint16_t*>(&r13_23) + esi24;
    if (!r12d22) {
        r13d50 = r13d50 + v51;
    }
    if (!v21) {
        r13d50 = r13d50 - v52;
    }
    if (reinterpret_cast<int32_t>(r13d50) > reinterpret_cast<int32_t>(0x1450)) {
        ecx46 = reinterpret_cast<uint16_t>(0);
        edx43 = reinterpret_cast<uint16_t>(0);
        eax44 = 0x7fff;
        edi45 = reinterpret_cast<uint16_t>(0x80000000);
        goto addr_18000c82f_103;
    } else {
        if (reinterpret_cast<int32_t>(r13d50) < reinterpret_cast<int32_t>(0xffffebb0)) {
            edx43 = reinterpret_cast<uint16_t>(0);
            eax44 = 0;
            edi45 = reinterpret_cast<uint16_t>(0);
            ecx46 = reinterpret_cast<uint16_t>(0);
            goto addr_18000c82f_103;
        } else {
            rsi53 = reinterpret_cast<struct s99*>(0x180018330);
            if (r13d50) {
                if (reinterpret_cast<int32_t>(r13d50) < reinterpret_cast<int32_t>(0)) {
                    r13d50 = -r13d50;
                    rsi53 = reinterpret_cast<struct s99*>(0x180018490);
                }
                if (!v14) {
                    *reinterpret_cast<uint16_t*>(&v54) = 0;
                }
                if (r13d50) {
                    *reinterpret_cast<uint32_t*>(&rdi55) = 0x80000000;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi55) + 4) = 0;
                    while (1) {
                        eax56 = r13d50;
                        rsi53 = reinterpret_cast<struct s99*>(reinterpret_cast<int64_t>(rsi53) + 84);
                        r13d50 = reinterpret_cast<uint32_t>(reinterpret_cast<int32_t>(r13d50) >> 3);
                        v57 = rsi53;
                        eax58 = eax56 & 7;
                        if (!eax58) {
                            addr_18000c7df_123:
                            if (r13d50) 
                                continue; else 
                                break;
                        } else {
                            rax59 = reinterpret_cast<int32_t>(eax58);
                            rdx60 = reinterpret_cast<struct s101*>(reinterpret_cast<int64_t>(rsi53) + (rax59 + rax59 * 2) * 4);
                            v61 = rdx60;
                            if (rdx60->f0 >= 0x8000) {
                                rdi55->f0 = rsi53->f0;
                                rdi62 = reinterpret_cast<struct s102*>(&rdi55->f4);
                                rsi63 = reinterpret_cast<struct s103*>(&rsi53->f4);
                                rdx60 = reinterpret_cast<struct s101*>(reinterpret_cast<int64_t>(rbp8) - 49);
                                rdi62->f0 = rsi63->f0;
                                rdi55 = reinterpret_cast<struct s100*>(&rdi62->f4);
                                rsi53 = reinterpret_cast<struct s99*>(&rsi63->f4);
                                v61 = rdx60;
                            }
                            *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(static_cast<uint32_t>(rdx60->f10));
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax64) + 4) = 0;
                            *reinterpret_cast<uint32_t*>(&rcx65) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 10);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx65) + 4) = 0;
                            *reinterpret_cast<int64_t*>(&v66) = 0;
                            r12d67 = *reinterpret_cast<uint16_t*>(&rax64);
                            *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax64) & 0x7fff);
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 8) = reinterpret_cast<uint16_t>(0);
                            r12w68 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r12d67) ^ *reinterpret_cast<uint16_t*>(&rcx65));
                            *reinterpret_cast<uint16_t*>(&rcx65) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rcx65) & 0x7fff);
                            r12w69 = reinterpret_cast<uint16_t>(r12w68 & 0x8000);
                            r8d70 = static_cast<int32_t>(rcx65 + rax64);
                            if (*reinterpret_cast<uint16_t*>(&rcx65) >= 0x7fff) 
                                goto addr_18000c7cb_133;
                            if (*reinterpret_cast<uint16_t*>(&rax64) >= 0x7fff) 
                                goto addr_18000c7cb_133;
                            if (*reinterpret_cast<uint16_t*>(&r8d70) > 0xbffd) 
                                goto addr_18000c7cb_133;
                            if (*reinterpret_cast<uint16_t*>(&r8d70) <= 0x3fbf) 
                                goto addr_18000c58a_137;
                            if (*reinterpret_cast<uint16_t*>(&rcx65)) 
                                goto addr_18000c5bb_139;
                            *reinterpret_cast<uint16_t*>(&r8d70) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r8d70) + 1);
                            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v54) + 8) & 0x7fffffff) 
                                goto addr_18000c5bb_139;
                            if (*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 4)) 
                                goto addr_18000c5bb_139;
                            if (!*reinterpret_cast<uint16_t*>(&v54)) 
                                goto addr_18000c5b2_143;
                        }
                        addr_18000c5bb_139:
                        if (*reinterpret_cast<uint16_t*>(&rax64) || ((*reinterpret_cast<uint16_t*>(&r8d70) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r8d70) + 1), !!(rdx60->f8 & 0x7fffffff)) || (rdx60->f4 || rdx60->f0))) {
                            *reinterpret_cast<uint16_t*>(&r15_71) = reinterpret_cast<uint16_t>(0);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r15_71) + 4) = 0;
                            r10d72 = 5;
                            do {
                                v73 = r10d72;
                                if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r10d72) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r10d72 == 0))) {
                                    rsi74 = &rdx60->f8;
                                    rdi75 = reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(rbp8) - 65 + static_cast<int32_t>(r15_71 + r15_71));
                                    do {
                                        r11d76 = reinterpret_cast<uint16_t>(0);
                                        *reinterpret_cast<uint32_t*>(&rcx65) = *rsi74 * *rdi75;
                                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx65) + 4) = 0;
                                        *reinterpret_cast<uint32_t*>(&rax77) = v78;
                                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax77) + 4) = 0;
                                        r14d79 = static_cast<uint32_t>(rax77 + rcx65);
                                        if (r14d79 < *reinterpret_cast<uint32_t*>(&rax77) || r14d79 < *reinterpret_cast<uint32_t*>(&rcx65)) {
                                            r11d76 = reinterpret_cast<uint16_t>(1);
                                        }
                                        v78 = r14d79;
                                        if (r11d76) {
                                        }
                                        ++rdi75;
                                        --rsi74;
                                        r11d80 = v73 - 1;
                                        v73 = r11d80;
                                    } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r11d80) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r11d80 == 0)));
                                    rdx60 = v61;
                                }
                                --r10d72;
                                *reinterpret_cast<uint16_t*>(&r15_71) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r15_71) + 1);
                                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r15_71) + 4) = 0;
                            } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(r10d72) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(r10d72 == 0)));
                            r10d81 = reinterpret_cast<uint16_t>(0);
                            r9d82 = 0;
                            r8w83 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r8d70) + 0xc002);
                            *reinterpret_cast<uint32_t*>(&rdi55) = 0x80000000;
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi55) + 4) = 0;
                            if (!(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r8w83) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r8w83 == 0))) 
                                goto addr_18000c68d_155;
                        } else {
                            addr_18000c58a_137:
                            *reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(&v54) + 4) = 0;
                            *reinterpret_cast<uint16_t*>(&v54) = reinterpret_cast<uint16_t>(0);
                            goto addr_18000c7df_123;
                        }
                        addr_18000c6cc_156:
                        r8w83 = reinterpret_cast<uint16_t>(r8w83 + 0xffff);
                        if (reinterpret_cast<int16_t>(r8w83) >= reinterpret_cast<int16_t>(0)) {
                            addr_18000c736_157:
                            *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(static_cast<uint32_t>(*reinterpret_cast<uint16_t*>(&v66)));
                        } else {
                            eax84 = r8w83;
                            edi85 = reinterpret_cast<uint16_t>(0);
                            *reinterpret_cast<uint32_t*>(&rdx86) = reinterpret_cast<uint16_t>(-*reinterpret_cast<int16_t*>(&eax84));
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx86) + 4) = 0;
                            r8w83 = reinterpret_cast<uint16_t>(r8w83 + *reinterpret_cast<uint16_t*>(&rdx86));
                            do {
                                if (*reinterpret_cast<unsigned char*>(&v66) & 1) {
                                    edi85 = reinterpret_cast<uint16_t>(edi85 + 1);
                                }
                                r11d87 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 4) >> 1 | r10d81 << 31);
                                r10d81 = reinterpret_cast<uint16_t>(r10d81 >> 1);
                                r9d82 = r9d82 >> 1 | *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 4) << 31;
                                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 4) = r11d87;
                                *reinterpret_cast<uint32_t*>(&v66) = r9d82;
                                --rdx86;
                            } while (rdx86);
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 8) = r10d81;
                            *reinterpret_cast<uint32_t*>(&rdi55) = 0x80000000;
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi55) + 4) = 0;
                            if (!edi85) 
                                goto addr_18000c736_157; else 
                                goto addr_18000c724_163;
                        }
                        addr_18000c73a_164:
                        rsi53 = v57;
                        if (*reinterpret_cast<uint16_t*>(&rax64) > 0x8000 || (r9d82 & 0x1ffff) == 0x18000) {
                            if (1) {
                                *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 2) + 1);
                                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 2) = *reinterpret_cast<uint16_t*>(&rax64);
                            } else {
                                eax88 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 6);
                                *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 2) = reinterpret_cast<uint16_t>(0);
                                if (1) {
                                    *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(eax88 + 1);
                                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 6) = *reinterpret_cast<uint16_t*>(&rax64);
                                } else {
                                    *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(static_cast<uint32_t>(*reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 10)));
                                    *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 6) = reinterpret_cast<uint16_t>(0);
                                    if (*reinterpret_cast<uint16_t*>(&rax64) != 0xffff) {
                                        *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax64) + 1);
                                        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 10) = *reinterpret_cast<uint16_t*>(&rax64);
                                    } else {
                                        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 10) = 0x8000;
                                        r8w83 = reinterpret_cast<uint16_t>(r8w83 + 1);
                                    }
                                }
                                r10d81 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 8);
                            }
                        }
                        if (r8w83 >= 0x7fff) {
                            addr_18000c7cb_133:
                            *reinterpret_cast<int64_t*>(&v54) = 0;
                            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v54) + 8) = (*reinterpret_cast<uint16_t*>(&rax64) - (*reinterpret_cast<uint16_t*>(&rax64) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint16_t*>(&rax64) < reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax64) + reinterpret_cast<uint1_t>(!!r12w69)))) & *reinterpret_cast<uint32_t*>(&rdi55)) + 0x7fff8000;
                            goto addr_18000c7df_123;
                        } else {
                            eax89 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 2);
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 6) = r10d81;
                            *reinterpret_cast<uint16_t*>(&v54) = *reinterpret_cast<uint16_t*>(&eax89);
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 10) = reinterpret_cast<uint16_t>(r8w83 | r12w69);
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 2) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 4);
                            goto addr_18000c7df_123;
                        }
                        addr_18000c724_163:
                        *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(static_cast<uint32_t>(*reinterpret_cast<uint16_t*>(&r9d82)));
                        *reinterpret_cast<uint16_t*>(&rax64) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rax64) | 1);
                        *reinterpret_cast<uint16_t*>(&v66) = *reinterpret_cast<uint16_t*>(&rax64);
                        r9d82 = *reinterpret_cast<uint32_t*>(&v66);
                        goto addr_18000c73a_164;
                        do {
                            addr_18000c68d_155:
                            if (0x80000000 & r10d81) 
                                break;
                            *reinterpret_cast<uint16_t*>(&r11_90) = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 4);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r11_90) + 4) = 0;
                            edx91 = r9d82 >> 31;
                            r9d82 = r9d82 + r9d82;
                            r8w83 = reinterpret_cast<uint16_t>(r8w83 + 0xffff);
                            r10d81 = reinterpret_cast<uint16_t>(r10d81 + r10d81 | *reinterpret_cast<uint16_t*>(&r11_90) >> 31);
                            *reinterpret_cast<uint32_t*>(&v66) = r9d82;
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 4) = reinterpret_cast<uint16_t>(static_cast<uint32_t>(r11_90 + r11_90) | edx91);
                            *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v66) + 8) = r10d81;
                        } while (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r8w83) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r8w83 == 0)));
                        if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int16_t>(r8w83) < reinterpret_cast<int16_t>(0)) | reinterpret_cast<uint1_t>(r8w83 == 0))) 
                            goto addr_18000c736_157; else 
                            goto addr_18000c6cc_156;
                        addr_18000c5b2_143:
                        *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 10) = 0;
                        goto addr_18000c7df_123;
                    }
                }
            }
            edx43 = reinterpret_cast<uint16_t>(static_cast<uint32_t>(*reinterpret_cast<uint16_t*>(&v54)));
            ecx46 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 2);
            edi45 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(&v54) + 6);
            eax44 = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v54) + 8) >> 16;
            goto addr_18000c82f_103;
        }
    }
    addr_18000c463_106:
    *reinterpret_cast<uint16_t*>(&r13_23) = -*reinterpret_cast<uint16_t*>(&r13_23);
    goto addr_18000c466_107;
    addr_18000c431_102:
    edx43 = reinterpret_cast<uint16_t>(0);
    eax44 = 0;
    edi45 = reinterpret_cast<uint16_t>(0);
    ecx46 = reinterpret_cast<uint16_t>(0);
    goto addr_18000c82f_103;
    addr_18000c3f4_62:
    r8 = rdi26;
    goto addr_18000c3f7_93;
    addr_18000c285_24:
    --r8;
    goto addr_18000c3fd_94;
    addr_18000c39a_28:
    r12d22 = reinterpret_cast<uint16_t>(1);
    while (*reinterpret_cast<signed char*>(&rdx) >= reinterpret_cast<signed char>(48)) {
        if (*reinterpret_cast<signed char*>(&rdx) > reinterpret_cast<signed char>(57)) 
            goto addr_18000c3ea_180;
        *reinterpret_cast<int32_t*>(&r13_92) = static_cast<int32_t>(r13_23 + r13_23 * 4);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r13_92) + 4) = 0;
        *reinterpret_cast<int32_t*>(&rax93) = *reinterpret_cast<signed char*>(&rdx);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax93) + 4) = 0;
        *reinterpret_cast<int32_t*>(&r13_94) = static_cast<int32_t>(r13_92 - 24);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r13_94) + 4) = 0;
        *reinterpret_cast<uint16_t*>(&r13_23) = reinterpret_cast<uint16_t>(static_cast<uint32_t>(rax93 + r13_94 * 2));
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r13_23) + 4) = 0;
        if (*reinterpret_cast<int16_t*>(&r13_23) > reinterpret_cast<int16_t>(0x1450)) 
            goto addr_18000c3d3_182;
        *reinterpret_cast<unsigned char*>(&rdx) = *r8;
        ++r8;
    }
    addr_18000c3ea_180:
    while (*reinterpret_cast<signed char*>(&rdx) >= reinterpret_cast<signed char>(48)) {
        if (*reinterpret_cast<signed char*>(&rdx) > reinterpret_cast<signed char>(57)) 
            goto addr_18000c285_24;
        *reinterpret_cast<unsigned char*>(&rdx) = *r8;
        ++r8;
    }
    goto addr_18000c285_24;
    addr_18000c3d3_182:
    *reinterpret_cast<uint16_t*>(&r13_23) = reinterpret_cast<uint16_t>(0x1451);
    goto addr_18000c3ea_180;
    addr_18000c27f_46:
    goto addr_18000c285_24;
    addr_18000c395_33:
    r8 = rdi26;
    goto addr_18000c3fd_94;
}

uint32_t g180018360 = 53;

uint32_t g18001835c = 0xfffffc01;

uint32_t g180018364 = 11;

uint32_t g180018358 = 0x400;

int32_t g18001836c = 0x3ff;

int32_t g180018368 = 64;

int32_t fun_18000b4a0(struct s47* rcx, struct s45* rdx, unsigned char* r8) {
    void* rsp4;
    void* rbp5;
    void* rsp6;
    uint64_t rax7;
    uint64_t v8;
    uint32_t eax9;
    uint32_t v10;
    int64_t v11;
    uint32_t eax12;
    uint32_t edi13;
    struct s45* v14;
    void* r14_15;
    int64_t v16;
    uint32_t eax17;
    uint32_t v18;
    uint32_t eax19;
    uint32_t r13d20;
    uint32_t v21;
    uint32_t edx22;
    uint32_t eax23;
    int64_t r10_24;
    uint32_t r8d25;
    int64_t r11_26;
    uint32_t ecx27;
    uint32_t v28;
    uint32_t ecx29;
    void* rdx30;
    uint64_t r8_31;
    void** rcx32;
    uint32_t ecx33;
    int64_t rdx34;
    uint32_t edx35;
    uint32_t eax36;
    int64_t r8_37;
    uint32_t ecx38;
    int64_t r11_39;
    int64_t rax40;
    int64_t rdx41;
    uint32_t ecx42;
    void* rcx43;
    uint32_t r8d44;
    void* rax45;
    uint32_t ecx46;
    uint32_t eax47;
    uint32_t r10d48;
    uint32_t edx49;
    uint32_t eax50;
    uint32_t eax51;
    int32_t r11d52;
    uint32_t ecx53;
    uint32_t r15d54;
    int32_t r8d55;
    uint32_t r10d56;
    uint32_t edi57;
    uint32_t r13d58;
    uint32_t ecx59;
    uint32_t ecx60;
    uint32_t v61;
    uint64_t r10_62;
    uint64_t rdi63;
    int64_t r9_64;
    void* rdx65;
    uint32_t r13d66;
    uint32_t edi67;
    uint32_t r9d68;
    uint32_t ecx69;
    uint32_t ecx70;
    uint32_t v71;
    uint64_t r9_72;
    uint64_t rdi73;
    int64_t r8_74;
    void* rdx75;
    int32_t r8d76;
    void* r11_77;
    uint32_t r9d78;
    uint32_t edx79;
    uint32_t eax80;
    uint32_t eax81;
    int32_t r13d82;
    uint32_t ecx83;
    uint32_t edi84;
    uint32_t r14d85;
    uint32_t r10d86;
    uint32_t ecx87;
    uint32_t ecx88;
    void* rdx89;
    uint32_t v90;
    uint32_t v91;
    uint64_t r10_92;
    uint64_t rdi93;
    void* r14_94;
    uint64_t r8_95;
    int64_t r9_96;
    int64_t r8_97;
    uint32_t edx98;
    uint32_t eax99;
    int64_t r9_100;
    uint32_t r11d101;
    uint32_t r12d102;
    int32_t eax103;
    uint32_t r8d104;
    uint64_t rcx105;
    struct s0* rax106;
    uint32_t ecx107;
    int64_t rcx108;
    void* rdx109;
    void* r8_110;
    void** rcx111;
    uint32_t eax112;
    uint32_t r9d113;
    uint32_t edx114;
    uint32_t eax115;
    uint32_t eax116;
    int32_t r10d117;
    uint32_t ecx118;
    uint32_t r11d119;
    uint32_t r13d120;
    uint32_t r15d121;
    uint32_t ecx122;
    uint32_t ecx123;
    uint64_t r10_124;
    uint64_t r8_125;
    int64_t r9_126;
    void* rdx127;
    uint32_t ecx128;
    int64_t rdx129;
    uint32_t edx130;
    uint32_t eax131;
    int64_t r10_132;
    uint32_t ecx133;
    int64_t r13_134;
    int64_t rax135;
    int64_t rdx136;
    uint32_t ecx137;
    uint32_t r8d138;
    void* rcx139;
    int32_t eax140;
    uint64_t rdx141;
    int64_t rax142;
    uint32_t r8d143;
    int32_t eax144;
    uint64_t rdx145;
    int64_t rax146;
    uint32_t r8d147;

    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8);
    rbp5 = rsp4;
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp4) - 96);
    rax7 = g1800170a0;
    v8 = rax7 ^ reinterpret_cast<uint64_t>(rsp6);
    eax9 = rcx->f10;
    v10 = eax9 & 0x8000;
    *reinterpret_cast<uint32_t*>(&v11) = rcx->f6;
    eax12 = rcx->f2;
    edi13 = (eax9 & 0x7fff) - 0x3fff;
    v14 = rdx;
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v11) + 4) = eax12;
    *reinterpret_cast<int32_t*>(&r14_15) = 3;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_15) + 4) = 0;
    if (edi13 != 0xffffc001) {
        v16 = v11;
        eax17 = g180018360;
        v18 = edi13;
        eax19 = eax17 - 1;
        r13d20 = 0;
        v21 = eax19;
        __asm__("cdq ");
        edx22 = *reinterpret_cast<uint32_t*>(&rdx) & 31;
        eax23 = eax19 + 1 + edx22;
        *reinterpret_cast<int32_t*>(&r10_24) = reinterpret_cast<int32_t>(eax23) >> 5;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_24) + 4) = 0;
        r8d25 = 31 - ((eax23 & 31) - edx22);
        r11_26 = *reinterpret_cast<int32_t*>(&r10_24);
        ecx27 = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_26 * 4 - 24);
        v28 = r8d25;
        if (!static_cast<int1_t>(ecx27 >> r8d25)) {
            addr_18000b633_3:
            ecx29 = r8d25;
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_26 * 4 - 24) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_26 * 4 - 24) & 0xffffffff << *reinterpret_cast<unsigned char*>(&ecx29);
            rdx30 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r10_24 + 1)));
            if (reinterpret_cast<int64_t>(rdx30) < reinterpret_cast<int64_t>(3)) {
                r8_31 = 3 - reinterpret_cast<uint64_t>(rdx30);
                rcx32 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) - 24 + reinterpret_cast<uint64_t>(rdx30) * 4);
                *reinterpret_cast<uint32_t*>(&rdx30) = 0;
                fun_180003c80(rcx32, 0, r8_31 << 2);
                rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
            }
        } else {
            ecx33 = r8d25;
            rdx34 = *reinterpret_cast<int32_t*>(&r10_24);
            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx34 * 4 - 24) & reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx33)))) {
                addr_18000b5c1_6:
                __asm__("cdq ");
                edx35 = *reinterpret_cast<uint32_t*>(&rdx34) & 31;
                eax36 = v21 + edx35;
                *reinterpret_cast<int32_t*>(&r8_37) = reinterpret_cast<int32_t>(eax36) >> 5;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_37) + 4) = 0;
                ecx38 = 31 - ((eax36 & 31) - edx35);
                r11_39 = *reinterpret_cast<int32_t*>(&r8_37);
                *reinterpret_cast<uint32_t*>(&rax40) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_39 * 4 - 24);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax40) + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rdx41) = 1 << *reinterpret_cast<unsigned char*>(&ecx38);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx41) + 4) = 0;
                ecx42 = static_cast<uint32_t>(rax40 + rdx41);
                if (ecx42 < *reinterpret_cast<uint32_t*>(&rax40) || ecx42 < *reinterpret_cast<uint32_t*>(&rdx41)) {
                    r13d20 = 1;
                    goto addr_18000b5f5_8;
                }
            } else {
                rcx43 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r10_24 + 1)));
                while (reinterpret_cast<int64_t>(rcx43) < reinterpret_cast<int64_t>(3)) {
                    if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rcx43) * 4 - 24)) 
                        goto addr_18000b5c1_6;
                    rcx43 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx43) + 1);
                }
                goto addr_18000b5bf_13;
            }
        }
    } else {
        r8d44 = 0;
        *reinterpret_cast<uint32_t*>(&rax45) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax45) + 4) = 0;
        do {
            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) * 4 - 24)) 
                goto addr_18000b537_16;
            rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rax45) + 1);
        } while (reinterpret_cast<int64_t>(rax45) < reinterpret_cast<int64_t>(3));
        goto addr_18000b532_18;
    }
    if (r13d20) {
        ++edi13;
    }
    ecx46 = g18001835c;
    *reinterpret_cast<uint32_t*>(&rax45) = ecx46 - g180018360;
    if (reinterpret_cast<int32_t>(edi13) >= *reinterpret_cast<int32_t*>(&rax45)) {
        if (reinterpret_cast<int32_t>(edi13) > reinterpret_cast<int32_t>(ecx46)) {
            eax47 = g180018364;
            r10d48 = g180018358;
            __asm__("cdq ");
            edx49 = *reinterpret_cast<uint32_t*>(&rdx30) & 31;
            eax50 = eax47 + edx49;
            eax51 = (eax50 & 31) - edx49;
            r11d52 = reinterpret_cast<int32_t>(eax50) >> 5;
            ecx53 = eax51;
            r15d54 = reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx53)));
            if (reinterpret_cast<int32_t>(edi13) < reinterpret_cast<int32_t>(r10d48)) {
                r8d55 = g18001836c;
                __asm__("btr dword [rbp-0x18], 0x1f");
                r10d56 = 0;
                r8d44 = r8d55 + edi13;
                edi57 = eax51;
                r13d58 = 32 - eax51;
                do {
                    ecx59 = edi57;
                    ecx60 = r13d58;
                    *reinterpret_cast<uint32_t*>(&rax45) = v61 >> *reinterpret_cast<signed char*>(&ecx59) | r10d56;
                    r10d56 = (v61 & r15d54) << *reinterpret_cast<unsigned char*>(&ecx60);
                    r14_15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_15) - 1);
                } while (r14_15);
                r10_62 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r11d52));
                *reinterpret_cast<int32_t*>(&rdi63) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r14_15) + 2);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi63) + 4) = 0;
                r9_64 = reinterpret_cast<int64_t>(-r10_62);
                do {
                    if (reinterpret_cast<int64_t>(rdi63) < reinterpret_cast<int64_t>(r10_62)) {
                        *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdi63 * 4 - 24) = 0;
                    } else {
                        rdx65 = reinterpret_cast<void*>(rdi63 << 2);
                        rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx65) + r9_64 * 4);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx65) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) + 0xffffffffffffffe8);
                    }
                    --rdi63;
                } while (reinterpret_cast<int64_t>(rdi63) >= reinterpret_cast<int64_t>(0));
            } else {
                v11 = 0;
                __asm__("bts dword [rbp-0x18], 0x1f");
                r13d66 = 32 - eax51;
                edi67 = eax51;
                r9d68 = 0;
                do {
                    ecx69 = edi67;
                    ecx70 = r13d66;
                    *reinterpret_cast<uint32_t*>(&rax45) = v71 >> *reinterpret_cast<signed char*>(&ecx69) | r9d68;
                    r9d68 = (r15d54 & v71) << *reinterpret_cast<unsigned char*>(&ecx70);
                    r14_15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_15) - 1);
                } while (r14_15);
                r9_72 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r11d52));
                *reinterpret_cast<int32_t*>(&rdi73) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r14_15) + 2);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi73) + 4) = 0;
                r8_74 = reinterpret_cast<int64_t>(-r9_72);
                do {
                    if (reinterpret_cast<int64_t>(rdi73) < reinterpret_cast<int64_t>(r9_72)) {
                        *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdi73 * 4 - 24) = 0;
                    } else {
                        rdx75 = reinterpret_cast<void*>(rdi73 << 2);
                        rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx75) + r8_74 * 4);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx75) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) + 0xffffffffffffffe8);
                    }
                    --rdi73;
                } while (reinterpret_cast<int64_t>(rdi73) >= reinterpret_cast<int64_t>(0));
                r8d76 = g18001836c;
                r8d44 = r8d76 + r10d48;
            }
        } else {
            v11 = v16;
            __asm__("cdq ");
            r11_77 = reinterpret_cast<void*>(3);
            r9d78 = 0;
            edx79 = *reinterpret_cast<uint32_t*>(&rdx30) & 31;
            eax80 = ecx46 - v18 + edx79;
            eax81 = (eax80 & 31) - edx79;
            r13d82 = reinterpret_cast<int32_t>(eax80) >> 5;
            ecx83 = eax81;
            edi84 = eax81;
            r14d85 = 32 - ecx83;
            r10d86 = reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx83)));
            do {
                ecx87 = edi84;
                ecx88 = r14d85;
                *reinterpret_cast<uint32_t*>(&rdx89) = v90 & r10d86;
                v91 = v90 >> *reinterpret_cast<signed char*>(&ecx87) | r9d78;
                r9d78 = *reinterpret_cast<uint32_t*>(&rdx89) << *reinterpret_cast<unsigned char*>(&ecx88);
                r11_77 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r11_77) - 1);
            } while (r11_77);
            r10_92 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r13d82));
            *reinterpret_cast<int32_t*>(&rdi93) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r11_77) + 2);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi93) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r14_94) = static_cast<int32_t>(reinterpret_cast<uint64_t>(r11_77) + 3);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r14_94) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_95) = *reinterpret_cast<int32_t*>(&rdi93);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_95) + 4) = 0;
            r9_96 = reinterpret_cast<int64_t>(-r10_92);
            do {
                if (reinterpret_cast<int64_t>(r8_95) < reinterpret_cast<int64_t>(r10_92)) {
                    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r8_95 * 4 - 24) = 0;
                } else {
                    rdx89 = reinterpret_cast<void*>(r8_95 << 2);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx89) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + (reinterpret_cast<uint64_t>(rdx89) + r9_96 * 4) - 24);
                }
                --r8_95;
            } while (reinterpret_cast<int64_t>(r8_95) >= reinterpret_cast<int64_t>(0));
            *reinterpret_cast<uint32_t*>(&r8_97) = v21;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_97) + 4) = 0;
            __asm__("cdq ");
            edx98 = *reinterpret_cast<uint32_t*>(&rdx89) & 31;
            eax99 = static_cast<int32_t>(r8_97 + 1) + edx98;
            *reinterpret_cast<int32_t*>(&r9_100) = reinterpret_cast<int32_t>(eax99) >> 5;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_100) + 4) = 0;
            r11d101 = 31 - ((eax99 & 31) - edx98);
            if (!static_cast<int1_t>(*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + *reinterpret_cast<int32_t*>(&r9_100) * 4 - 24) >> r11d101)) 
                goto addr_18000b807_47; else 
                goto addr_18000b76f_48;
        }
    } else {
        v11 = 0;
        r8d44 = 0;
    }
    addr_18000b9ea_50:
    rdx = v14;
    addr_18000b9ee_51:
    r12d102 = 31 - g180018364;
    eax103 = g180018368;
    r8d104 = r8d44 << *reinterpret_cast<unsigned char*>(&r12d102) | *reinterpret_cast<uint32_t*>(&rax45) - (*reinterpret_cast<uint32_t*>(&rax45) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax45) < *reinterpret_cast<uint32_t*>(&rax45) + reinterpret_cast<uint1_t>(!!v10))) & 0x80000000 | *reinterpret_cast<uint32_t*>(&v11);
    if (eax103 != 64) {
        if (eax103 == 32) {
            rdx->f0 = r8d104;
        }
    } else {
        rdx->f4 = r8d104;
        rdx->f0 = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(&v11) + 4);
    }
    rcx105 = v8 ^ reinterpret_cast<uint64_t>(rsp6);
    rax106 = fun_180002f40(rcx105, rcx105);
    return *reinterpret_cast<int32_t*>(&rax106);
    addr_18000b807_47:
    ecx107 = r11d101;
    rcx108 = *reinterpret_cast<int32_t*>(&r9_100);
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rcx108 * 4 - 24) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rcx108 * 4 - 24) & 0xffffffff << *reinterpret_cast<unsigned char*>(&ecx107);
    rdx109 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r9_100 + 1)));
    if (reinterpret_cast<int64_t>(rdx109) < reinterpret_cast<int64_t>(r14_94)) {
        r8_110 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_94) - reinterpret_cast<uint64_t>(rdx109));
        rcx111 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) - 24 + reinterpret_cast<uint64_t>(rdx109) * 4);
        *reinterpret_cast<uint32_t*>(&rdx109) = 0;
        fun_180003c80(rcx111, 0, reinterpret_cast<uint64_t>(r8_110) << 2);
        rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
    }
    eax112 = g180018364;
    r9d113 = 0;
    __asm__("cdq ");
    edx114 = *reinterpret_cast<uint32_t*>(&rdx109) & 31;
    eax115 = eax112 + 1 + edx114;
    eax116 = (eax115 & 31) - edx114;
    r10d117 = reinterpret_cast<int32_t>(eax115) >> 5;
    ecx118 = eax116;
    r11d119 = eax116;
    r13d120 = 32 - eax116;
    r15d121 = reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx118)));
    do {
        ecx122 = r11d119;
        ecx123 = r13d120;
        *reinterpret_cast<uint32_t*>(&rax45) = v91 >> *reinterpret_cast<signed char*>(&ecx122) | r9d113;
        r9d113 = (v91 & r15d121) << *reinterpret_cast<unsigned char*>(&ecx123);
        r14_94 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r14_94) - 1);
    } while (r14_94);
    r10_124 = reinterpret_cast<uint64_t>(static_cast<int64_t>(r10d117));
    r8_125 = rdi93;
    r9_126 = reinterpret_cast<int64_t>(-r10_124);
    do {
        if (reinterpret_cast<int64_t>(r8_125) < reinterpret_cast<int64_t>(r10_124)) {
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r8_125 * 4 - 24) = 0;
        } else {
            rdx127 = reinterpret_cast<void*>(r8_125 << 2);
            rax45 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rdx127) + r9_126 * 4);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rdx127) + 0xffffffffffffffe8) = *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rax45) + 0xffffffffffffffe8);
        }
        --r8_125;
    } while (reinterpret_cast<int64_t>(r8_125) >= reinterpret_cast<int64_t>(0));
    r8d44 = 0;
    goto addr_18000b9ea_50;
    addr_18000b76f_48:
    ecx128 = r11d101;
    rdx129 = *reinterpret_cast<int32_t*>(&r9_100);
    if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx129 * 4 - 24) & reinterpret_cast<uint32_t>(~(-1 << *reinterpret_cast<unsigned char*>(&ecx128)))) {
        addr_18000b79b_65:
        __asm__("cdq ");
        edx130 = *reinterpret_cast<uint32_t*>(&rdx129) & 31;
        eax131 = *reinterpret_cast<uint32_t*>(&r8_97) + edx130;
        *reinterpret_cast<int32_t*>(&r10_132) = reinterpret_cast<int32_t>(eax131) >> 5;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r10_132) + 4) = 0;
        ecx133 = 31 - ((eax131 & 31) - edx130);
        r13_134 = *reinterpret_cast<int32_t*>(&r10_132);
        *reinterpret_cast<uint32_t*>(&rax135) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r13_134 * 4 - 24);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax135) + 4) = 0;
        *reinterpret_cast<uint32_t*>(&rdx136) = 1 << *reinterpret_cast<unsigned char*>(&ecx133);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx136) + 4) = 0;
        ecx137 = 0;
        r8d138 = static_cast<uint32_t>(rax135 + rdx136);
        if (r8d138 < *reinterpret_cast<uint32_t*>(&rax135) || r8d138 < *reinterpret_cast<uint32_t*>(&rdx136)) {
            ecx137 = 1;
        }
    } else {
        rcx139 = reinterpret_cast<void*>(static_cast<int64_t>(static_cast<int32_t>(r9_100 + 1)));
        while (reinterpret_cast<int64_t>(rcx139) < reinterpret_cast<int64_t>(r14_94)) {
            if (*reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + reinterpret_cast<uint64_t>(rcx139) * 4 - 24)) 
                goto addr_18000b79b_65;
            rcx139 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rcx139) + 1);
        }
        goto addr_18000b799_71;
    }
    eax140 = static_cast<int32_t>(r10_132 - 1);
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r13_134 * 4 - 24) = r8d138;
    rdx141 = reinterpret_cast<uint64_t>(static_cast<int64_t>(eax140));
    if (eax140 >= 0) {
        do {
            if (!ecx137) 
                goto addr_18000b807_47;
            *reinterpret_cast<uint32_t*>(&rax142) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx141 * 4 - 24);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax142) + 4) = 0;
            ecx137 = 0;
            r8d143 = static_cast<uint32_t>(rax142 + 1);
            if (r8d143 < *reinterpret_cast<uint32_t*>(&rax142) || r8d143 < 1) {
                ecx137 = 1;
            }
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx141 * 4 - 24) = r8d143;
            --rdx141;
        } while (reinterpret_cast<int64_t>(rdx141) >= reinterpret_cast<int64_t>(0));
        goto addr_18000b807_47;
    }
    addr_18000b799_71:
    goto addr_18000b807_47;
    addr_18000b5f5_8:
    eax144 = static_cast<int32_t>(r8_37 - 1);
    *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + r11_39 * 4 - 24) = ecx42;
    rdx145 = reinterpret_cast<uint64_t>(static_cast<int64_t>(eax144));
    if (eax144 >= 0) {
        do {
            if (!r13d20) 
                break;
            *reinterpret_cast<uint32_t*>(&rax146) = *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx145 * 4 - 24);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax146) + 4) = 0;
            r13d20 = 0;
            r8d147 = static_cast<uint32_t>(rax146 + 1);
            if (r8d147 < *reinterpret_cast<uint32_t*>(&rax146) || r8d147 < 1) {
                r13d20 = 1;
            }
            *reinterpret_cast<uint32_t*>(reinterpret_cast<int64_t>(rbp5) + rdx145 * 4 - 24) = r8d147;
            --rdx145;
        } while (reinterpret_cast<int64_t>(rdx145) >= reinterpret_cast<int64_t>(0));
    }
    r8d25 = v28;
    r11_26 = *reinterpret_cast<int32_t*>(&r10_24);
    goto addr_18000b633_3;
    addr_18000b5bf_13:
    goto addr_18000b633_3;
    addr_18000b537_16:
    v11 = 0;
    goto addr_18000b9ee_51;
    addr_18000b532_18:
    goto addr_18000b9ee_51;
}

struct s104 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s0* fun_18000b408(struct s32* rcx, unsigned char* rdx, void** r8) {
    void* rsp4;
    uint64_t rax5;
    void* rsp6;
    int32_t eax7;
    void* rsp8;
    int32_t ebx9;
    uint64_t v10;
    int32_t eax11;
    signed char v12;
    struct s104* v13;
    uint64_t rcx14;
    struct s0* rax15;

    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 0x80);
    rax5 = g1800170a0;
    fun_180003bc4(reinterpret_cast<uint64_t>(rsp4) + 72, r8);
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp4) - 8 + 8);
    eax7 = fun_18000c010(reinterpret_cast<uint64_t>(rsp6) + 0x68, reinterpret_cast<uint64_t>(rsp6) + 64, rdx, 0);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
    ebx9 = eax7;
    if (!1) {
        g0 = v10;
    }
    eax11 = fun_18000ba58(reinterpret_cast<uint64_t>(rsp8) + 0x68, rcx, rdx);
    if (3 & *reinterpret_cast<unsigned char*>(&ebx9)) {
        if (!(*reinterpret_cast<unsigned char*>(&ebx9) & 1)) {
            if (*reinterpret_cast<unsigned char*>(&ebx9) & 2) {
                addr_18000b314_7:
                if (v12) {
                    v13->f200 = v13->f200 & 0xfffffffd;
                }
            } else {
                addr_18000b312_9:
                goto addr_18000b314_7;
            }
            rcx14 = rax5 ^ reinterpret_cast<uint64_t>(rsp4) ^ reinterpret_cast<uint64_t>(rsp8) - 8 + 8;
            rax15 = fun_180002f40(rcx14, rcx14);
            return rax15;
        }
    } else {
        if (eax11 == 1) 
            goto addr_18000b314_7;
        if (eax11 != 2) 
            goto addr_18000b312_9;
    }
    goto addr_18000b314_7;
}

struct s105 {
    void** f0;
    signed char f1;
};

struct s0* fun_180003eac(void** rcx, struct s105* rdx, void** r8, void*** r9);

uint32_t fun_180002e1c(unsigned char* rcx, void* rdx, void* r8, int64_t r9) {
    void** rax5;
    uint32_t eax6;
    void** rax7;

    if (!r8 || (!rcx || !rdx)) {
        rax5 = fun_1800039c8();
        *reinterpret_cast<void***>(rax5) = reinterpret_cast<void**>(22);
    } else {
        eax6 = fun_180002d34(fun_180003eac, rcx, rdx, r8);
        if (reinterpret_cast<int32_t>(eax6) < reinterpret_cast<int32_t>(0)) {
            *rcx = 0;
        }
        if (eax6 != 0xfffffffe) 
            goto addr_180002e84_6; else 
            goto addr_180002e64_7;
    }
    addr_180002e7c_8:
    fun_1800038fc();
    eax6 = 0xffffffff;
    addr_180002e84_6:
    return eax6;
    addr_180002e64_7:
    rax7 = fun_1800039c8();
    *reinterpret_cast<void***>(rax7) = reinterpret_cast<void**>(34);
    goto addr_180002e7c_8;
}

int64_t fun_1800015b0(struct WINBIO_PIPELINE* rcx, int64_t rdx, void** r8, void** r9) {
    int64_t v5;
    int32_t ebx6;
    struct s4* rdx7;
    void** rdi8;
    void** rcx9;
    void** rdi10;
    uint32_t rcx11;
    void** r8_12;
    int64_t v13;
    int64_t rax14;

    fun_1800010e0(2, ">>> SensorAdapterClearContext", r8, r9, v5);
    ebx6 = 0;
    if (rcx) {
        rdx7 = rcx->f48;
        if (rdx7) {
            rdi8 = rdx7->f40;
            rdx7->f72 = 0;
            if (rdi8) {
                rcx9 = rdx7->f48;
                while (*reinterpret_cast<int32_t*>(&rcx9)) {
                    *reinterpret_cast<int32_t*>(&rcx9) = *reinterpret_cast<int32_t*>(&rcx9) - 1;
                    *reinterpret_cast<void***>(rdi8) = reinterpret_cast<void**>(0);
                    ++rdi8;
                }
            }
            rdi10 = rdx7->f56;
            if (rdi10) {
                rcx11 = rdx7->f64;
                while (*reinterpret_cast<int32_t*>(&rcx11)) {
                    *reinterpret_cast<int32_t*>(&rcx11) = *reinterpret_cast<int32_t*>(&rcx11) - 1;
                    *reinterpret_cast<void***>(rdi10) = reinterpret_cast<void**>(0);
                    ++rdi10;
                }
            }
        } else {
            ebx6 = 0x8009800f;
        }
    } else {
        ebx6 = 0x80004003;
    }
    *reinterpret_cast<int32_t*>(&r8_12) = ebx6;
    *reinterpret_cast<int32_t*>(&r8_12 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterClearContext : ErrorCode [0x%08X]", r8_12, r9, v13);
    *reinterpret_cast<int32_t*>(&rax14) = ebx6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax14) + 4) = 0;
    return rax14;
}

struct s106 {
    void** f0;
    signed char[7] pad8;
    int32_t f8;
};

int32_t fun_180008a74() {
    int64_t rsi1;
    struct s106* rbx2;
    int64_t rdi3;
    int64_t rax4;
    void** rcx5;

    *reinterpret_cast<int32_t*>(&rsi1) = 0;
    rbx2 = reinterpret_cast<struct s106*>(0x180018030);
    *reinterpret_cast<int32_t*>(&rdi3) = 36;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
    do {
        if (rbx2->f8 == 1) {
            rax4 = *reinterpret_cast<int32_t*>(&rsi1);
            *reinterpret_cast<int32_t*>(&rsi1) = *reinterpret_cast<int32_t*>(&rsi1) + 1;
            rcx5 = reinterpret_cast<void**>(0x18001d690 + (rax4 + rax4 * 4) * 8);
            rbx2->f0 = rcx5;
            fun_180006234(rcx5, 0xfa0);
        }
        rbx2 = reinterpret_cast<struct s106*>(reinterpret_cast<int64_t>(rbx2) + 16);
        --rdi3;
    } while (rdi3);
    return static_cast<int32_t>(rdi3 + 1);
}

int64_t g1800180b0 = 0;

void fun_180005590() {
    int1_t zf1;
    void** rdx2;
    void** r8_3;
    int64_t rax4;
    void** rdx5;

    zf1 = g1800180b0 == 0;
    if (zf1 && (rax4 = fun_1800089b4(8, rdx2, r8_3), !*reinterpret_cast<int32_t*>(&rax4))) {
        fun_1800053cc(static_cast<int32_t>(rax4 + 17), rdx5);
    }
    goto EnterCriticalSection;
}

int64_t fun_1800097ac() {
    int64_t rsi1;
    uint32_t edi2;
    void** rdx3;
    void** r8_4;
    int32_t ebx5;
    int1_t less6;
    int64_t r15_7;
    void** rax8;
    void** rdx9;
    void** r8_10;
    void** rax11;
    void** rcx12;
    void** r8_13;
    uint32_t eax14;
    void** r8_15;
    uint32_t eax16;
    void** rdx17;
    void** rdx18;
    int64_t rax19;

    *reinterpret_cast<uint32_t*>(&rsi1) = 0;
    edi2 = 0;
    fun_1800088e8(1, rdx3, r8_4);
    ebx5 = 0;
    while (less6 = ebx5 < g18001dfa8, less6) {
        r15_7 = ebx5;
        rax8 = g18001dfa0;
        rdx9 = *reinterpret_cast<void***>(rax8 + r15_7 * 8);
        if (rdx9 && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rdx9 + 24)) & 0x83) {
            fun_180006c04(ebx5, rdx9, r8_10);
            rax11 = g18001dfa0;
            rcx12 = *reinterpret_cast<void***>(rax11 + r15_7 * 8);
            if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx12 + 24)) & 0x83) {
                if (0) {
                    if (!1 && reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx12 + 24)) & 2) {
                        eax14 = fun_1800096e4(rcx12, rdx9, r8_13);
                        if (eax14 == 0xffffffff) {
                            edi2 = 0xffffffff;
                        }
                    }
                } else {
                    eax16 = fun_1800096e4(rcx12, rdx9, r8_15);
                    if (eax16 != 0xffffffff) {
                        *reinterpret_cast<uint32_t*>(&rsi1) = *reinterpret_cast<uint32_t*>(&rsi1) + 1;
                    }
                }
            }
            rdx17 = g18001dfa0;
            rdx18 = *reinterpret_cast<void***>(rdx17 + r15_7 * 8);
            fun_180006c88(ebx5, rdx18);
        }
        ++ebx5;
    }
    fun_180008ad8(1, 1);
    if (1) {
        edi2 = *reinterpret_cast<uint32_t*>(&rsi1);
    }
    *reinterpret_cast<uint32_t*>(&rax19) = edi2;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax19) + 4) = 0;
    return rax19;
}

int64_t fun_18000909c() {
    goto DecodePointer;
}

int64_t g18001df08;

void fun_180009094(int64_t rcx) {
    g18001df08 = rcx;
    return;
}

void fun_18000908c(int64_t rcx) {
    g18001df00 = rcx;
    return;
}

void fun_18000388c(int64_t rcx) {
    g18001cd68 = rcx;
    return;
}

void fun_1800090ac(int64_t rcx) {
    g18001df10 = rcx;
    g18001df18 = rcx;
    g18001df20 = rcx;
    g18001df28 = rcx;
    return;
}

void fun_180009018();

int64_t g18001def8;

void fun_180009038(int64_t rcx) {
    int64_t rax2;

    rax2 = reinterpret_cast<int64_t>(EncodePointer(fun_180009018));
    g18001def8 = rax2;
    return;
}

int64_t g18001df38;

void fun_180009300(int64_t rcx) {
    g18001df38 = rcx;
    return;
}

uint32_t fun_18000ad64(void** rcx, uint16_t* rdx, int64_t r8) {
    uint32_t r9d4;
    uint16_t* r10_5;
    uint64_t r11_6;
    int64_t rcx7;
    int32_t eax8;
    int64_t rdx9;
    int32_t eax10;

    r9d4 = 0;
    r10_5 = rdx;
    if (r8) {
        r11_6 = reinterpret_cast<unsigned char>(rcx) - reinterpret_cast<uint64_t>(rdx);
        do {
            *reinterpret_cast<uint32_t*>(&rcx7) = *reinterpret_cast<uint16_t*>(r11_6 + reinterpret_cast<uint64_t>(r10_5));
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
            eax8 = static_cast<int32_t>(rcx7 - 65);
            if (*reinterpret_cast<uint16_t*>(&eax8) <= 25) {
                *reinterpret_cast<uint16_t*>(&rcx7) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rcx7) + 32);
            }
            *reinterpret_cast<uint32_t*>(&rdx9) = *r10_5;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx9) + 4) = 0;
            eax10 = static_cast<int32_t>(rdx9 - 65);
            if (*reinterpret_cast<uint16_t*>(&eax10) <= 25) {
                *reinterpret_cast<uint16_t*>(&rdx9) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&rdx9) + 32);
            }
            ++r10_5;
            --r8;
        } while (r8 && (*reinterpret_cast<uint16_t*>(&rcx7) && *reinterpret_cast<uint16_t*>(&rcx7) == *reinterpret_cast<uint16_t*>(&rdx9)));
        r9d4 = *reinterpret_cast<uint16_t*>(&rcx7) - *reinterpret_cast<uint16_t*>(&rdx9);
    }
    return r9d4;
}

struct s0* fun_18000c898(uint64_t* rcx, void** rdx, void* r8, int64_t r9) {
    void** v5;
    struct s0* rax6;
    void** v7;
    void** v8;

    if (!(0xffffffdf & static_cast<uint32_t>(r9 - 69))) {
        rax6 = fun_18000cec4(rcx, rdx, r8, v5);
    } else {
        if (*reinterpret_cast<int32_t*>(&r9) != 0x66) {
            if (!(0xffffffdf & static_cast<uint32_t>(r9 - 65))) {
                rax6 = fun_18000c918(rcx, rdx, r8, v7);
            } else {
                rax6 = fun_18000d1f4(rcx, rdx, r8, v7);
            }
        } else {
            rax6 = fun_18000d120(rcx, rdx, r8, v8);
        }
    }
    return rax6;
}

void fun_18000dad0(struct s81* rcx, struct s82* rdx) {
    uint32_t r11d3;
    struct s81* r10_4;
    uint32_t r8d5;
    uint16_t r11w6;
    uint32_t eax7;
    uint16_t r8w8;
    uint32_t ecx9;
    uint32_t ebx10;
    uint32_t edx11;
    int32_t r8d12;
    int64_t r9_13;
    int64_t rdx14;

    r11d3 = *reinterpret_cast<uint16_t*>(reinterpret_cast<int64_t>(rdx) + 6);
    r10_4 = rcx;
    r8d5 = *reinterpret_cast<uint16_t*>(&r11d3);
    r11w6 = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r11d3) & 0x8000);
    eax7 = rdx->f0;
    r8w8 = reinterpret_cast<uint16_t>(reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r8d5) >> 4) & 0x7ff);
    ecx9 = rdx->f4 & 0xfffff;
    ebx10 = 0x80000000;
    edx11 = r8w8;
    if (!edx11) {
        if (ecx9 || eax7) {
            *reinterpret_cast<uint16_t*>(&r8d12) = reinterpret_cast<uint16_t>(r8w8 + 0x3c01);
            ebx10 = 0;
        } else {
            r10_4->f4 = r10_4->f4 & eax7;
            r10_4->f0 = r10_4->f0 & eax7;
            goto addr_18000db92_5;
        }
    } else {
        if (edx11 == 0x7ff) {
            r8d12 = 0x7fff;
        } else {
            *reinterpret_cast<uint16_t*>(&r8d12) = reinterpret_cast<uint16_t>(r8w8 + 0x3c00);
        }
    }
    r10_4->f0 = eax7 << 11;
    *reinterpret_cast<uint32_t*>(&r9_13) = eax7 >> 21 | ecx9 << 11 | ebx10;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_13) + 4) = 0;
    r10_4->f4 = *reinterpret_cast<uint32_t*>(&r9_13);
    if (*reinterpret_cast<int32_t*>(&r9_13) >= reinterpret_cast<int32_t>(0)) {
        do {
            *reinterpret_cast<uint32_t*>(&rdx14) = r10_4->f0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx14) + 4) = 0;
            *reinterpret_cast<uint32_t*>(&r9_13) = *reinterpret_cast<uint32_t*>(&rdx14) >> 31 | static_cast<uint32_t>(r9_13 + r9_13);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9_13) + 4) = 0;
            r10_4->f0 = static_cast<uint32_t>(rdx14 + rdx14);
            *reinterpret_cast<uint16_t*>(&r8d12) = reinterpret_cast<uint16_t>(*reinterpret_cast<uint16_t*>(&r8d12) - 1);
        } while (*reinterpret_cast<int32_t*>(&r9_13) >= reinterpret_cast<int32_t>(0));
        r10_4->f4 = *reinterpret_cast<uint32_t*>(&r9_13);
    }
    r11w6 = reinterpret_cast<uint16_t>(r11w6 | *reinterpret_cast<uint16_t*>(&r8d12));
    addr_18000db92_5:
    r10_4->f8 = r11w6;
    return;
}

struct s107 {
    signed char[8] pad8;
    int64_t f8;
    struct s0* f16;
};

struct s108 {
    unsigned char f0;
    signed char[3] pad4;
    int32_t f4;
    int32_t f8;
};

struct s109 {
    signed char[3] pad3;
    unsigned char f3;
};

struct s0* fun_180002ec4(void* rcx, struct s107* rdx, struct s108* r8) {
    void* r9_4;
    void* r10_5;
    struct s0* rax6;
    int64_t rcx7;
    struct s109* rcx8;
    uint64_t rcx9;
    int1_t zf10;
    int32_t eax11;
    int64_t rax12;
    struct s0* rax13;

    r9_4 = rcx;
    r10_5 = rcx;
    if (r8->f0 & 4) {
        r10_5 = reinterpret_cast<void*>(r8->f4 + reinterpret_cast<uint64_t>(rcx) & reinterpret_cast<uint64_t>(static_cast<int64_t>(-r8->f8)));
    }
    rax6 = rdx->f16;
    *reinterpret_cast<int32_t*>(&rcx7) = rax6->f8;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
    rcx8 = reinterpret_cast<struct s109*>(rcx7 + rdx->f8);
    if (rcx8->f3 & 15) {
        rax6 = reinterpret_cast<struct s0*>(static_cast<int64_t>(reinterpret_cast<int32_t>(static_cast<uint32_t>(rcx8->f3) & 0xfffffff0)));
        r9_4 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(r9_4) + reinterpret_cast<uint64_t>(rax6));
    }
    rcx9 = reinterpret_cast<uint64_t>(r9_4) ^ *reinterpret_cast<uint64_t*>((r8->f0 & 0xfffffff8) + reinterpret_cast<uint64_t>(r10_5));
    zf10 = rcx9 == g1800170a0;
    if (zf10) {
        __asm__("rol rcx, 0x10");
        if (*reinterpret_cast<uint16_t*>(&rcx9) & 0xffff) {
            __asm__("ror rcx, 0x10");
        } else {
            return rax6;
        }
    }
    eax11 = fun_18000e730(23);
    if (eax11) {
        __asm__("int 0x29");
    }
    fun_180006150(0x18001ce10);
    g18001cf08 = reinterpret_cast<int64_t>(__return_address());
    g18001cea8 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 32 + 32 + 8 - 56 - 8 + 8 - 8 + 8 + 56 + 8);
    rax12 = g18001cf08;
    g18001cd80 = rax12;
    g18001ce90 = rcx9;
    g18001cd70 = 0xc0000409;
    g18001cd74 = 1;
    g18001cd88 = 1;
    g18001cd90 = 2;
    rax13 = fun_180004a04(0x180010360);
    return rax13;
}

void fun_180003e3a() {
    signed char* rax1;
    signed char* rax2;
    signed char al3;

    *rax1 = reinterpret_cast<signed char>(*rax2 + al3);
    __asm__("outsd ");
}

void fun_180003e46() {
    signed char* rax1;
    signed char* rax2;
    signed char al3;
    signed char* rax4;
    signed char* rax5;
    signed char al6;

    *rax1 = reinterpret_cast<signed char>(*rax2 + al3);
    *rax4 = reinterpret_cast<signed char>(*rax5 + al6);
}

void fun_180003e52(int64_t rcx, int64_t rdx) {
    signed char* rax3;
    signed char* rax4;
    signed char al5;

    *rax3 = reinterpret_cast<signed char>(*rax4 + al5);
    *reinterpret_cast<int64_t*>(rcx - 15) = rdx;
    *reinterpret_cast<int32_t*>(rcx - 7) = *reinterpret_cast<int32_t*>(&rdx);
    *reinterpret_cast<int16_t*>(rcx - 3) = *reinterpret_cast<int16_t*>(&rdx);
    *reinterpret_cast<signed char*>(rcx - 1) = *reinterpret_cast<signed char*>(&rdx);
    return;
}

struct s110 {
    signed char[1] pad1;
    unsigned char f1;
};

void fun_18000d9e9(int32_t ecx) {
    unsigned char ah2;
    struct s110* rbx3;

    if (ah2 >= rbx3->f1) {
        goto 0x18000d9e6;
    }
}

struct s111 {
    signed char[1] pad1;
    signed char f1;
};

void fun_18000d9f8() {
    signed char ah1;
    struct s111* rbx2;

    if (ah1 == rbx2->f1) 
        goto 0x18000d9b9; else 
        goto "???";
}

struct s112 {
    int64_t f0;
    signed char[40] pad48;
    int64_t f48;
};

int64_t fun_180001850(struct s112* rcx) {
    void** r8_2;
    void** r9_3;
    int64_t v4;
    int64_t v5;
    uint32_t ebx6;
    void** r9_7;
    void* r8_8;
    int64_t rcx9;
    void* rdx10;
    int64_t rax11;
    int64_t rcx12;
    void** r8_13;
    int64_t rdx14;
    int32_t eax15;
    int32_t eax16;
    void** r8_17;
    int64_t v18;
    int64_t v19;
    int32_t eax20;
    int32_t eax21;
    void* rsp22;
    int32_t eax23;
    int32_t eax24;
    uint16_t ax25;
    uint32_t eax26;
    void** r8_27;
    int64_t v28;
    int64_t v29;
    int64_t rax30;
    int64_t v31;
    int64_t v32;

    fun_1800010e0(2, ">>> SensorAdapterReset", r8_2, r9_3, v4);
    v5 = 0;
    if (rcx) {
        if (!rcx->f48 || rcx->f0 == -1) {
            ebx6 = 0x8009800f;
        } else {
            *reinterpret_cast<int32_t*>(&r9_7) = 0;
            *reinterpret_cast<int32_t*>(&r9_7 + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_8) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_8) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rcx9) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx9) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rdx10) = 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx10) + 4) = 0;
            rax11 = reinterpret_cast<int64_t>(CreateEventA());
            v5 = rax11;
            if (rax11) {
                rcx12 = rcx->f0;
                *reinterpret_cast<int32_t*>(&r9_7) = 0;
                *reinterpret_cast<int32_t*>(&r9_7 + 4) = 0;
                *reinterpret_cast<int32_t*>(&r8_13) = 0;
                *reinterpret_cast<int32_t*>(&r8_13 + 4) = 0;
                *reinterpret_cast<int32_t*>(&rdx14) = 0x440008;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx14) + 4) = 0;
                eax15 = reinterpret_cast<int32_t>(DeviceIoControl(rcx12, 0x440008));
                if (eax15) {
                    addr_18000197b_6:
                    if (1) {
                        addr_180001999_7:
                        eax16 = reinterpret_cast<int32_t>(GetLastError(rcx12, rdx14, r8_13));
                        *reinterpret_cast<int32_t*>(&r8_17) = eax16;
                        *reinterpret_cast<int32_t*>(&r8_17 + 4) = 0;
                        fun_1800010e0(2, "SensorAdapterReset : call IOCTL_BIOMETRIC_RESET GetLastError() [%d]", r8_17, r9_7, v18, 2, "SensorAdapterReset : call IOCTL_BIOMETRIC_RESET GetLastError() [%d]", r8_17, r9_7, v19);
                        eax20 = reinterpret_cast<int32_t>(GetLastError(2, "SensorAdapterReset : call IOCTL_BIOMETRIC_RESET GetLastError() [%d]", r8_17));
                        if (eax20 == 0x4c7 || eax20 == 0x3e3) {
                            ebx6 = 0x80098004;
                        } else {
                            ebx6 = 0x80098036;
                        }
                    } else {
                        ebx6 = 0;
                    }
                } else {
                    eax21 = reinterpret_cast<int32_t>(GetLastError(rcx12, 0x440008));
                    if (eax21 != 0x3e5) 
                        goto addr_180001999_7;
                    SetLastError();
                    rsp22 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 96 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8);
                    rcx9 = rcx->f0;
                    r8_8 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp22) + 0x70);
                    rdx10 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp22) + 64);
                    *reinterpret_cast<int32_t*>(&r9_7) = 1;
                    *reinterpret_cast<int32_t*>(&r9_7 + 4) = 0;
                    eax23 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx9, rdx10, r8_8, 1));
                    if (!eax23) 
                        goto addr_1800018c8_13;
                    if (1) 
                        goto addr_1800018c8_13; else 
                        goto addr_180001962_15;
                }
            } else {
                addr_1800018c8_13:
                eax24 = reinterpret_cast<int32_t>(GetLastError(rcx9, rdx10, r8_8, r9_7));
                if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax24 < 0) | reinterpret_cast<uint1_t>(eax24 == 0))) {
                    ax25 = reinterpret_cast<uint16_t>(GetLastError(rcx9, rdx10, r8_8, r9_7));
                    ebx6 = static_cast<uint32_t>(ax25) | 0x80070000;
                } else {
                    eax26 = reinterpret_cast<uint32_t>(GetLastError(rcx9, rdx10, r8_8, r9_7));
                    ebx6 = eax26;
                }
            }
        }
    } else {
        ebx6 = 0x80004003;
    }
    if (v5) {
        CloseHandle();
    }
    *reinterpret_cast<uint32_t*>(&r8_27) = ebx6;
    *reinterpret_cast<int32_t*>(&r8_27 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterReset : ErrorCode [0x%08X]", r8_27, r9_7, v28, 2, "<<< SensorAdapterReset : ErrorCode [0x%08X]", r8_27, r9_7, v29);
    *reinterpret_cast<uint32_t*>(&rax30) = ebx6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax30) + 4) = 0;
    return rax30;
    addr_180001962_15:
    *reinterpret_cast<int32_t*>(&r9_7) = 8;
    *reinterpret_cast<int32_t*>(&r9_7 + 4) = 0;
    rdx14 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : IOCTL_BIOMETRIC_RESET GetOverlappedResult result = [%d], bytesReturned = [%d]");
    *reinterpret_cast<int32_t*>(&r8_13) = eax23;
    *reinterpret_cast<int32_t*>(&r8_13 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&rcx12) = 2;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx12) + 4) = 0;
    fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_RESET GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_13, 8, v31, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_RESET GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_13, 8, v32);
    goto addr_18000197b_6;
}

struct s113 {
    int64_t f0;
    signed char[40] pad48;
    int64_t f48;
};

int64_t fun_180001a10(struct s113* rcx) {
    void** r8_2;
    void** r9_3;
    int64_t v4;
    int64_t rbx5;
    void** r8_6;
    void** r9_7;
    int64_t v8;
    int64_t rax9;

    fun_1800010e0(2, ">>> SensorAdapterSetMode", r8_2, r9_3, v4);
    *reinterpret_cast<int32_t*>(&rbx5) = 0;
    if (rcx) {
        if (!rcx->f48 || rcx->f0 == -1) {
            *reinterpret_cast<int32_t*>(&rbx5) = 0x8009800f;
        }
    } else {
        *reinterpret_cast<int32_t*>(&rbx5) = 0x80004003;
    }
    *reinterpret_cast<int32_t*>(&r8_6) = *reinterpret_cast<int32_t*>(&rbx5);
    *reinterpret_cast<int32_t*>(&r8_6 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterSetMode : ErrorCode [0x%08X]", r8_6, r9_7, v8);
    *reinterpret_cast<int32_t*>(&rax9) = *reinterpret_cast<int32_t*>(&rbx5);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax9) + 4) = 0;
    return rax9;
}

struct s114 {
    int64_t f0;
    signed char[40] pad48;
    int64_t f48;
};

struct s0* fun_180001c50(struct s114* rcx, int32_t* rdx, void** r8, void** r9) {
    void* rsp5;
    uint64_t rax6;
    int64_t v7;
    void* rsp8;
    int64_t v9;
    uint32_t ebx10;
    void* rdx11;
    void* r8_12;
    int64_t rcx13;
    int64_t rax14;
    void* rsp15;
    int64_t rcx16;
    void** r8_17;
    int64_t rdx18;
    int32_t eax19;
    int32_t eax20;
    int32_t eax21;
    void* rsp22;
    int32_t eax23;
    int32_t eax24;
    void* rsp25;
    uint16_t ax26;
    uint32_t eax27;
    void** r8_28;
    int64_t v29;
    int64_t v30;
    uint64_t rcx31;
    struct s0* rax32;
    int64_t v33;
    int64_t v34;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x80);
    rax6 = g1800170a0;
    fun_1800010e0(2, ">>> SensorAdapterGetIndicatorStatus", r8, r9, v7);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp5) - 8 + 8);
    v9 = 0;
    if (!rcx || !rdx) {
        ebx10 = 0x80004003;
    } else {
        if (!rcx->f48 || rcx->f0 == -1) {
            ebx10 = 0x8009800f;
        } else {
            *reinterpret_cast<int32_t*>(&rdx11) = 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx11) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r9) = 0;
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_12) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_12) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rcx13) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx13) + 4) = 0;
            *rdx = 2;
            rax14 = reinterpret_cast<int64_t>(CreateEventA());
            rsp15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
            v9 = rax14;
            if (rax14) {
                rcx16 = rcx->f0;
                *reinterpret_cast<int32_t*>(&r9) = 0;
                *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                *reinterpret_cast<int32_t*>(&r8_17) = 0;
                *reinterpret_cast<int32_t*>(&r8_17 + 4) = 0;
                *reinterpret_cast<int32_t*>(&rdx18) = 0x440020;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx18) + 4) = 0;
                eax19 = reinterpret_cast<int32_t>(DeviceIoControl(rcx16, 0x440020));
                rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
                if (eax19) {
                    addr_180001da4_7:
                    if (1) {
                        addr_180001dcc_8:
                        eax20 = reinterpret_cast<int32_t>(GetLastError(rcx16, rdx18, r8_17));
                        rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
                        if (eax20 == 0x4c7 || eax20 == 0x3e3) {
                            ebx10 = 0x80098004;
                        } else {
                            ebx10 = 0x80098036;
                        }
                    } else {
                        ebx10 = 0;
                        if (!0) {
                            *rdx = 0;
                        }
                    }
                } else {
                    eax21 = reinterpret_cast<int32_t>(GetLastError(rcx16, 0x440020));
                    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
                    if (eax21 != 0x3e5) 
                        goto addr_180001dcc_8;
                    SetLastError();
                    rsp22 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
                    rcx13 = rcx->f0;
                    r8_12 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp22) + 64);
                    rdx11 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp22) + 72);
                    *reinterpret_cast<int32_t*>(&r9) = 1;
                    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                    eax23 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx13, rdx11, r8_12, 1));
                    rsp15 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp22) - 8 + 8);
                    if (!eax23) 
                        goto addr_180001cf1_15;
                    if (1) 
                        goto addr_180001cf1_15; else 
                        goto addr_180001d8b_17;
                }
            } else {
                addr_180001cf1_15:
                eax24 = reinterpret_cast<int32_t>(GetLastError(rcx13, rdx11, r8_12, r9));
                rsp25 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
                if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax24 < 0) | reinterpret_cast<uint1_t>(eax24 == 0))) {
                    ax26 = reinterpret_cast<uint16_t>(GetLastError(rcx13, rdx11, r8_12, r9));
                    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) - 8 + 8);
                    ebx10 = static_cast<uint32_t>(ax26) | 0x80070000;
                } else {
                    eax27 = reinterpret_cast<uint32_t>(GetLastError(rcx13, rdx11, r8_12, r9));
                    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp25) - 8 + 8);
                    ebx10 = eax27;
                }
            }
        }
    }
    if (v9) {
        CloseHandle();
        rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp8) - 8 + 8);
    }
    *reinterpret_cast<uint32_t*>(&r8_28) = ebx10;
    *reinterpret_cast<int32_t*>(&r8_28 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterGetIndicatorStatus : ErrorCode [0x%08X]", r8_28, r9, v29, 2, "<<< SensorAdapterGetIndicatorStatus : ErrorCode [0x%08X]", r8_28, r9, v30);
    rcx31 = rax6 ^ reinterpret_cast<uint64_t>(rsp5) ^ reinterpret_cast<uint64_t>(rsp8) - 8 + 8;
    rax32 = fun_180002f40(rcx31, rcx31);
    return rax32;
    addr_180001d8b_17:
    *reinterpret_cast<int32_t*>(&r9) = 12;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    rdx18 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_INDICATOR GetOverlappedResult result = [%d], bytesReturned = [%d]");
    *reinterpret_cast<int32_t*>(&r8_17) = eax23;
    *reinterpret_cast<int32_t*>(&r8_17 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&rcx16) = 2;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx16) + 4) = 0;
    fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_INDICATOR GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_17, 12, v33, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_INDICATOR GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_17, 12, v34);
    rsp8 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp15) - 8 + 8);
    goto addr_180001da4_7;
}

int64_t ResetEvent = 0x163fc;

struct s0* fun_180001e40(struct WINBIO_PIPELINE* rcx, unsigned char /* WINBIO_BIR_PURPOSE - bitmask */ dl, void** r8, void** r9) {
    void* rbp5;
    void* rsp6;
    uint64_t rax7;
    uint64_t v8;
    uint32_t r15d9;
    struct WINBIO_PIPELINE* rsi10;
    void** r12_11;
    int64_t v12;
    void* rsp13;
    int64_t v14;
    uint32_t ebx15;
    struct s4* rdi16;
    uint32_t eax17;
    int64_t rdx18;
    int64_t rcx19;
    void** r8_20;
    int64_t v21;
    int64_t v22;
    int64_t rdx23;
    int64_t v24;
    int64_t v25;
    struct s3* rax26;
    uint32_t eax27;
    void* r8_28;
    void** rdx29;
    int64_t rcx30;
    int64_t rax31;
    void* rsp32;
    int64_t v33;
    int64_t v34;
    int64_t rax35;
    void** rax36;
    void** rbx37;
    int64_t rcx38;
    int64_t rax39;
    int64_t rcx40;
    int32_t eax41;
    void* rsp42;
    int32_t eax43;
    void** rbx44;
    void** rax45;
    int64_t rax46;
    int32_t eax47;
    void* rsp48;
    int32_t eax49;
    void* rsp50;
    uint16_t ax51;
    uint32_t eax52;
    int64_t v53;
    int64_t v54;
    void** rcx55;
    void** rax56;
    void** rbx57;
    int64_t rcx58;
    int64_t rcx59;
    void* r8_60;
    uint32_t eax61;
    void* rsp62;
    int32_t eax63;
    int32_t eax64;
    void** r8_65;
    int64_t v66;
    int64_t v67;
    int32_t eax68;
    void** r8_69;
    int64_t v70;
    int64_t v71;
    uint64_t rcx72;
    struct s0* rax73;
    int64_t rcx74;
    int32_t eax75;
    int32_t eax76;
    int32_t eax77;
    void** r8_78;
    int64_t v79;
    int64_t v80;
    uint32_t r10d81;
    uint32_t eax82;
    int32_t eax83;
    uint32_t eax84;
    int64_t v85;
    int64_t v86;
    int64_t rax87;
    int64_t rcx88;
    void** r8_89;
    int32_t eax90;
    void* rsp91;
    int32_t eax92;
    uint32_t eax93;
    int64_t v94;
    int64_t v95;
    int32_t eax96;
    int64_t v97;
    int64_t v98;

    rbp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 95);
    rsp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 0xc8);
    rax7 = g1800170a0;
    v8 = rax7 ^ reinterpret_cast<uint64_t>(rsp6);
    r15d9 = dl;
    rsi10 = rcx;
    r12_11 = r8; // 3rd param, overlapped?
    fun_1800010e0(2, ">>> SensorAdapterStartCapture", r8, r9, v12);
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp6) - 8 + 8);
    v14 = 0;
    if (!rsi10 || (!*reinterpret_cast<signed char*>(&r15d9) /* not 0 */ || !r12_11)) {
        ebx15 = 0x80004003;
        goto addr_180002449_3;
    }
    rdi16 = rsi10->f48;  // SensorContext
    if (!rdi16 || rsi10->f0 == -1) {
        addr_18000206a_5:
        ebx15 = 0x8009800f;
        goto addr_180002449_3;
    } else {
        *reinterpret_cast<void***>(r12_11) = reinterpret_cast<void**>(0);
        // Call SensorAdapterQueryStatus
        some_var = reinterpret_cast<int64_t>(rbp5) - 53;
        eax17 = fun_180001640(rsi10, &some_var, r8, r9);
        ebx15 = eax17;
        // winerror.h -> if(FAILED(eax17))
        if (reinterpret_cast<int32_t>(eax17) < reinterpret_cast<int32_t>(0)) 
            // calls CloseHandle and logs error
            goto addr_180002449_3;
        rdx18 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : called SensorAdapterQueryStatus(1) = %d");
        *reinterpret_cast<uint32_t*>(&rcx19) = 2;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx19) + 4) = 0;
        *reinterpret_cast<int32_t*>(&r8_20) = 6;
        *reinterpret_cast<int32_t*>(&r8_20 + 4) = 0;

        // This does something (a large function), don't know what :thinking:
        fun_1800010e0(2, rdx18, 6, r9, v21, 2, "SensorAdapterStartCapture : called SensorAdapterQueryStatus(1) = %d", 6, r9, v22);
        if (some_var == 5)
            goto addr_180001f2e_8;
    }
    addr_180002040_9:
    else if (some_var == 4) {
        ebx15 = 0x80098010;
        // calls CloseHandle and logs error
        goto addr_180002449_3;
    }
    else if (some_var != 3) {
        fun_1800010e0(2, "SensorAdapterStartCapture : sensorStatus != WINBIO_SENSOR_READY, sensorStatus = %d. ", 6, r9, v33, 2, "SensorAdapterStartCapture : sensorStatus != WINBIO_SENSOR_READY, sensorStatus = %d. ", 6, r9, v34);
        rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
        goto addr_18000206a_5;
    }
    else if (condition hard to read /* Probably not the area we're looking for? */) {
        if (rdi16->f76 || rdi16->f78) {
            addr_1800021ef_13:
            __asm__("movups xmm0, [rdi+0x50]");
            __asm__("movups [rbp-0x5], xmm0");
            if (rdi16->f40) {
                rdx23 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : Call SensorAdapterClearContext");
                fun_1800010e0(2, "SensorAdapterStartCapture : Call SensorAdapterClearContext", r8_20, r9, v24, 2, "SensorAdapterStartCapture : Call SensorAdapterClearContext", r8_20, r9, v25);
                fun_1800015b0(rsi10, "SensorAdapterStartCapture : Call SensorAdapterClearContext", r8_20, r9);
                rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8 - 8 + 8);
                goto addr_180002386_15;
            }
        } else {
            rax26 = rsi10->f32;  // EngineInterface
            eax27 = reinterpret_cast<uint32_t>(rax26->f56(rsi10, &rdi16->f76, rdi16 + 1));
            rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
            ebx15 = eax27;
            if (reinterpret_cast<int32_t>(eax27) < reinterpret_cast<int32_t>(0)) {
                addr_180002449_3:
                if (v14) {
                    CloseHandle();
                    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
                    goto addr_180002488_18;
                }
            } else {
                rdi16->f64 = reinterpret_cast<uint32_t>(0x62c);
                rdi16->f56 = reinterpret_cast<void**>(0x180018670);
                if (v14) {
                    CloseHandle();
                    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8);
                }
                *reinterpret_cast<uint32_t*>(&r9) = 0;
                *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                *reinterpret_cast<int32_t*>(&r8_28) = 0;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_28) + 4) = 0;
                *reinterpret_cast<int32_t*>(&rdx29) = 1;
                *reinterpret_cast<int32_t*>(&rdx29 + 4) = 0;
                *reinterpret_cast<int32_t*>(&rcx30) = 0;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx30) + 4) = 0;
                rax31 = reinterpret_cast<int64_t>(CreateEventA());
                rsp32 = rsp13;
                v14 = rax31;
                if (rax31) 
                    goto addr_18000210f_22; else 
                    goto addr_1800020f4_23;
            }
        }
    }
    // Probably interested here - start
    // https://docs.microsoft.com/en-us/windows/win32/api/winbio_adapter/nc-winbio_adapter-pibio_sensor_start_capture_fn
    rax35 = reinterpret_cast<int64_t>(GetProcessHeap(rcx19, rdx18, r8_20));
    rax36 = reinterpret_cast<void**>(HeapAlloc(rax35));
    rdi16->f40 = rax36;
    if (rax36) {
        rdi16->f48 = reinterpret_cast<void**>(24);
        rbx37 = reinterpret_cast<void**>(&rdi16->f8);
        *reinterpret_cast<void***>(rbx37) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx37 + 8) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx37 + 16) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx37 + 24) = reinterpret_cast<void**>(0);
        rcx38 = rdi16->f0;
        ResetEvent(rcx38 /* Event Handle */);
        rax39 = rdi16->f0;
        rdi16->f32 = rax39;
        rcx40 = rsi10->f0;
        r8_20 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0xffffffffffffffef /* -17 */);
        *reinterpret_cast<uint32_t*>(&r9) = 32;
        *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
        *reinterpret_cast<int32_t*>(&rdx23) = 0x440014;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx23) + 4) = 0;  
        eax41 = reinterpret_cast<int32_t>(DeviceIoControl(rcx40, 0x440014, r8_20, 32 /* interesting */));
        rsp42 = rsp13;
        if (eax41 || (eax43 = reinterpret_cast<int32_t>(GetLastError(rcx40, 0x440014, r8_20, 32)), rsp42 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp42) - 8 + 8), eax43 != 0x3e5)) {
            addr_18000230c_27:
            rbx44 = rdi16->f40;
            rax45 = *reinterpret_cast<void***>(rbx44);
            *reinterpret_cast<int32_t*>(&rax45 + 4) = 0;
            if (reinterpret_cast<unsigned char>(rdi16->f48) < reinterpret_cast<unsigned char>(rax45) && (rdi16->f48 = rax45, !!rbx44)) {
                rax46 = reinterpret_cast<int64_t>(GetProcessHeap(rcx40, rdx23, r8_20, r9));
                r8_20 = rbx44;
                *reinterpret_cast<int32_t*>(&rdx23) = 0;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx23) + 4) = 0;
                HeapFree(rax46);
                rsp42 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp42) - 8 + 8 - 8 + 8);
                rdi16->f40 = reinterpret_cast<void**>(0);
            }
        } else {
            SetLastError();
            rcx30 = rsi10->f0;
            r8_28 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) - 57);
            *reinterpret_cast<uint32_t*>(&r9) = 1;
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            rdx29 = rbx37;
            eax47 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx30, rdx29, r8_28, 1));  // Size of 1? Hmm
            rsp48 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp42) - 8 + 8 - 8 + 8);
            if (!eax47 || 1) {
                addr_180001f65_30:
                eax49 = reinterpret_cast<int32_t>(GetLastError(rcx30, rdx29, r8_28, r9));
                rsp50 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp48) - 8 + 8);
                if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax49 < 0) | reinterpret_cast<uint1_t>(eax49 == 0))) {
                    addr_180002359_31:
                    ax51 = reinterpret_cast<uint16_t>(GetLastError(rcx30, rdx29, r8_28, r9));
                    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp50) - 8 + 8);
                    ebx15 = static_cast<uint32_t>(ax51) | 0x80070000;
                    goto addr_180002449_3;
                } else {
                    eax52 = reinterpret_cast<uint32_t>(GetLastError(rcx30, rdx29, r8_28, r9));
                    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp50) - 8 + 8);
                    ebx15 = eax52;
                    goto addr_180002449_3;
                }
            } else {
                *reinterpret_cast<uint32_t*>(&r9) = 4;
                *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                // Most importantly here!!!
                rdx23 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : IOCTL_BIOMETRIC_CAPTURE_DATA GetOverlappedResult result = [%d], bytesReturned = [%d]");
                *reinterpret_cast<int32_t*>(&r8_20) = eax47;
                *reinterpret_cast<int32_t*>(&r8_20 + 4) = 0;
                *reinterpret_cast<uint32_t*>(&rcx40) = 2;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx40) + 4) = 0;
                fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_CAPTURE_DATA GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_20, 4, v53, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_CAPTURE_DATA GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_20, 4, v54);
                rsp42 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp48) - 8 + 8);
                goto addr_18000230c_27;
            }
        }
    } else {
        rdi16->f48 = reinterpret_cast<void**>(0);
        ebx15 = 0x8007000e;
        goto addr_180002449_3;
    }
    rcx55 = rdi16->f48;
    rax56 = fun_180002bb0(rcx55, rdx23, r8_20, r9);
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp42) - 8 + 8);
    rdi16->f40 = rax56;
    if (rax56) {
        addr_180002386_15:
        rbx57 = reinterpret_cast<void**>(&rdi16->f8);
        *reinterpret_cast<void***>(rbx57) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx57 + 8) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx57 + 16) = reinterpret_cast<void**>(0);
        *reinterpret_cast<void***>(rbx57 + 24) = reinterpret_cast<void**>(0);
        rcx58 = rdi16->f0;
        ResetEvent(rcx58, rdx23, r8_20, r9);
        rdi16->f32 = rdi16->f0;
        SetLastError();
        rcx59 = rsi10->f0;
        r8_60 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) - 17);
        *reinterpret_cast<uint32_t*>(&r9) = 32;
        *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
        eax61 = reinterpret_cast<uint32_t>(DeviceIoControl(rcx59, 0x440014, r8_60, 32));
        rsp62 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8 - 8 + 8 - 8 + 8);
        if (eax61 || (eax63 = reinterpret_cast<int32_t>(GetLastError(rcx59, 0x440014, r8_60, 32)), rsp62 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp62) - 8 + 8), eax63 == 0x3e5)) {
            eax64 = reinterpret_cast<int32_t>(GetLastError(rcx59, 0x440014, r8_60, 32));
            *reinterpret_cast<uint32_t*>(&r9) = eax61;
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_65) = eax64;
            *reinterpret_cast<int32_t*>(&r8_65 + 4) = 0;
            fun_1800010e0(2, "SensorAdapterStartCapture : Call DeviceIoControl, GetLastError() = [%d], result = [%d]", r8_65, r9, v66, 2, "SensorAdapterStartCapture : Call DeviceIoControl, GetLastError() = [%d], result = [%d]", r8_65, r9, v67);
            rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp62) - 8 + 8 - 8 + 8);
            *reinterpret_cast<void***>(r12_11) = rbx57;
            ebx15 = 0;
            goto addr_180002449_3;
        } else {
            eax68 = reinterpret_cast<int32_t>(GetLastError(rcx59, 0x440014, r8_60, 32));
            rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp62) - 8 + 8);
            if (eax68 == 0x4c7 || eax68 == 0x3e3) {
                ebx15 = 0x80098004;
                goto addr_180002449_3;
            } else {
                ebx15 = 0x80098036;
                goto addr_180002449_3;
            }
        }
    } else {
        rdi16->f48 = reinterpret_cast<void**>(0);
        ebx15 = 0x8007000e;
        goto addr_180002449_3;
    }
    addr_180002488_18:
    *reinterpret_cast<uint32_t*>(&r8_69) = ebx15;
    *reinterpret_cast<int32_t*>(&r8_69 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterStartCapture : ErrorCode [0x%08X]", r8_69, r9, v70, 2, "<<< SensorAdapterStartCapture : ErrorCode [0x%08X]", r8_69, r9, v71);
    rcx72 = v8 ^ reinterpret_cast<uint64_t>(rsp13) - 8 + 8;
    rax73 = fun_180002f40(rcx72, rcx72);
    return rax73;
    addr_18000210f_22:
    rcx74 = rsi10->f0;
    *reinterpret_cast<uint32_t*>(&rdx18) = 0x440004;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx18) + 4) = 0;
    eax75 = reinterpret_cast<int32_t>(DeviceIoControl(rcx74, 0x440004));
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp32) - 8 + 8);
    if (!eax75 && (eax76 = reinterpret_cast<int32_t>(GetLastError(rcx74, 0x440004)), rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8), eax76 == 0x3e5)) {
        SetLastError();
        rcx30 = rsi10->f0;
        r8_28 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) - 57);
        rdx29 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0xffffffffffffffcf);
        *reinterpret_cast<uint32_t*>(&r9) = 1;
        *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
        eax77 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx30, rdx29, r8_28, 1));
        rsp48 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp13) - 8 + 8 - 8 + 8);
        if (!eax77) 
            goto addr_180001f65_30;
        *reinterpret_cast<uint32_t*>(&r9) = 0;
        *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
        if (rdi16->f64) 
            goto addr_180001f65_30;
        // Maybe interested here?
        rdx18 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_ATTRIBUTES GetOverlappedResult result = [%d], bytesReturned = [%d]");
        *reinterpret_cast<int32_t*>(&r8_78) = eax77;
        *reinterpret_cast<int32_t*>(&r8_78 + 4) = 0;
        fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_ATTRIBUTES GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_78, 0, v79, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_ATTRIBUTES GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_78, 0, v80);
        rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp48) - 8 + 8);
    }
    r8_20 = rdi16->f56;
    *reinterpret_cast<uint32_t*>(&rcx19) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx19) + 4) = 0;
    *reinterpret_cast<uint32_t*>(&r9) = *reinterpret_cast<uint32_t*>(r8_20 + 0x624);
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    if (*reinterpret_cast<uint32_t*>(&r9)) {
        r10d81 = rdi16->f76;
        do {
            *reinterpret_cast<uint32_t*>(&rdx18) = *reinterpret_cast<uint32_t*>(&rcx19);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx18) + 4) = 0;
            if (*reinterpret_cast<int16_t*>(reinterpret_cast<unsigned char>(r8_20) + reinterpret_cast<uint64_t>(rdx18 * 4) + 0x628) != *reinterpret_cast<int16_t*>(&r10d81)) 
                continue;
            eax82 = rdi16->f78;
            if (*reinterpret_cast<int16_t*>(reinterpret_cast<unsigned char>(r8_20) + reinterpret_cast<uint64_t>(rdx18 * 4) + 0x62a) == *reinterpret_cast<int16_t*>(&eax82)) 
                break;
            *reinterpret_cast<uint32_t*>(&rcx19) = *reinterpret_cast<uint32_t*>(&rcx19) + 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx19) + 4) = 0;
        } while (*reinterpret_cast<uint32_t*>(&rcx19) < *reinterpret_cast<uint32_t*>(&r9));
    }
    if (*reinterpret_cast<uint32_t*>(&rcx19) == *reinterpret_cast<uint32_t*>(&r9)) {
        rdi16->f76 = reinterpret_cast<uint16_t>(0x401001b);
        goto addr_1800021ef_13;
    }
    // Probably interested here - end
    // We maybe interested in here?
    addr_1800020f4_23:
    eax83 = reinterpret_cast<int32_t>(GetLastError());
    rsp50 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp32) - 8 + 8);
    if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax83 < 0) | reinterpret_cast<uint1_t>(eax83 == 0))) 
        goto addr_180002359_31;
    eax84 = reinterpret_cast<uint32_t>(GetLastError());
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp50) - 8 + 8);
    ebx15 = eax84;
    goto addr_180002449_3;
    addr_180001f2e_8:
    // Again this function is called, but with different argument, is it kind of debug logging function?
    // Or is it sth that calls something based on passed string?
    fun_1800010e0(2, "SensorAdapterStartCapture : call IOCTL_BIOMETRIC_CALIBRATE = %d", 6, r9, v85, 2, "SensorAdapterStartCapture : call IOCTL_BIOMETRIC_CALIBRATE = %d", 6, r9, v86);
    *reinterpret_cast<int32_t*>(&rdx29) = 1;
    *reinterpret_cast<int32_t*>(&rdx29 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&r9) = 0;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    *reinterpret_cast<int32_t*>(&r8_28) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_28) + 4) = 0;
    *reinterpret_cast<int32_t*>(&rcx30) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx30) + 4) = 0;
    rax87 = reinterpret_cast<int64_t>(CreateEventA());
    rsp48 = sp13;
    v14 = rax87;
    if (!rax87) 
        // Logs error
        goto addr_180001f65_30;
    rcx88 = rsi10->f0;  // SensorHandle
    *reinterpret_cast<uint32_t*>(&r9) = 0;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    *reinterpret_cast<int32_t*>(&r8_89) = 0;
    *reinterpret_cast<int32_t*>(&r8_89 + 4) = 0;
    eax90 = reinterpret_cast<int32_t>(DeviceIoControl(rcx88, 0x44000c));
    rsp91 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp48) - 8 + 8);
    if (eax90) 
        goto addr_180002012_53;
    eax92 = reinterpret_cast<int32_t>(GetLastError(rcx88, 0x44000c /* control code - just a id */));
    if (eax92 == 0x3e5) 
        goto addr_180001fc8_55;
    addr_180002012_53:
    eax93 = fun_180001640(rsi10, reinterpret_cast<int64_t>(rbp5) - 53, r8_89, r9);
    rdx18 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : called SensorAdapterQueryStatus(2) = %d");
    *reinterpret_cast<int32_t*>(&r8_20) = 6;
    *reinterpret_cast<int32_t*>(&r8_20 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&rcx19) = 2;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx19) + 4) = 0;
    ebx15 = eax93;
    // Again lol, must be logging or somthing...
    fun_1800010e0(2, "SensorAdapterStartCapture : called SensorAdapterQueryStatus(2) = %d", 6, r9, v94, 2, "SensorAdapterStartCapture : called SensorAdapterQueryStatus(2) = %d", 6, r9, v95);
    rsp13 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp91) - 8 + 8 - 8 + 8);
    if (reinterpret_cast<int32_t>(ebx15) < reinterpret_cast<int32_t>(0)) 
        goto addr_180002449_3; else 
        goto addr_180002040_9;
    addr_180001fc8_55:
    SetLastError();
    rcx30 = rsi10->f0;
    r8_28 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp5) - 57);
    rdx29 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp5) + 0xffffffffffffffcf);
    *reinterpret_cast<uint32_t*>(&r9) = 1;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    eax96 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx30, rdx29, r8_28, 1));
    rsp48 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp91) - 8 + 8 - 8 + 8);
    if (!eax96) 
        goto addr_180001f65_30;
    if (1) 
        goto addr_180001f65_30;
    *reinterpret_cast<uint32_t*>(&r9) = 16;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    *reinterpret_cast<int32_t*>(&r8_89) = eax96;
    *reinterpret_cast<int32_t*>(&r8_89 + 4) = 0;
    fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_CALIBRATE GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_89, 16, v97, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_CALIBRATE GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_89, 16, v98);
    rsp91 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp48) - 8 + 8);
    goto addr_180002012_53;
}

struct s117 {
    signed char[4] pad4;
    int32_t f4;
    int32_t f8;
    int32_t f12;
};

struct s116 {
    signed char[40] pad40;
    struct s117* f40;
    void** f48;
};

struct s115 {
    int64_t f0;
    signed char[40] pad48;
    struct s116* f48;
};

int64_t fun_1800024c0(struct s115* rcx, int32_t* rdx, void** r8, void** r9) {
    int64_t v5;
    int32_t ebx6;
    struct s116* rdi7;
    int64_t v8;
    int32_t eax9;
    void** r8_10;
    int64_t v11;
    int64_t rcx12;
    int64_t rdx13;
    void* r8_14;
    int32_t eax15;
    int32_t eax16;
    int64_t v17;
    int64_t v18;
    void** r8_19;
    int64_t rax20;
    int64_t v21;
    int64_t v22;
    int64_t rcx23;
    void** r8_24;
    int64_t v25;
    int64_t v26;
    int64_t rax27;

    fun_1800010e0(2, ">>> SensorAdapterFinishCapture", r8, r9, v5);
    if (!rcx || !rdx) {
        ebx6 = 0x80004003;
    } else {
        rdi7 = rcx->f48;
        if (!rdi7 || rcx->f0 == -1) {
            ebx6 = 0x8009800f;
            fun_1800010e0(2, " SensorAdapterFinishCapture Verify the state of the pipeline", r8, r9, v8);
        } else {
            *rdx = 0;
            eax9 = reinterpret_cast<int32_t>(GetLastError(2, ">>> SensorAdapterFinishCapture"));
            *reinterpret_cast<int32_t*>(&r8_10) = eax9;
            *reinterpret_cast<int32_t*>(&r8_10 + 4) = 0;
            fun_1800010e0(2, " SensorAdapterFinishCapture call  GetLastError() = [%d]", r8_10, r9, v11);
            SetLastError();
            rcx12 = rcx->f0;
            rdx13 = reinterpret_cast<int64_t>(rdi7) + 8;
            r8_14 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 48 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 + 64);
            *reinterpret_cast<int32_t*>(&r9) = 1;
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            eax15 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx12, rdx13, r8_14, 1));
            if (!eax15 || static_cast<int1_t>(!!rdi7->f48)) {
                eax16 = reinterpret_cast<int32_t>(GetLastError(rcx12, rdx13, r8_14, 1));
                if (1) {
                    if (eax16 == 0x4c7 || eax16 == 0x3e3) {
                        ebx6 = 0x80098004;
                    } else {
                        ebx6 = 0x80098036;
                    }
                } else {
                    ebx6 = 0x80098008;
                    *rdx = 7;
                }
            } else {
                GetLastError(rcx12, rdx13, r8_14, 1);
                r9 = rdi7->f48;
                fun_1800010e0(2, " SensorAdapterFinishCapture call GetOverlappedResult success : bytesReturned = [0x%08X], sensorContext->CaptureBufferSize = [0x%08X], GetLastError()=[%d]", 0, r9, v17, 2, " SensorAdapterFinishCapture call GetOverlappedResult success : bytesReturned = [0x%08X], sensorContext->CaptureBufferSize = [0x%08X], GetLastError()=[%d]", 0, r9, v18);
                if (!rdi7->f40 || (reinterpret_cast<unsigned char>(rdi7->f48) < reinterpret_cast<unsigned char>(24) || rdi7->f40->f4)) {
                    ebx6 = 0x8009800f;
                    if (rdi7->f40->f4) {
                        ebx6 = rdi7->f40->f4;
                    }
                } else {
                    *reinterpret_cast<int32_t*>(&r8_19) = rdi7->f40->f8;
                    *reinterpret_cast<int32_t*>(&r8_19 + 4) = 0;
                    *reinterpret_cast<uint32_t*>(&rax20) = static_cast<uint32_t>(reinterpret_cast<uint64_t>(r8_19 + 0xffffffffffffffff));
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax20) + 4) = 0;
                    if (*reinterpret_cast<uint32_t*>(&rax20) > 5) {
                        fun_1800010e0(2, " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = [%d]?", r8_19, r9, v21, 2, " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = [%d]?", r8_19, r9, v22);
                        rdi7->f40->f4 = 0x8009800f;
                        *rdx = rdi7->f40->f12;
                        ebx6 = rdi7->f40->f4;
                    } else {
                        *reinterpret_cast<int32_t*>(&rcx23) = *reinterpret_cast<int32_t*>(0x180000000 + rax20 * 4 + 0x26f0);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx23) + 4) = 0;
                        goto rcx23 + 0x180000000;
                    }
                }
            }
        }
    }
    *reinterpret_cast<int32_t*>(&r8_24) = ebx6;
    *reinterpret_cast<int32_t*>(&r8_24 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterFinishCapture : ErrorCode [0x%08X]", r8_24, r9, v25, 2, "<<< SensorAdapterFinishCapture : ErrorCode [0x%08X]", r8_24, r9, v26);
    *reinterpret_cast<int32_t*>(&rax27) = ebx6;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax27) + 4) = 0;
    return rax27;
}

struct s118 {
    signed char[4] pad4;
    int32_t f4;
};

struct s120 {
    signed char[12] pad12;
    int32_t f12;
};

struct s119 {
    signed char[40] pad40;
    struct s120* f40;
};

void fun_1800025d2() {
    struct s118* rdx1;
    int32_t* rsi2;
    struct s119* rdi3;
    void** r8_4;
    void** r9_5;

    rdx1->f4 = 0x80098008;
    *rsi2 = rdi3->f40->f12;
    fun_1800010e0(2, " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_REJECT", r8_4, r9_5, __return_address());
    goto 0x180002655;
}

int64_t fun_180002b80() {
    void** r8_1;
    void** r9_2;
    int64_t v3;
    void** r9_4;
    int64_t v5;

    fun_1800010e0(2, ">>> SensorAdapterControlUnitPrivileged", r8_1, r9_2, v3);
    fun_1800010e0(2, "<<< SensorAdapterControlUnitPrivileged : ErrorCode [0x%08X]", 0, r9_4, v5);
    return 0;
}

int64_t g180010278 = 0;

int64_t fun_180003675(int64_t rcx, int32_t edx, void** r8, struct s6* r9) {
    int64_t rbx5;
    int32_t edx6;
    int1_t zf7;
    uint32_t eax8;
    uint32_t edi9;
    int64_t rax10;
    int64_t rax11;
    int32_t eax12;
    void** rdx13;
    int32_t eax14;
    int64_t rax15;
    void** rdx16;
    int64_t rcx17;
    int32_t eax18;
    uint32_t ecx19;
    int64_t rax20;
    int64_t rdx21;
    uint32_t eax22;

    *reinterpret_cast<int32_t*>(&rbx5) = edx;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx5) + 4) = 0;
    edx6 = 1;
    if (*reinterpret_cast<int32_t*>(&rbx5) || (zf7 = g18001cd50 == *reinterpret_cast<int32_t*>(&rbx5), !zf7)) {
        if (static_cast<uint32_t>(rbx5 - 1) > 1) {
            addr_1800036f5_4:
            eax8 = fun_180002be0(rcx, rcx);
            edi9 = eax8;
            if (*reinterpret_cast<int32_t*>(&rbx5) == 1 && (!eax8 && (fun_180002be0(rcx), fun_1800034d8(rcx, 0, r8, r9), rax10 = g180010278, !!rax10))) {
                rax10(rcx);
            }
        } else {
            rax11 = g180010278;
            if (rax11) {
                eax12 = reinterpret_cast<int32_t>(rax11());
                edx6 = eax12;
            }
            if (!edx6) 
                goto addr_1800036ee_9;
            *reinterpret_cast<int32_t*>(&rdx13) = *reinterpret_cast<int32_t*>(&rbx5);
            *reinterpret_cast<int32_t*>(&rdx13 + 4) = 0;
            eax14 = fun_1800034d8(rcx, rdx13, r8, r9);
            if (eax14) 
                goto addr_1800036f5_4; else 
                goto addr_1800036ee_9;
        }
    } else {
        *reinterpret_cast<uint32_t*>(&rax15) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax15) + 4) = 0;
        goto addr_180003787_12;
    }
    if ((!*reinterpret_cast<int32_t*>(&rbx5) || *reinterpret_cast<int32_t*>(&rbx5) == 3) && ((*reinterpret_cast<int32_t*>(&rdx16) = *reinterpret_cast<int32_t*>(&rbx5), *reinterpret_cast<int32_t*>(&rdx16 + 4) = 0, rcx17 = rcx, eax18 = fun_1800034d8(rcx17, rdx16, r8, r9), ecx19 = *reinterpret_cast<uint32_t*>(&rcx17) - (*reinterpret_cast<uint32_t*>(&rcx17) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rcx17) < *reinterpret_cast<uint32_t*>(&rcx17) + reinterpret_cast<uint1_t>(!!eax18))) & edi9, edi9 = ecx19, !!ecx19) && (rax20 = g180010278, !!rax20))) {
        *reinterpret_cast<int32_t*>(&rdx21) = *reinterpret_cast<int32_t*>(&rbx5);
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx21) + 4) = 0;
        eax22 = reinterpret_cast<uint32_t>(rax20(rcx, rdx21, r8));
        edi9 = eax22;
    }
    *reinterpret_cast<uint32_t*>(&rax15) = edi9;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax15) + 4) = 0;
    addr_180003787_12:
    return rax15;
    addr_1800036ee_9:
    *reinterpret_cast<uint32_t*>(&rax15) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax15) + 4) = 0;
    goto addr_180003787_12;
}

void fun_180003e6f(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 11) = rdx;
    goto 0x180003e67;
}

int32_t g180017234 = 2;

int64_t fun_180004b24() {
    int64_t rdi1;
    uint32_t edx2;
    int64_t rdx3;
    uint32_t r8d4;
    uint32_t r8d5;

    *reinterpret_cast<uint32_t*>(&rdi1) = 0;
    g180017234 = 2;
    g180017230 = 1;
    if (!!(__intrinsic() ^ 0x49656e69 | __intrinsic() ^ 0x6c65746e | __intrinsic() ^ 0x756e6547) || (edx2 = __intrinsic() & 0xfff3ff0, edx2 != 0x106c0) && (edx2 != 0x20660 && (edx2 != 0x20670 && ((*reinterpret_cast<uint32_t*>(&rdx3) = edx2 - 0x30650, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx3) + 4) = 0, *reinterpret_cast<uint32_t*>(&rdx3) > 32) || !static_cast<int1_t>(0x100010001 >> rdx3))))) {
        r8d4 = g18001d2e4;
    } else {
        r8d5 = g18001d2e4;
        r8d4 = r8d5 | 1;
        g18001d2e4 = r8d4;
    }
    if (!(__intrinsic() ^ 0x68747541 | __intrinsic() ^ 0x69746e65 | __intrinsic() ^ 0x444d4163) && reinterpret_cast<int32_t>(__intrinsic() & 0xff00f00) >= reinterpret_cast<int32_t>(0x600f00)) {
        r8d4 = r8d4 | 4;
        g18001d2e4 = r8d4;
    }
    if (__intrinsic() >= 7 && (*reinterpret_cast<uint32_t*>(&rdi1) = __intrinsic(), static_cast<int1_t>(__intrinsic() >> 9))) {
        g18001d2e4 = r8d4 | 2;
    }
    if (static_cast<int1_t>(__intrinsic() >> 20) && ((g180017230 = 2, g180017234 = 6, static_cast<int1_t>(__intrinsic() >> 27)) && (static_cast<int1_t>(__intrinsic() >> 28) && (g180017230 = 3, g180017234 = 14, !!(*reinterpret_cast<unsigned char*>(&rdi1) & 32))))) {
        g180017230 = 5;
        g180017234 = 46;
    }
    return 0;
}

void fun_1800068a8() {
    int64_t* rbx1;
    int64_t rax2;

    rbx1 = reinterpret_cast<int64_t*>(0x1800154d0);
    while (reinterpret_cast<uint64_t>(rbx1) < 0x1800154d0) {
        rax2 = *rbx1;
        if (rax2) {
            rax2();
        }
        ++rbx1;
    }
    return;
}

int64_t g18001efc8;

int64_t fun_1800068e0(void** rcx, void** rdx, void** r8, struct s6* r9) {
    void* rsp5;
    void* r12_6;
    uint32_t* rbx7;
    uint64_t r15_8;
    struct s6* r14_9;
    void** r13_10;
    void** rbp11;
    int64_t rdi12;
    uint64_t rsi13;
    uint32_t edx14;
    int64_t rcx15;
    int64_t rcx16;
    uint64_t rax17;
    uint64_t rax18;
    uint32_t r9d19;
    int64_t r8_20;
    int64_t r8_21;
    uint64_t rax22;
    uint64_t rax23;
    uint64_t rax24;
    int64_t r8_25;
    uint32_t esi26;
    int64_t rdi27;
    int64_t rdi28;
    uint64_t rax29;
    uint64_t rax30;
    int1_t zf31;
    uint32_t eax32;
    int64_t rax33;
    int32_t eax34;
    int1_t sf35;
    int64_t rcx36;
    void* rdx37;
    int64_t rax38;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 64);
    r12_6 = r9->f8;
    rbx7 = r9->f56;
    r15_8 = r9->f0 - reinterpret_cast<uint64_t>(r12_6);
    r14_9 = r9;
    r13_10 = rdx;
    rbp11 = rcx;
    if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 4)) & 0x66) {
        *reinterpret_cast<uint32_t*>(&rdi12) = r9->f72;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi12) + 4) = 0;
        rsi13 = r9->f32 - reinterpret_cast<uint64_t>(r12_6);
        while (edx14 = *rbx7, *reinterpret_cast<uint32_t*>(&rdi12) < edx14) {
            *reinterpret_cast<uint32_t*>(&rcx15) = *reinterpret_cast<uint32_t*>(&rdi12);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx15) + 4) = 0;
            rcx16 = rcx15 + rcx15;
            *reinterpret_cast<int32_t*>(&rax17) = *reinterpret_cast<int32_t*>(rbx7 + rcx16 * 2 + 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax17) + 4) = 0;
            if (r15_8 >= rax17 && (*reinterpret_cast<int32_t*>(&rax18) = *reinterpret_cast<int32_t*>(rbx7 + rcx16 * 2 + 2), *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax18) + 4) = 0, r15_8 < rax18)) {
                if (reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rbp11 + 4)) & 32) {
                    r9d19 = 0;
                    if (edx14) {
                        do {
                            *reinterpret_cast<uint32_t*>(&r8_20) = r9d19;
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_20) + 4) = 0;
                            r8_21 = r8_20 + r8_20;
                            *reinterpret_cast<int32_t*>(&rax22) = *reinterpret_cast<int32_t*>(rbx7 + r8_21 * 2 + 1);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax22) + 4) = 0;
                            if (rsi13 < rax22) 
                                continue;
                            *reinterpret_cast<int32_t*>(&rax23) = *reinterpret_cast<int32_t*>(rbx7 + r8_21 * 2 + 2);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax23) + 4) = 0;
                            if (rsi13 >= rax23) 
                                continue;
                            if (*reinterpret_cast<int32_t*>(rbx7 + r8_21 * 2 + 4) != *reinterpret_cast<int32_t*>(rbx7 + rcx16 * 2 + 4)) 
                                continue;
                            if (*reinterpret_cast<int32_t*>(rbx7 + r8_21 * 2 + 3) == *reinterpret_cast<int32_t*>(rbx7 + rcx16 * 2 + 3)) 
                                break;
                            ++r9d19;
                        } while (r9d19 < edx14);
                    }
                    if (r9d19 != edx14) 
                        break;
                }
                *reinterpret_cast<int32_t*>(&rax24) = *reinterpret_cast<int32_t*>(rbx7 + rcx16 * 2 + 4);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax24) + 4) = 0;
                if (!*reinterpret_cast<int32_t*>(&rax24)) {
                    r14_9->f72 = static_cast<uint32_t>(rdi12 + 1);
                    *reinterpret_cast<int32_t*>(&r8_25) = *reinterpret_cast<int32_t*>(rbx7 + rcx16 * 2 + 3);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_25) + 4) = 0;
                    r8_25 + reinterpret_cast<uint64_t>(r12_6)(1, r13_10);
                } else {
                    if (rsi13 == rax24) 
                        break;
                }
            }
            *reinterpret_cast<uint32_t*>(&rdi12) = *reinterpret_cast<uint32_t*>(&rdi12) + 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi12) + 4) = 0;
        }
    } else {
        esi26 = r9->f72;
        while (esi26 < *rbx7) {
            *reinterpret_cast<uint32_t*>(&rdi27) = esi26;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi27) + 4) = 0;
            rdi28 = rdi27 + rdi27;
            *reinterpret_cast<int32_t*>(&rax29) = *reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 1);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax29) + 4) = 0;
            if (r15_8 < rax29 || ((*reinterpret_cast<int32_t*>(&rax30) = *reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 2), *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax30) + 4) = 0, r15_8 >= rax30) || !*reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 4))) {
                addr_1800069ed_21:
                ++esi26;
                continue;
            } else {
                if (*reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 3) == 1) {
                    addr_180006979_23:
                    if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rbp11) == 0xe06d7363) && ((zf31 = g18001efc8 == 0, !zf31) && (eax32 = fun_180008e30(0x18001efc8, rdx, r8, r9), rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8), !!eax32))) {
                        g18001efc8(rbp11, 1, r8, r9);
                        rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8);
                    }
                } else {
                    *reinterpret_cast<int32_t*>(&rax33) = *reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 3);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax33) + 4) = 0;
                    rdx = r13_10;
                    eax34 = reinterpret_cast<int32_t>(rax33 + reinterpret_cast<uint64_t>(r12_6)(reinterpret_cast<int64_t>(rsp5) + 48, rdx, r8, r9));
                    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8);
                    sf35 = eax34 < 0;
                    if (sf35) 
                        goto addr_1800069f4_26;
                    if (reinterpret_cast<uint1_t>(sf35) | reinterpret_cast<uint1_t>(eax34 == 0)) 
                        goto addr_1800069ed_21; else 
                        goto addr_180006979_23;
                }
            }
            *reinterpret_cast<int32_t*>(&rcx36) = *reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 4);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx36) + 4) = 0;
            fun_180009350(rcx36 + reinterpret_cast<uint64_t>(r12_6), r13_10, 1, r9);
            *reinterpret_cast<int32_t*>(&rdx37) = *reinterpret_cast<int32_t*>(rbx7 + rdi28 * 2 + 4);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx37) + 4) = 0;
            *reinterpret_cast<void***>(&r9) = *reinterpret_cast<void***>(rbp11);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r9) + 4) = 0;
            rdx = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rdx37) + reinterpret_cast<uint64_t>(r12_6));
            r8 = rbp11;
            RtlUnwindEx(r13_10);
            fun_180009380(r13_10);
            rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 8 + 8 - 8 + 8 - 8 + 8);
            goto addr_1800069ed_21;
        }
    }
    *reinterpret_cast<int32_t*>(&rax38) = 1;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax38) + 4) = 0;
    addr_180006aa3_30:
    return rax38;
    addr_1800069f4_26:
    *reinterpret_cast<int32_t*>(&rax38) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax38) + 4) = 0;
    goto addr_180006aa3_30;
}

void fun_180008e70() {
}

int64_t fun_180008eb0() {
    void** r8_1;
    void** rax2;
    void** rax3;
    int64_t rax4;

    rax2 = fun_1800066f0(32, 8, r8_1);
    rax3 = reinterpret_cast<void**>(EncodePointer(rax2));
    g18001f100 = rax3;
    g18001f0f8 = rax3;
    if (rax2) {
        *reinterpret_cast<void***>(rax2) = reinterpret_cast<void**>(0);
        *reinterpret_cast<int32_t*>(&rax4) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax4) + 4) = 0;
    } else {
        *reinterpret_cast<int32_t*>(&rax4) = static_cast<int32_t>(reinterpret_cast<uint64_t>(rax2 + 24));
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax4) + 4) = 0;
    }
    return rax4;
}

void fun_18000a62c() {
    goto fun_1800053cc;
}

void fun_18000a714() {
    int1_t zf1;
    void** rdx2;
    void** r8_3;
    void** rax4;

    zf1 = reinterpret_cast<int1_t>(g180017e70 == 0x180017e80);
    if (!zf1) {
        fun_1800088e8(12, rdx2, r8_3);
        rax4 = fun_180007b18(0x180017e70, 0x180017e80);
        g180017e70 = rax4;
        fun_180008ad8(12, 12);
    }
    return;
}

void fun_18000e7af() {
    goto fun_180008ad8;
}

void fun_18000e805() {
    fun_180008ad8(11);
    return;
}

void fun_18000e8e2() {
    goto fun_180008ad8;
}

int64_t fun_1800014c0(struct s67* rcx) {
    void** r8_2;
    void** r9_3;
    int64_t v4;
    struct s68* rsi5;
    void** r8_6;
    void** r9_7;
    struct s68* rbx8;
    struct s68* rdi9;
    signed char* rdi10;
    struct s68* rcx11;
    struct s68* rcx12;
    int64_t rax13;
    void** r8_14;
    void** r9_15;
    int64_t v16;
    int64_t rax17;
    int64_t rax18;

    fun_1800010e0(2, ">>> SensorAdapterDetach", r8_2, r9_3, v4);
    *reinterpret_cast<int32_t*>(&rsi5) = 0;
    *reinterpret_cast<int32_t*>(&rsi5 + 4) = 0;
    if (rcx) {
        if (rcx->f48) {
            fun_1800027f0(rcx, ">>> SensorAdapterDetach", r8_6, r9_7);
            rbx8 = rcx->f48;
            rcx->f48 = reinterpret_cast<struct s68*>(0);
            rdi9 = rbx8->f40;
            if (!rdi9) {
                addr_18000154a_4:
                rdi10 = rbx8->f56;
                if (rdi10) {
                    rcx11 = rbx8->f64;
                    while (*reinterpret_cast<int32_t*>(&rcx11)) {
                        *reinterpret_cast<int32_t*>(&rcx11) = *reinterpret_cast<int32_t*>(&rcx11) - 1;
                        *rdi10 = 0;
                        ++rdi10;
                        rsi5 = reinterpret_cast<struct s68*>(&rsi5->pad40);
                    }
                    rbx8->f64 = rsi5;
                }
            } else {
                rcx12 = rbx8->f48;
                while (*reinterpret_cast<int32_t*>(&rcx12)) {
                    *reinterpret_cast<int32_t*>(&rcx12) = *reinterpret_cast<int32_t*>(&rcx12) - 1;
                    *reinterpret_cast<struct s68**>(&rdi9->f0) = reinterpret_cast<struct s68*>(0);
                    rdi9 = reinterpret_cast<struct s68*>(&rdi9->pad40);
                    rsi5 = reinterpret_cast<struct s68*>(&rsi5->pad40);
                }
                if (!rbx8->f40) 
                    goto addr_180001542_13; else 
                    goto addr_18000152e_14;
            }
        } else {
            *reinterpret_cast<int32_t*>(&rsi5) = 0x8009800f;
            goto addr_180001589_16;
        }
    } else {
        *reinterpret_cast<int32_t*>(&rsi5) = 0x80004003;
        goto addr_180001589_16;
    }
    if (*reinterpret_cast<struct s68**>(&rbx8->f0)) {
        CloseHandle();
        *reinterpret_cast<struct s68**>(&rbx8->f0) = rsi5;
    }
    rax13 = reinterpret_cast<int64_t>(GetProcessHeap());
    HeapFree(rax13);
    addr_180001589_16:
    *reinterpret_cast<int32_t*>(&r8_14) = *reinterpret_cast<int32_t*>(&rsi5);
    *reinterpret_cast<int32_t*>(&r8_14 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterDetach : ErrorCode [0x%08X]", r8_14, r9_15, v16);
    *reinterpret_cast<int32_t*>(&rax17) = *reinterpret_cast<int32_t*>(&rsi5);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax17) + 4) = 0;
    return rax17;
    addr_180001542_13:
    rbx8->f40 = rsi5;
    rbx8->f48 = rsi5;
    goto addr_18000154a_4;
    addr_18000152e_14:
    rax18 = reinterpret_cast<int64_t>(GetProcessHeap());
    HeapFree(rax18);
    goto addr_180001542_13;
}

struct s121 {
    int64_t f0;
    signed char[40] pad48;
    int64_t f48;
};

int64_t fun_180001a70(struct s121* rcx, int32_t edx, void** r8, void** r9) {
    int64_t v5;
    int64_t v6;
    uint32_t ebx7;
    void* rdx8;
    void* r8_9;
    int64_t rcx10;
    int64_t rax11;
    void* rsp12;
    int64_t rcx13;
    void** r8_14;
    int64_t rdx15;
    int32_t eax16;
    int32_t eax17;
    int32_t eax18;
    void* rsp19;
    int32_t eax20;
    int32_t eax21;
    uint16_t ax22;
    uint32_t eax23;
    void** r8_24;
    int64_t v25;
    int64_t v26;
    int64_t rax27;
    int64_t v28;
    int64_t v29;

    fun_1800010e0(2, ">>> SensorAdapterSetIndicatorStatus", r8, r9, v5);
    v6 = 0;
    if (!rcx || !edx) {
        ebx7 = 0x80004003;
    } else {
        if (!rcx->f48 || rcx->f0 == -1) {
            ebx7 = 0x8009800f;
        } else {
            *reinterpret_cast<int32_t*>(&rdx8) = 1;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx8) + 4) = 0;
            *reinterpret_cast<int32_t*>(&r9) = 0;
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            *reinterpret_cast<int32_t*>(&r8_9) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_9) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rcx10) = 0;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx10) + 4) = 0;
            rax11 = reinterpret_cast<int64_t>(CreateEventA());
            rsp12 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 96 - 8 + 8 - 8 + 8);
            v6 = rax11;
            if (rax11) {
                rcx13 = rcx->f0;
                r8_14 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rsp12) + 0x80);
                *reinterpret_cast<int32_t*>(&r9) = 8;
                *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                *reinterpret_cast<int32_t*>(&rdx15) = 0x440024;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx15) + 4) = 0;
                eax16 = reinterpret_cast<int32_t>(DeviceIoControl(rcx13, 0x440024, r8_14, 8));
                if (eax16) {
                    addr_180001bce_7:
                    if (1) {
                        addr_180001bef_8:
                        eax17 = reinterpret_cast<int32_t>(GetLastError(rcx13, rdx15, r8_14, 8));
                        if (eax17 == 0x4c7 || eax17 == 0x3e3) {
                            ebx7 = 0x80098004;
                        } else {
                            ebx7 = 0x80098036;
                        }
                    } else {
                        ebx7 = 0;
                    }
                } else {
                    eax18 = reinterpret_cast<int32_t>(GetLastError(rcx13, 0x440024, r8_14, 8));
                    if (eax18 != 0x3e5) 
                        goto addr_180001bef_8;
                    SetLastError();
                    rsp19 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp12) - 8 + 8 - 8 + 8 - 8 + 8);
                    rcx10 = rcx->f0;
                    r8_9 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp19) + 0x70);
                    rdx8 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp19) + 64);
                    *reinterpret_cast<int32_t*>(&r9) = 1;
                    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
                    eax20 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx10, rdx8, r8_9, 1));
                    if (!eax20) 
                        goto addr_180001b10_14;
                    if (1) 
                        goto addr_180001b10_14; else 
                        goto addr_180001bb5_16;
                }
            } else {
                addr_180001b10_14:
                eax21 = reinterpret_cast<int32_t>(GetLastError(rcx10, rdx8, r8_9, r9));
                if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax21 < 0) | reinterpret_cast<uint1_t>(eax21 == 0))) {
                    ax22 = reinterpret_cast<uint16_t>(GetLastError(rcx10, rdx8, r8_9, r9));
                    ebx7 = static_cast<uint32_t>(ax22) | 0x80070000;
                } else {
                    eax23 = reinterpret_cast<uint32_t>(GetLastError(rcx10, rdx8, r8_9, r9));
                    ebx7 = eax23;
                }
            }
        }
    }
    if (v6) {
        CloseHandle();
    }
    *reinterpret_cast<uint32_t*>(&r8_24) = ebx7;
    *reinterpret_cast<int32_t*>(&r8_24 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterSetIndicatorStatus : ErrorCode [0x%08X]", r8_24, r9, v25, 2, "<<< SensorAdapterSetIndicatorStatus : ErrorCode [0x%08X]", r8_24, r9, v26);
    *reinterpret_cast<uint32_t*>(&rax27) = ebx7;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax27) + 4) = 0;
    return rax27;
    addr_180001bb5_16:
    *reinterpret_cast<int32_t*>(&r9) = 8;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    rdx15 = reinterpret_cast<int64_t>("SensorAdapterStartCapture : IOCTL_BIOMETRIC_SET_INDICATOR GetOverlappedResult result = [%d], bytesReturned = [%d]");
    *reinterpret_cast<int32_t*>(&r8_14) = eax20;
    *reinterpret_cast<int32_t*>(&r8_14 + 4) = 0;
    *reinterpret_cast<uint32_t*>(&rcx13) = 2;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx13) + 4) = 0;
    fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_SET_INDICATOR GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_14, 8, v28, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_SET_INDICATOR GetOverlappedResult result = [%d], bytesReturned = [%d]", r8_14, 8, v29);
    goto addr_180001bce_7;
}

struct s122 {
    signed char[4] pad4;
    int32_t f4;
};

void fun_1800025f6() {
    struct s122* rdx1;

    rdx1->f4 = 0x80098010;
    goto 0x180002655;
}

struct s125 {
    signed char[16] pad16;
    int32_t f16;
    void** f20;
};

struct s124 {
    signed char[40] pad40;
    struct s125* f40;
};

struct s123 {
    signed char[48] pad48;
    struct s124* f48;
};

signed char g1a5ff26fa;

signed char g1a6122702;

void fun_1800026f0(struct s123* rcx, void*** rdx, void** r8, void** r9) {
    signed char* rax5;
    signed char* rax6;
    signed char al7;
    signed char* rax8;
    signed char* rax9;
    signed char al10;
    signed char* rax11;
    signed char al12;
    int64_t v13;
    int32_t ebx14;
    struct s124* rdi15;
    void** rcx16;
    void** rax17;
    void* r8_18;
    void** rdx19;
    void** rax20;
    void** r8_21;
    int64_t v22;
    int64_t rbp23;

    *rax5 = reinterpret_cast<signed char>(*rax6 + al7);
    g1a5ff26fa = reinterpret_cast<signed char>(g1a5ff26fa << *reinterpret_cast<unsigned char*>(&rcx));
    *rax8 = reinterpret_cast<signed char>(*rax9 + al10);
    *reinterpret_cast<int16_t*>(&rax11) = reinterpret_cast<int16_t>(al12 * g1a6122702);
    *rax11 = reinterpret_cast<signed char>(*rax11 + *reinterpret_cast<signed char*>(&rax11));
    fun_1800010e0(2, ">>> SensorAdapterExportSensorData", r8, r9, v13);
    ebx14 = 0;
    if (!rcx || (!rdx || !r8)) {
        ebx14 = 0x80004003;
    } else {
        rdi15 = rcx->f48;
        if (rdi15) {
            if (!rdi15->f40 || (*reinterpret_cast<int32_t*>(&rcx16) = rdi15->f40->f16, *reinterpret_cast<int32_t*>(&rcx16 + 4) = 0, *reinterpret_cast<int32_t*>(&rcx16) == 0)) {
                ebx14 = 0x80098026;
            } else {
                rax17 = fun_180002bb0(rcx16, ">>> SensorAdapterExportSensorData", r8, r9);
                if (rax17) {
                    *reinterpret_cast<int32_t*>(&r8_18) = rdi15->f40->f16;
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_18) + 4) = 0;
                    rdx19 = reinterpret_cast<void**>(&rdi15->f40->f20);
                    fun_180002f70(rax17, rdx19, r8_18);
                    *rdx = rax17;
                    *reinterpret_cast<int32_t*>(&rax20) = rcx->f48->f40->f16;
                    *reinterpret_cast<int32_t*>(&rax20 + 4) = 0;
                    *reinterpret_cast<void***>(r8) = rax20;
                } else {
                    ebx14 = 0x8007000e;
                }
            }
        } else {
            ebx14 = 0x8009800f;
        }
    }
    *reinterpret_cast<int32_t*>(&r8_21) = ebx14;
    *reinterpret_cast<int32_t*>(&r8_21 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterExportSensorData : ErrorCode [0x%08X]", r8_21, r9, v22);
    goto rbp23;
}

struct s127 {
    signed char[96] pad96;
    int64_t f96;
};

struct s129 {
    signed char[4] pad4;
    int32_t f4;
    int32_t f8;
    void** f12;
    signed char[3] pad16;
    int32_t f16;
};

struct s128 {
    signed char[40] pad40;
    struct s129* f40;
    uint64_t f48;
};

struct s126 {
    signed char[32] pad32;
    struct s127* f32;
    signed char[8] pad48;
    struct s128* f48;
};

int64_t fun_180002880(struct s126* rcx, unsigned char dl, void** r8, void** r9) {
    uint32_t esi5;
    int64_t v6;
    int32_t ebx7;
    void** r8_8;
    int64_t v9;
    int64_t v10;
    int64_t rax11;
    int64_t rdx12;
    int64_t r8_13;
    int64_t r10_14;
    int32_t eax15;

    esi5 = dl;
    fun_1800010e0(2, ">>> SensorAdapterPushDataToEngine", r8, r9, v6);
    if (!rcx) 
        goto addr_18000293f_2;
    if (!r9) 
        goto addr_18000293f_2;
    if (rcx->f48) {
        if (!rcx->f48->f40) 
            goto addr_180002938_6;
        if (rcx->f48->f48 < 24) 
            goto addr_18000291b_8;
        if (!rcx->f48->f40->f16) 
            goto addr_18000291b_8;
        if (rcx->f48->f40->f8 == 1) 
            goto addr_1800028e8_11;
    } else {
        ebx7 = 0x8009800f;
        goto addr_180002944_13;
    }
    addr_18000291b_8:
    if (!rcx->f48->f40 || (rcx->f48->f48 < 24 || (ebx7 = 0x80098008, rcx->f48->f40->f4 != 0x80098008))) {
        addr_180002938_6:
        ebx7 = 0x80098026;
    } else {
        *reinterpret_cast<void***>(r9) = rcx->f48->f40->f12;
    }
    addr_180002944_13:
    *reinterpret_cast<int32_t*>(&r8_8) = ebx7;
    *reinterpret_cast<int32_t*>(&r8_8 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterPushDataToEngine : ErrorCode [0x%08X]", r8_8, r9, v9, 2, "<<< SensorAdapterPushDataToEngine : ErrorCode [0x%08X]", r8_8, r9, v10);
    *reinterpret_cast<int32_t*>(&rax11) = ebx7;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax11) + 4) = 0;
    return rax11;
    addr_1800028e8_11:
    rdx12 = reinterpret_cast<int64_t>(rcx->f48->f40 + 1);
    *reinterpret_cast<int32_t*>(&r8_13) = rcx->f48->f40->f16;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_13) + 4) = 0;
    if (!rcx->f32) {
        addr_18000293f_2:
        ebx7 = 0x80004003;
        goto addr_180002944_13;
    } else {
        r10_14 = rcx->f32->f96;
        if (r10_14) {
            *reinterpret_cast<uint32_t*>(&r9) = *reinterpret_cast<unsigned char*>(&esi5);
            *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
            eax15 = reinterpret_cast<int32_t>(r10_14(rcx, rdx12, r8_13, r9));
            ebx7 = eax15;
            goto addr_180002944_13;
        } else {
            ebx7 = 0x80004001;
            goto addr_180002944_13;
        }
    }
}

struct s130 {
    int64_t f0;
    signed char[40] pad48;
    int64_t f48;
};

int64_t fun_180002970(struct s130* rcx, int32_t edx, void** r8, void** r9) {
    void** r15_5;
    int64_t v6;
    int64_t rbx7;
    int64_t v8;
    void*** v9;
    int64_t v10;
    int32_t eax11;
    int32_t eax12;
    int32_t eax13;
    int32_t eax14;
    void*** r8_15;
    int64_t rcx16;
    void* rdx17;
    int64_t rax18;
    int64_t rcx19;
    int64_t rdx20;
    int32_t eax21;
    uint32_t eax22;
    int32_t eax23;
    int32_t eax24;
    uint16_t ax25;
    uint32_t eax26;
    void** v27;
    int64_t v28;
    int64_t v29;
    int64_t v30;
    int64_t v31;
    int64_t rax32;

    r15_5 = r9;
    fun_1800010e0(2, ">>> SensorAdapterControlUnit", r8, r9, v6);
    *reinterpret_cast<uint32_t*>(&rbx7) = 0;
    v8 = 0;
    if (!rcx || (!v9 || !v10)) {
        *reinterpret_cast<uint32_t*>(&rbx7) = 0x80004003;
        goto addr_180002b26_3;
    }
    if (!rcx->f48 || rcx->f0 == -1) {
        *reinterpret_cast<uint32_t*>(&rbx7) = 0x8009800f;
        goto addr_180002b26_3;
    }
    eax11 = edx - 0x442010;
    if (!eax11 || ((eax12 = eax11 - 4, eax12 == 0) || ((eax13 = eax12 - 4, eax13 == 0) || ((eax14 = eax13 - 4, eax14 == 0) || eax14 == 4)))) {
        *reinterpret_cast<int32_t*>(&r9) = 0;
        *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
        *reinterpret_cast<int32_t*>(&r8_15) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r8_15) + 4) = 0;
        *reinterpret_cast<int32_t*>(&rcx16) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx16) + 4) = 0;
        *reinterpret_cast<int32_t*>(&rdx17) = 1;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx17) + 4) = 0;
        rax18 = reinterpret_cast<int64_t>(CreateEventA());
        v8 = rax18;
        if (!rax18) 
            goto addr_180002a3f_8;
        rcx19 = rcx->f0;
        *reinterpret_cast<int32_t*>(&r9) = *reinterpret_cast<int32_t*>(&r15_5);
        *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
        *reinterpret_cast<int32_t*>(&rdx20) = edx;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx20) + 4) = 0;
        eax21 = reinterpret_cast<int32_t>(DeviceIoControl(rcx19, rdx20, r8, r9));
        if (eax21) 
            goto addr_180002b26_3;
        eax22 = reinterpret_cast<uint32_t>(GetLastError(rcx19, rdx20, r8, r9));
        *reinterpret_cast<uint32_t*>(&rbx7) = eax22;
        if (eax22 != 0x3e5) 
            goto addr_180002b26_3;
    } else {
        addr_180002b26_3:
        if (v8) {
            CloseHandle();
            goto addr_180002b60_12;
        }
    }
    SetLastError();
    rcx16 = rcx->f0;
    rdx17 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 0x70 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 - 8 + 8 + 64);
    *reinterpret_cast<int32_t*>(&r9) = 1;
    *reinterpret_cast<int32_t*>(&r9 + 4) = 0;
    r8_15 = v9;
    eax23 = reinterpret_cast<int32_t>(GetOverlappedResult(rcx16, rdx17, r8_15, 1));
    if (!eax23) {
        addr_180002a3f_8:
        eax24 = reinterpret_cast<int32_t>(GetLastError(rcx16, rdx17, r8_15, r9));
        if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(eax24 < 0) | reinterpret_cast<uint1_t>(eax24 == 0))) {
            ax25 = reinterpret_cast<uint16_t>(GetLastError(rcx16, rdx17, r8_15, r9));
            *reinterpret_cast<uint32_t*>(&rbx7) = static_cast<uint32_t>(ax25) | 0x80070000;
            goto addr_180002b26_3;
        } else {
            eax26 = reinterpret_cast<uint32_t>(GetLastError(rcx16, rdx17, r8_15, r9));
            *reinterpret_cast<uint32_t*>(&rbx7) = eax26;
            goto addr_180002b26_3;
        }
    } else {
        r9 = *v9;
        if (r9 == v27) {
            rbx7 = 0;
            if (!1) {
                *reinterpret_cast<uint32_t*>(&rbx7) = 0x80070000;
            }
        } else {
            *reinterpret_cast<uint32_t*>(&rbx7) = 0x800705b6;
        }
        fun_1800010e0(2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_VENDOR GetOverlappedResult ReceiveBufferSize = [%d], ReceiveDataSize = [%d]", v27, r9, v28, 2, "SensorAdapterStartCapture : IOCTL_BIOMETRIC_VENDOR GetOverlappedResult ReceiveBufferSize = [%d], ReceiveDataSize = [%d]", v27, r9, v29);
        goto addr_180002b26_3;
    }
    addr_180002b60_12:
    fun_1800010e0(2, "<<< SensorAdapterControlUnit : ErrorCode [0x%08X]", 0, r9, v30, 2, "<<< SensorAdapterControlUnit : ErrorCode [0x%08X]", 0, r9, v31);
    *reinterpret_cast<uint32_t*>(&rax32) = *reinterpret_cast<uint32_t*>(&rbx7);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax32) + 4) = 0;
    return rax32;
}

void fun_180003638(int64_t rcx, int32_t edx, int64_t r8) {
    if (edx == 1) {
        fun_180005f40();
    }
    goto 0x180003678;
}

int64_t WbioQuerySensorInterface(int64_t* rcx) {
    void** r8_2;
    void** r9_3;
    int64_t v4;
    void** r8_5;
    void** r9_6;
    int64_t v7;

    if (rcx) {
        fun_1800010e0(2, ">>> WbioQuerySensorInterface", r8_2, r9_3, v4);
        *rcx = 0x180017000;
        fun_1800010e0(2, "<<< WbioQuerySensorInterface", r8_5, r9_6, v7);
        return 0;
    } else {
        return 0x80004003;
    }
}

void fun_180003785() {
}

int64_t fun_180006acc() {
    int32_t eax1;
    void* rbx2;
    int64_t rdi3;
    void** r8_4;
    void** rax5;
    void** rdx6;
    void** r8_7;
    int64_t rcx8;
    int64_t rax9;

    eax1 = g18001dfa8;
    *reinterpret_cast<int32_t*>(&rbx2) = 0;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rbx2) + 4) = 0;
    *reinterpret_cast<int32_t*>(&rdi3) = 20;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdi3) + 4) = 0;
    if (eax1) {
        if (eax1 < 20) {
            eax1 = 20;
        }
    } else {
        eax1 = 0x200;
    }
    g18001dfa8 = eax1;
    rax5 = fun_1800066f0(static_cast<int64_t>(eax1), 8, r8_4);
    g18001dfa0 = rax5;
    if (rax5 || (*reinterpret_cast<int32_t*>(&rdx6) = static_cast<int32_t>(reinterpret_cast<uint64_t>(rax5 + 8)), *reinterpret_cast<int32_t*>(&rdx6 + 4) = 0, g18001dfa8 = 20, rax5 = fun_1800066f0(20, rdx6, r8_7), g18001dfa0 = rax5, !!rax5)) {
        rcx8 = 0x1800172a0;
        while (*reinterpret_cast<int64_t*>(reinterpret_cast<int64_t>(rbx2) + reinterpret_cast<unsigned char>(rax5)) = rcx8, rcx8 = rcx8 + 48, rbx2 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbx2) + 8), --rdi3, !!rdi3) {
            rax5 = g18001dfa0;
        }
        *reinterpret_cast<int32_t*>(&rax9) = 0;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax9) + 4) = 0;
    } else {
        *reinterpret_cast<int32_t*>(&rax9) = 26;
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax9) + 4) = 0;
    }
    return rax9;
}

void fun_180003e75(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 14) = rdx;
    *reinterpret_cast<int32_t*>(rcx - 6) = *reinterpret_cast<int32_t*>(&rdx);
    *reinterpret_cast<int16_t*>(rcx - 2) = *reinterpret_cast<int16_t*>(&rdx);
    return;
}

void fun_180009018() {
    void** rax1;
    void** rcx2;

    rax1 = fun_180005018();
    rcx2 = *reinterpret_cast<void***>(rax1 + 0xd0);
    if (rcx2) {
        rcx2();
    }
    fun_18000abbc();
}

void** fun_180006b64() {
    int1_t zf1;
    void** rcx2;
    void** rax3;

    fun_1800097ac();
    zf1 = g18001d324 == 0;
    if (!zf1) {
        fun_18000963c();
    }
    rcx2 = g18001dfa0;
    rax3 = fun_180005f00(rcx2);
    g18001dfa0 = reinterpret_cast<void**>(0);
    return rax3;
}

struct s131 {
    unsigned char f0;
    signed char[7] pad8;
    unsigned char f8;
    signed char[7] pad16;
    unsigned char f16;
    signed char[7] pad24;
    unsigned char f24;
};

int64_t fun_18000aff0(struct s131* rcx, int64_t rdx, uint64_t r8) {
    int64_t rdx4;
    uint64_t r9_5;
    unsigned char rax6;
    uint1_t cf7;
    uint64_t r9_8;
    uint64_t r9_9;
    uint1_t cf10;
    uint32_t eax11;
    int64_t rax12;
    uint64_t tmp64_13;
    uint64_t tmp64_14;
    uint64_t rax15;
    uint64_t tmp64_16;
    uint64_t tmp64_17;
    uint1_t cf18;
    uint32_t eax19;
    int64_t rax20;

    rdx4 = rdx - reinterpret_cast<int64_t>(rcx);
    if (r8 < 8) 
        goto addr_18000b01b_2;
    if (!(*reinterpret_cast<unsigned char*>(&rcx) & 7)) {
        addr_18000b012_4:
        r9_5 = r8 >> 3;
        if (!r9_5) 
            goto addr_18000b01b_2;
    } else {
        do {
            rax6 = rcx->f0;
            cf7 = reinterpret_cast<uint1_t>(rax6 < *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx)));
            if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx))) 
                goto addr_18000b033_7;
            rcx = reinterpret_cast<struct s131*>(&rcx->pad8);
            --r8;
        } while (*reinterpret_cast<unsigned char*>(&rcx) & 7);
        goto addr_18000b012_4;
    }
    r9_8 = r9_5 >> 2;
    if (!r9_8) {
        addr_18000b077_10:
        r9_9 = r8 >> 3;
        if (!r9_9) {
            addr_18000b01b_2:
            if (!r8) {
                addr_18000b02f_11:
                return 0;
            } else {
                do {
                    rax6 = rcx->f0;
                    cf7 = reinterpret_cast<uint1_t>(rax6 < *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx)));
                    if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx))) 
                        break;
                    rcx = reinterpret_cast<struct s131*>(&rcx->pad8);
                    --r8;
                } while (r8);
                goto addr_18000b02f_11;
            }
        } else {
            do {
                rax6 = rcx->f0;
                if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx))) 
                    goto addr_18000b0a4_15;
                rcx = reinterpret_cast<struct s131*>(&rcx->f8);
                --r9_9;
            } while (r9_9);
            goto addr_18000b092_17;
        }
    } else {
        do {
            rax6 = rcx->f0;
            if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx))) 
                goto addr_18000b0a4_15;
            rax6 = rcx->f8;
            if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx) + 8)) 
                goto addr_18000b0a0_20;
            rax6 = rcx->f16;
            if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx) + 16)) 
                goto addr_18000b09c_22;
            rax6 = rcx->f24;
            if (rax6 != *reinterpret_cast<unsigned char*>(rdx4 + reinterpret_cast<int64_t>(rcx) + 24)) 
                goto addr_18000b098_24;
            rcx = reinterpret_cast<struct s131*>(reinterpret_cast<int64_t>(rcx) + 32);
            --r9_8;
        } while (r9_8);
        goto addr_18000b073_26;
    }
    addr_18000b033_7:
    cf10 = reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax6) < *reinterpret_cast<uint32_t*>(&rax6) + cf7);
    eax11 = *reinterpret_cast<uint32_t*>(&rax6) - (*reinterpret_cast<uint32_t*>(&rax6) + cf10);
    *reinterpret_cast<uint32_t*>(&rax12) = eax11 - (1 - reinterpret_cast<uint1_t>(eax11 < 1 - cf10));
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax12) + 4) = 0;
    return rax12;
    addr_18000b0a4_15:
    tmp64_13 = (rax6 & 0xffffffff) << 32 | (rax6 & 0xffffffff00000000) >> 32;
    tmp64_14 = (tmp64_13 & 0xffff0000ffff) << 16 | (tmp64_13 & 0xffff0000ffff0000) >> 16;
    rax15 = (tmp64_14 & 0xff00ff00ff00ff) << 8 | (tmp64_14 & 0xff00ff00ff00ff00) >> 8;
    tmp64_16 = (*reinterpret_cast<uint64_t*>(reinterpret_cast<int64_t>(rcx) + rdx4) & 0xffffffff) << 32 | (*reinterpret_cast<uint64_t*>(reinterpret_cast<int64_t>(rcx) + rdx4) & 0xffffffff00000000) >> 32;
    tmp64_17 = (tmp64_16 & 0xffff0000ffff) << 16 | (tmp64_16 & 0xffff0000ffff0000) >> 16;
    cf18 = reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rax15) < *reinterpret_cast<uint32_t*>(&rax15) + reinterpret_cast<uint1_t>(rax15 < ((tmp64_17 & 0xff00ff00ff00ff) << 8 | (tmp64_17 & 0xff00ff00ff00ff00) >> 8)));
    eax19 = *reinterpret_cast<uint32_t*>(&rax15) - (*reinterpret_cast<uint32_t*>(&rax15) + cf18);
    *reinterpret_cast<uint32_t*>(&rax20) = eax19 - (1 - reinterpret_cast<uint1_t>(eax19 < 1 - cf18));
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax20) + 4) = 0;
    return rax20;
    addr_18000b092_17:
    r8 = r8 & 7;
    goto addr_18000b01b_2;
    addr_18000b0a0_20:
    rcx = reinterpret_cast<struct s131*>(&rcx->f8);
    goto addr_18000b0a4_15;
    addr_18000b09c_22:
    rcx = reinterpret_cast<struct s131*>(&rcx->f8);
    goto addr_18000b0a0_20;
    addr_18000b098_24:
    rcx = reinterpret_cast<struct s131*>(&rcx->f8);
    goto addr_18000b09c_22;
    addr_18000b073_26:
    r8 = r8 & 31;
    goto addr_18000b077_10;
}

void fun_18000af78() {
    int64_t rcx1;

    rcx1 = g180018338;
    if (reinterpret_cast<uint64_t>(rcx1 + 2) > 1) {
        CloseHandle();
    }
    return;
}

int64_t g180017fe8 = 0x18000a62c;

struct s132 {
    signed char f0;
    signed char f1;
};

void fun_18000d328(struct s132* rcx);

int64_t g180017fe0 = 0x18000a62c;

struct s0* fun_18000c874(uint64_t* rcx, void** rdx, void* r8, int64_t r9);

int64_t g180017ff0 = 0x18000a62c;

void fun_18000d3c8(int32_t ecx, int32_t* rdx, unsigned char* r8);

int64_t g180018008 = 0x18000a62c;

int64_t g180017ff8 = 0x18000a62c;

struct s133 {
    unsigned char f0;
    unsigned char f1;
};

void fun_18000d410(struct s133* rcx);

int64_t g180018000 = 0x18000a62c;

int64_t fun_18000d498();

int64_t g180018010 = 0x18000a62c;

int64_t g180018018 = 0x18000a62c;

int64_t g180018020 = 0x18000a62c;

int64_t g180018028 = 0x18000a62c;

void fun_18000b410() {
    g180017fe8 = reinterpret_cast<int64_t>(fun_18000d328);
    g180017fe0 = reinterpret_cast<int64_t>(fun_18000c874);
    g180017ff0 = reinterpret_cast<int64_t>(fun_18000d3c8);
    g180018008 = reinterpret_cast<int64_t>(fun_18000c874);
    g180017ff8 = reinterpret_cast<int64_t>(fun_18000d410);
    g180018000 = reinterpret_cast<int64_t>(fun_18000d498);
    g180018010 = reinterpret_cast<int64_t>(fun_18000c898);
    g180018018 = 0x18000d3d0;
    g180018020 = 0x18000d330;
    g180018028 = 0x18000d418;
    return;
}

struct s0* fun_18000c874(uint64_t* rcx, void** rdx, void* r8, int64_t r9) {
    struct s0* rax5;

    rax5 = fun_18000c898(rcx, rdx, r8, r9);
    return rax5;
}

struct s134 {
    signed char[240] pad240;
    signed char** f240;
};

struct s135 {
    signed char[200] pad200;
    uint32_t f200;
};

void fun_18000d328(struct s132* rcx) {
    struct s132* rbx2;
    signed char cl3;
    struct s134* r8_4;
    struct s134* v5;
    signed char al6;
    signed char* rbx7;
    signed char v8;
    struct s135* v9;
    signed char* rdx10;
    signed char al11;

    rbx2 = rcx;
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 + 32, 0);
    cl3 = rbx2->f0;
    r8_4 = v5;
    if (cl3) {
        al6 = **r8_4->f240;
        do {
            if (cl3 == al6) 
                break;
            rbx2 = reinterpret_cast<struct s132*>(&rbx2->f1);
            cl3 = rbx2->f0;
        } while (cl3);
    }
    rbx7 = &rbx2->f1;
    if (!rbx2->f0) {
        addr_18000d3ad_7:
        if (v8) {
            v9->f200 = v9->f200 & 0xfffffffd;
        }
    } else {
        while (*rbx7 && reinterpret_cast<unsigned char>(*rbx7 - 69) & 0xdf) {
            ++rbx7;
        }
        rdx10 = rbx7;
        do {
            --rbx7;
        } while (*rbx7 == 48);
        if (*rbx7 != **r8_4->f240) 
            goto addr_18000d39f_15; else 
            goto addr_18000d39c_16;
    }
    return;
    do {
        addr_18000d39f_15:
        al11 = *rdx10;
        ++rbx7;
        ++rdx10;
        *rbx7 = al11;
    } while (al11);
    goto addr_18000d3ad_7;
    addr_18000d39c_16:
    --rbx7;
    goto addr_18000d39f_15;
}

void fun_18000d3c8(int32_t ecx, int32_t* rdx, unsigned char* r8) {
    void* rsp4;
    int32_t v5;
    int32_t v6;

    rsp4 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 48);
    if (!ecx) {
        fun_18000b408(reinterpret_cast<int64_t>(rsp4) + 64, r8, 0);
        *rdx = v5;
    } else {
        fun_18000b340(reinterpret_cast<int64_t>(rsp4) + 32, r8, 0);
        *rdx = v6;
    }
    return;
}

struct s136 {
    signed char[240] pad240;
    unsigned char** f240;
};

struct s137 {
    signed char[200] pad200;
    uint32_t f200;
};

void fun_18000d410(struct s133* rcx) {
    struct s133* rbx2;
    int64_t rcx3;
    uint32_t eax4;
    uint32_t ecx5;
    uint32_t eax6;
    int64_t rcx7;
    uint32_t eax8;
    unsigned char dl9;
    struct s136* v10;
    unsigned char* rbx11;
    unsigned char al12;
    unsigned char v13;
    struct s137* v14;

    rbx2 = rcx;
    fun_180003bc4(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 64 + 32, 0);
    *reinterpret_cast<int32_t*>(&rcx3) = reinterpret_cast<signed char>(rbx2->f0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx3) + 4) = 0;
    eax4 = fun_18000d8a0(rcx3);
    if (eax4 != 0x65) {
        do {
            rbx2 = reinterpret_cast<struct s133*>(&rbx2->f1);
            ecx5 = rbx2->f0;
            eax6 = fun_18000d6d0(ecx5);
        } while (eax6);
    }
    *reinterpret_cast<int32_t*>(&rcx7) = reinterpret_cast<signed char>(rbx2->f0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx7) + 4) = 0;
    eax8 = fun_18000d8a0(rcx7);
    if (eax8 == 0x78) {
        ++rbx2;
    }
    dl9 = rbx2->f0;
    rbx2->f0 = **v10->f240;
    rbx11 = &rbx2->f1;
    do {
        al12 = *rbx11;
        *rbx11 = dl9;
        dl9 = al12;
        ++rbx11;
    } while (*rbx11);
    if (v13 != *rbx11) {
        v14->f200 = v14->f200 & 0xfffffffd;
    }
    return;
}

int64_t fun_18000d498() {
    int32_t* rdi1;
    int32_t* rsi2;

    *rdi1 = *rsi2;
    __asm__("comisd xmm0, [rip+0x7eba]");
    return 1;
}

struct s138 {
    signed char[40] pad40;
    void** f40;
    signed char[7] pad48;
    void** f48;
    signed char[7] pad56;
    void** f56;
    signed char[7] pad64;
    void** f64;
    signed char[47] pad112;
    int64_t f112;
    int32_t f120;
    signed char[4] pad128;
    void** f128;
};

int64_t fun_18000e766(void** rcx, struct s138* rdx) {
    void** edx3;
    void** r8_4;
    int64_t rcx5;
    struct s6* r9_6;
    void** rdx7;
    void** ecx8;
    int64_t rax9;

    rdx->f64 = rcx;
    edx3 = *reinterpret_cast<void***>(*reinterpret_cast<void***>(rcx));
    rdx->f48 = edx3;
    rdx->f56 = rcx;
    rdx->f40 = edx3;
    if (rdx->f120 == 1) {
        r8_4 = rdx->f128;
        rcx5 = rdx->f112;
        fun_1800034d8(rcx5, 0, r8_4, r9_6);
    }
    rdx7 = rdx->f56;
    ecx8 = rdx->f40;
    rax9 = fun_180004e94(ecx8, rdx7, r8_4);
    return rax9;
}

void fun_18000e7c8() {
    goto fun_180008ad8;
}

void fun_18000e820() {
    goto fun_180009a58;
}

struct s139 {
    signed char[32] pad32;
    int32_t f32;
};

void fun_18000e8fb() {
    int64_t rcx1;
    struct s139* rdx2;
    void** rdx3;
    void** rdx4;

    rcx1 = rdx2->f32;
    rdx3 = g18001dfa0;
    rdx4 = *reinterpret_cast<void***>(rdx3 + rcx1 * 8);
    fun_180006c88(*reinterpret_cast<int32_t*>(&rcx1), rdx4);
    return;
}

struct s140 {
    signed char[56] pad56;
    struct s108* f56;
};

int64_t fun_180002ea4() {
    struct s108* r8_1;
    struct s140* r9_2;
    void* rdx3;
    struct s107* r9_4;

    r8_1 = r9_2->f56;
    fun_180002ec4(rdx3, r9_4, r8_1);
    return 1;
}

struct s142 {
    int64_t f0;
    signed char[32] pad40;
    struct s142* f40;
    struct s142* f48;
    struct s142* f56;
    struct s142* f64;
};

struct s141 {
    signed char[48] pad48;
    struct s142* f48;
};

int64_t fun_1800013d0(struct s141* rcx) {
    void** r8_2;
    void** r9_3;
    int64_t v4;
    struct s142* rbx5;
    int64_t rax6;
    struct s142* rax7;
    int64_t rax8;
    uint32_t eax9;
    int64_t rax10;
    void** r8_11;
    int64_t v12;
    int64_t rax13;

    fun_1800010e0(2, ">>> SensorAdapterAttach", r8_2, r9_3, v4);
    *reinterpret_cast<uint32_t*>(&rbx5) = 0;
    if (rcx) {
        if (!rcx->f48) {
            rax6 = reinterpret_cast<int64_t>(GetProcessHeap(2, ">>> SensorAdapterAttach"));
            rax7 = reinterpret_cast<struct s142*>(HeapAlloc(rax6));
            if (rax7) {
                rax7->f40 = reinterpret_cast<struct s142*>(0);
                rax7->f48 = reinterpret_cast<struct s142*>(0);
                rax7->f56 = reinterpret_cast<struct s142*>(0);
                rax7->f64 = reinterpret_cast<struct s142*>(0);
                rax8 = reinterpret_cast<int64_t>(CreateEventA());
                rax7->f0 = rax8;
                if (rax8) {
                    rcx->f48 = rax7;
                } else {
                    eax9 = reinterpret_cast<uint32_t>(GetLastError());
                    if (!reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<int32_t>(eax9) < reinterpret_cast<int32_t>(0)) | reinterpret_cast<uint1_t>(eax9 == 0))) {
                        *reinterpret_cast<uint32_t*>(&rbx5) = static_cast<uint32_t>(*reinterpret_cast<uint16_t*>(&eax9)) | 0x80070000;
                    } else {
                        *reinterpret_cast<uint32_t*>(&rbx5) = eax9;
                    }
                    if (*reinterpret_cast<int32_t*>(&rbx5) < reinterpret_cast<int32_t>(0)) {
                        rax10 = reinterpret_cast<int64_t>(GetProcessHeap());
                        HeapFree(rax10);
                    }
                }
            } else {
                *reinterpret_cast<uint32_t*>(&rbx5) = 0x8007000e;
            }
        } else {
            *reinterpret_cast<uint32_t*>(&rbx5) = 0x8009800f;
        }
    } else {
        *reinterpret_cast<uint32_t*>(&rbx5) = 0x80004003;
    }
    *reinterpret_cast<uint32_t*>(&r8_11) = *reinterpret_cast<uint32_t*>(&rbx5);
    *reinterpret_cast<int32_t*>(&r8_11 + 4) = 0;
    fun_1800010e0(2, "<<< SensorAdapterAttach : ErrorCode [0x%08X]", r8_11, 0, v12);
    *reinterpret_cast<uint32_t*>(&rax13) = *reinterpret_cast<uint32_t*>(&rbx5);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax13) + 4) = 0;
    return rax13;
}

void fun_1800025ff() {
    void** r8_1;
    void** r9_2;

    fun_1800010e0(2, " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_READY", r8_1, r9_2, __return_address());
    goto 0x180002655;
}

void fun_180003e15() {
    signed char* rax1;
    signed char* rax2;
    signed char al3;
    signed char* rsi4;
    signed char* rsi5;
    signed char bh6;
    signed char tmp8_7;
    signed char ah8;
    signed char* rax9;
    signed char* rax10;
    signed char al11;
    signed char* rax12;
    signed char* rax13;
    signed char al14;
    signed char* rax15;
    signed char* rax16;
    signed char al17;
    signed char* rax18;
    signed char* rax19;
    signed char* rax20;
    signed char al21;
    signed char* rax22;
    signed char* rax23;
    signed char al24;
    int32_t* rsi25;
    signed char* rax26;
    signed char* rax27;
    signed char al28;

    __asm__("outsb ");
    *rax1 = reinterpret_cast<signed char>(*rax2 + al3);
    *rsi4 = reinterpret_cast<signed char>(*rsi5 + bh6);
    tmp8_7 = reinterpret_cast<signed char>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g3c) + 2) + ah8);
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&g3c) + 2) = tmp8_7;
    *rax9 = reinterpret_cast<signed char>(*rax10 + al11);
    *rax12 = reinterpret_cast<signed char>(*rax13 + al14);
    *rax15 = reinterpret_cast<signed char>(*rax16 + al17);
    if (*rax18 >= 0) 
        goto 0x180003e6d;
    *rax19 = reinterpret_cast<signed char>(*rax20 + al21);
    *rax22 = reinterpret_cast<signed char>(*rax23 + al24);
    *reinterpret_cast<int32_t*>(&g0) = *rsi25;
    *rax26 = reinterpret_cast<signed char>(*rax27 + al28);
}

void fun_180003e81(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 13) = rdx;
    *reinterpret_cast<int32_t*>(rcx - 5) = *reinterpret_cast<int32_t*>(&rdx);
    *reinterpret_cast<signed char*>(rcx - 1) = *reinterpret_cast<signed char*>(&rdx);
    return;
}

struct s143 {
    signed char[64] pad64;
    int64_t f64;
};

int32_t fun_18000e740() {
    struct s143* rdx1;
    int1_t zf2;
    int32_t eax3;

    if (!rdx1->f64 && (zf2 = g180017238 == 0xffffffff, !zf2)) {
        eax3 = fun_180005204();
    }
    return eax3;
}

struct s144 {
    signed char[128] pad128;
    int32_t f128;
};

void fun_18000e7e1() {
    struct s144* rdx1;

    if (rdx1->f128) {
        fun_180008ad8(8);
    }
    return;
}

void fun_18000e837() {
    goto fun_180008ad8;
}

void fun_18000e923() {
    goto fun_180008ad8;
}

void fun_180002612() {
    void** r8_1;
    void** r9_2;

    fun_1800010e0(2, " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_NOT_CALIBRATED", r8_1, r9_2, __return_address());
    goto 0x180002655;
}

struct s145 {
    signed char[49] pad49;
    signed char f49;
};

struct s146 {
    signed char[49] pad49;
    signed char f49;
};

void* g9000031c6000031;

void fun_180003050(int16_t cx, int16_t dx) {
    int32_t* rcx1;
    void* rsp3;
    int64_t* rsp4;
    int32_t eax5;
    int64_t rax6;
    int64_t rdi7;
    int64_t rdi8;
    signed char* rbx9;
    signed char bh10;
    signed char bl11;
    signed char* rsi12;
    signed char* rsi13;
    signed char* rdi14;
    signed char* rdi15;
    int64_t rsi16;
    int64_t rsi17;
    signed char bl18;
    struct s145* rbp19;
    struct s146* rbp20;
    int32_t esi21;

    *reinterpret_cast<int16_t*>(&rcx1) = cx;
    rsp3 = __zero_stack_offset();
    *reinterpret_cast<int32_t*>(&rsp4) = eax5;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rsp4) + 4) = 0;
    *reinterpret_cast<void**>(&rax6) = *reinterpret_cast<void**>(&rsp3);
    *reinterpret_cast<signed char*>(rdi7 - 0x3bffffd0) = reinterpret_cast<signed char>(*reinterpret_cast<signed char*>(rdi8 - 0x3bffffd0) + *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rcx1) + 1));
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rcx1) + 1) = reinterpret_cast<signed char>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rcx1) + 1) + *reinterpret_cast<signed char*>(&rcx1));
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rbx9) + 1) = reinterpret_cast<signed char>(bh10 + bl11);
    *rsi12 = reinterpret_cast<signed char>(*rsi13 + *reinterpret_cast<signed char*>(&rcx1));
    *rbx9 = reinterpret_cast<signed char>(*rbx9 + *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rcx1) + 1));
    *rdi14 = reinterpret_cast<signed char>(*rdi15 + *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rbx9) + 1));
    *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(rcx1) + rsi16) = reinterpret_cast<signed char>(*reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(rcx1) + rsi17) + bl18);
    rbp19->f49 = reinterpret_cast<signed char>(rbp20->f49 + *reinterpret_cast<signed char*>(reinterpret_cast<int64_t>(&rcx1) + 1));
    *rcx1 = esi21;
    g9000031c6000031 = *reinterpret_cast<void**>(&rax6);
    goto *rsp4;
}

void fun_180003e8c(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 12) = rdx;
    *reinterpret_cast<int32_t*>(rcx - 4) = *reinterpret_cast<int32_t*>(&rdx);
    return;
}

void fun_18000e850() {
    goto fun_180008ad8;
}

void fun_18000e93c() {
    goto fun_180008ad8;
}

void fun_180002625() {
    void** r8_1;
    void** r9_2;

    fun_1800010e0(2, " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_FAILURE", r8_1, r9_2, __return_address());
    goto 0x180002655;
}

int64_t fun_180003098() {
    uint64_t rax1;
    unsigned char* rdx2;
    signed char* r10_3;
    int64_t r11_4;

    rax1 = *rdx2;
    *r10_3 = *reinterpret_cast<signed char*>(&rax1);
    return r11_4;
}

void fun_180003e94(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 10) = rdx;
    *reinterpret_cast<int16_t*>(rcx - 2) = *reinterpret_cast<int16_t*>(&rdx);
    return;
}

void fun_18000e869() {
    goto LeaveCriticalSection;
}

void fun_18000e955() {
    goto fun_180006c38;
}

int64_t fun_1800030a3() {
    uint64_t rax1;
    uint16_t* rdx2;
    int16_t* r10_3;
    int64_t r11_4;

    rax1 = *rdx2;
    *r10_3 = *reinterpret_cast<int16_t*>(&rax1);
    return r11_4;
}

void fun_180003e9d(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 9) = rdx;
    *reinterpret_cast<signed char*>(rcx - 1) = *reinterpret_cast<signed char*>(&rdx);
    return;
}

int64_t fun_18000e890(int32_t** rcx, int64_t rdx) {
    int32_t ecx3;
    int64_t rax4;

    ecx3 = 0;
    *reinterpret_cast<unsigned char*>(&ecx3) = reinterpret_cast<uint1_t>(**rcx == 0xc0000005);
    *reinterpret_cast<int32_t*>(&rax4) = ecx3;
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax4) + 4) = 0;
    return rax4;
}

void fun_18000e96d() {
    goto fun_180009a58;
}

struct s147 {
    signed char[1] pad1;
    uint16_t f1;
};

struct s148 {
    signed char[1] pad1;
    int16_t f1;
};

int64_t fun_1800030af() {
    uint64_t rax1;
    unsigned char* rdx2;
    uint64_t rcx3;
    struct s147* rdx4;
    signed char* r10_5;
    struct s148* r10_6;
    int64_t r11_7;

    rax1 = *rdx2;
    rcx3 = rdx4->f1;
    *r10_5 = *reinterpret_cast<signed char*>(&rax1);
    r10_6->f1 = *reinterpret_cast<int16_t*>(&rcx3);
    return r11_7;
}

void fun_180003ea5(int64_t rcx, int64_t rdx) {
    *reinterpret_cast<int64_t*>(rcx - 8) = rdx;
    return;
}

void fun_18000e8b0() {
    goto fun_18000559c;
}

void fun_18000e984() {
    signed char* rax1;
    signed char* rax2;
    signed char al3;
    signed char* rax4;
    signed char* rax5;
    signed char al6;
    signed char* rax7;
    signed char* rax8;
    signed char al9;
    signed char* rax10;
    signed char* rax11;
    signed char al12;
    signed char* rax13;
    signed char* rax14;
    signed char al15;
    signed char* rax16;
    signed char* rax17;
    signed char al18;
    signed char* rax19;
    signed char* rax20;
    signed char al21;
    signed char* rax22;
    signed char* rax23;
    signed char al24;
    signed char* rax25;
    signed char* rax26;
    signed char al27;
    signed char* rax28;
    signed char* rax29;
    signed char al30;
    signed char* rax31;
    signed char* rax32;
    signed char al33;
    signed char* rax34;
    signed char* rax35;
    signed char al36;
    signed char* rax37;
    signed char* rax38;
    signed char al39;
    signed char* rax40;
    signed char* rax41;
    signed char al42;
    signed char* rax43;
    signed char* rax44;
    signed char al45;
    signed char* rax46;
    signed char* rax47;
    signed char al48;
    signed char* rax49;
    signed char* rax50;
    signed char al51;
    signed char* rax52;
    signed char* rax53;
    signed char al54;
    signed char* rax55;
    signed char* rax56;
    signed char al57;
    signed char* rax58;
    signed char* rax59;
    signed char al60;
    signed char* rax61;
    signed char* rax62;
    signed char al63;
    signed char* rax64;
    signed char* rax65;
    signed char al66;
    signed char* rax67;
    signed char* rax68;
    signed char al69;
    signed char* rax70;
    signed char* rax71;
    signed char al72;
    signed char* rax73;
    signed char* rax74;
    signed char al75;
    signed char* rax76;
    signed char* rax77;
    signed char al78;
    signed char* rax79;
    signed char* rax80;
    signed char al81;
    signed char* rax82;
    signed char* rax83;
    signed char al84;
    signed char* rax85;
    signed char* rax86;
    signed char al87;
    signed char* rax88;
    signed char* rax89;
    signed char al90;
    signed char* rax91;
    signed char* rax92;
    signed char al93;
    signed char* rax94;
    signed char* rax95;
    signed char al96;
    signed char* rax97;
    signed char* rax98;
    signed char al99;
    signed char* rax100;
    signed char* rax101;
    signed char al102;
    signed char* rax103;
    signed char* rax104;
    signed char al105;
    signed char* rax106;
    signed char* rax107;
    signed char al108;
    signed char* rax109;
    signed char* rax110;
    signed char al111;
    signed char* rax112;
    signed char* rax113;
    signed char al114;
    signed char* rax115;
    signed char* rax116;
    signed char al117;
    signed char* rax118;
    signed char* rax119;
    signed char al120;
    signed char* rax121;
    signed char* rax122;
    signed char al123;
    signed char* rax124;
    signed char* rax125;
    signed char al126;
    signed char* rax127;
    signed char* rax128;
    signed char al129;
    signed char* rax130;
    signed char* rax131;
    signed char al132;
    signed char* rax133;
    signed char* rax134;
    signed char al135;
    signed char* rax136;
    signed char* rax137;
    signed char al138;
    signed char* rax139;
    signed char* rax140;
    signed char al141;
    signed char* rax142;
    signed char* rax143;
    signed char al144;
    signed char* rax145;
    signed char* rax146;
    signed char al147;
    signed char* rax148;
    signed char* rax149;
    signed char al150;
    signed char* rax151;
    signed char* rax152;
    signed char al153;
    signed char* rax154;
    signed char* rax155;
    signed char al156;
    signed char* rax157;
    signed char* rax158;
    signed char al159;
    signed char* rax160;
    signed char* rax161;
    signed char al162;
    signed char* rax163;
    signed char* rax164;
    signed char al165;
    signed char* rax166;
    signed char* rax167;
    signed char al168;
    signed char* rax169;
    signed char* rax170;
    signed char al171;
    signed char* rax172;
    signed char* rax173;
    signed char al174;
    signed char* rax175;
    signed char* rax176;
    signed char al177;
    signed char* rax178;
    signed char* rax179;
    signed char al180;
    signed char* rax181;
    signed char* rax182;
    signed char al183;
    signed char* rax184;
    signed char* rax185;
    signed char al186;

    *rax1 = reinterpret_cast<signed char>(*rax2 + al3);
    *rax4 = reinterpret_cast<signed char>(*rax5 + al6);
    *rax7 = reinterpret_cast<signed char>(*rax8 + al9);
    *rax10 = reinterpret_cast<signed char>(*rax11 + al12);
    *rax13 = reinterpret_cast<signed char>(*rax14 + al15);
    *rax16 = reinterpret_cast<signed char>(*rax17 + al18);
    *rax19 = reinterpret_cast<signed char>(*rax20 + al21);
    *rax22 = reinterpret_cast<signed char>(*rax23 + al24);
    *rax25 = reinterpret_cast<signed char>(*rax26 + al27);
    *rax28 = reinterpret_cast<signed char>(*rax29 + al30);
    *rax31 = reinterpret_cast<signed char>(*rax32 + al33);
    *rax34 = reinterpret_cast<signed char>(*rax35 + al36);
    *rax37 = reinterpret_cast<signed char>(*rax38 + al39);
    *rax40 = reinterpret_cast<signed char>(*rax41 + al42);
    *rax43 = reinterpret_cast<signed char>(*rax44 + al45);
    *rax46 = reinterpret_cast<signed char>(*rax47 + al48);
    *rax49 = reinterpret_cast<signed char>(*rax50 + al51);
    *rax52 = reinterpret_cast<signed char>(*rax53 + al54);
    *rax55 = reinterpret_cast<signed char>(*rax56 + al57);
    *rax58 = reinterpret_cast<signed char>(*rax59 + al60);
    *rax61 = reinterpret_cast<signed char>(*rax62 + al63);
    *rax64 = reinterpret_cast<signed char>(*rax65 + al66);
    *rax67 = reinterpret_cast<signed char>(*rax68 + al69);
    *rax70 = reinterpret_cast<signed char>(*rax71 + al72);
    *rax73 = reinterpret_cast<signed char>(*rax74 + al75);
    *rax76 = reinterpret_cast<signed char>(*rax77 + al78);
    *rax79 = reinterpret_cast<signed char>(*rax80 + al81);
    *rax82 = reinterpret_cast<signed char>(*rax83 + al84);
    *rax85 = reinterpret_cast<signed char>(*rax86 + al87);
    *rax88 = reinterpret_cast<signed char>(*rax89 + al90);
    *rax91 = reinterpret_cast<signed char>(*rax92 + al93);
    *rax94 = reinterpret_cast<signed char>(*rax95 + al96);
    *rax97 = reinterpret_cast<signed char>(*rax98 + al99);
    *rax100 = reinterpret_cast<signed char>(*rax101 + al102);
    *rax103 = reinterpret_cast<signed char>(*rax104 + al105);
    *rax106 = reinterpret_cast<signed char>(*rax107 + al108);
    *rax109 = reinterpret_cast<signed char>(*rax110 + al111);
    *rax112 = reinterpret_cast<signed char>(*rax113 + al114);
    *rax115 = reinterpret_cast<signed char>(*rax116 + al117);
    *rax118 = reinterpret_cast<signed char>(*rax119 + al120);
    *rax121 = reinterpret_cast<signed char>(*rax122 + al123);
    *rax124 = reinterpret_cast<signed char>(*rax125 + al126);
    *rax127 = reinterpret_cast<signed char>(*rax128 + al129);
    *rax130 = reinterpret_cast<signed char>(*rax131 + al132);
    *rax133 = reinterpret_cast<signed char>(*rax134 + al135);
    *rax136 = reinterpret_cast<signed char>(*rax137 + al138);
    *rax139 = reinterpret_cast<signed char>(*rax140 + al141);
    *rax142 = reinterpret_cast<signed char>(*rax143 + al144);
    *rax145 = reinterpret_cast<signed char>(*rax146 + al147);
    *rax148 = reinterpret_cast<signed char>(*rax149 + al150);
    *rax151 = reinterpret_cast<signed char>(*rax152 + al153);
    *rax154 = reinterpret_cast<signed char>(*rax155 + al156);
    *rax157 = reinterpret_cast<signed char>(*rax158 + al159);
    *rax160 = reinterpret_cast<signed char>(*rax161 + al162);
    *rax163 = reinterpret_cast<signed char>(*rax164 + al165);
    *rax166 = reinterpret_cast<signed char>(*rax167 + al168);
    *rax169 = reinterpret_cast<signed char>(*rax170 + al171);
    *rax172 = reinterpret_cast<signed char>(*rax173 + al174);
    *rax175 = reinterpret_cast<signed char>(*rax176 + al177);
    *rax178 = reinterpret_cast<signed char>(*rax179 + al180);
    *rax181 = reinterpret_cast<signed char>(*rax182 + al183);
    *rax184 = reinterpret_cast<signed char>(*rax185 + al186);
}

int64_t fun_1800030c4() {
    int32_t* r10_1;
    int32_t* rdx2;
    int64_t r11_3;

    *r10_1 = *rdx2;
    return r11_3;
}

struct s149 {
    signed char[56] pad56;
    unsigned char f56;
};

void** g180017220 = reinterpret_cast<void**>(0x80);

void** g180017228 = reinterpret_cast<void**>(0x88);

struct s150 {
    signed char[200] pad200;
    uint32_t f200;
};

struct s0* fun_180003eac(void** rcx, struct s105* rdx, void** r8, void*** r9) {
    void* rsp5;
    void* rbp6;
    void* rsp7;
    uint64_t rax8;
    uint64_t v9;
    void** v10;
    struct s105* rdi11;
    void*** r13_12;
    void** r14d13;
    void** v14;
    int64_t r12_15;
    void** v16;
    void** v17;
    void** rbx18;
    void** v19;
    void* rsp20;
    void** eax21;
    struct s149* r8_22;
    int64_t r10_23;
    struct s149* r9_24;
    int64_t rdx25;
    int64_t rdx26;
    int64_t rcx27;
    int64_t rcx28;
    void** r15_29;
    void** esi30;
    void** v31;
    void** v32;
    void** rdx33;
    void** v34;
    struct s105* v35;
    int32_t eax36;
    void** ecx37;
    void* rax38;
    void* rax39;
    void** v40;
    uint32_t eax41;
    void** ecx42;
    void** ecx43;
    void** ecx44;
    int64_t rax45;
    int64_t rcx46;
    int64_t rax47;
    void** eax48;
    void** eax49;
    void** ecx50;
    void** ecx51;
    int64_t r12_52;
    int64_t rax53;
    int64_t r12_54;
    void** ecx55;
    int64_t rcx56;
    void** rax57;
    void** rdi58;
    int32_t eax59;
    int64_t r9_60;
    int64_t rcx61;
    int64_t rax62;
    void** rdx63;
    int64_t rcx64;
    int64_t rax65;
    int64_t rcx66;
    int64_t rax67;
    void* rax68;
    void** edx69;
    void** r8_70;
    void*** r13_71;
    void*** v72;
    void* rbx73;
    void** ecx74;
    uint64_t rcx75;
    uint64_t rdx76;
    void* rax77;
    void** eax78;
    void** v79;
    void** eax80;
    void** rcx81;
    int64_t rcx82;
    void** rcx83;
    void** edi84;
    void* esi85;
    void** edi86;
    void** r15_87;
    uint32_t r9d88;
    void** eax89;
    void** v90;
    void** eax91;
    uint32_t r9d92;
    void** eax93;
    void** rax94;
    void** v95;
    struct s150* v96;
    uint64_t rcx97;
    struct s0* rax98;

    rsp5 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(__zero_stack_offset()) - 8 - 8 - 8 - 8 - 8 - 8 - 8);
    rbp6 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 0x1e0);
    rsp7 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rsp5) - 0x2e0);
    rax8 = g1800170a0;
    v9 = rax8 ^ reinterpret_cast<uint64_t>(rsp7);
    v10 = rcx;
    rdi11 = rdx;
    r13_12 = r9;
    r14d13 = reinterpret_cast<void**>(0);
    v14 = reinterpret_cast<void**>(0);
    *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0);
    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
    v16 = reinterpret_cast<void**>(0);
    v17 = reinterpret_cast<void**>(0);
    rbx18 = reinterpret_cast<void**>(0);
    *reinterpret_cast<int32_t*>(&rbx18 + 4) = 0;
    v19 = reinterpret_cast<void**>(0);
    fun_180003bc4(reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffffa8, r8);
    fun_1800039c8();
    rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp7) - 8 + 8 - 8 + 8);
    if (!rcx) 
        goto addr_18000487c_2;
    if (!(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(rcx + 24)) & 64)) {
        eax21 = fun_180006ca8(rcx, r8);
        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        r8_22 = reinterpret_cast<struct s149*>(0x180017240);
        r10_23 = reinterpret_cast<int32_t>(eax21);
        if (static_cast<uint32_t>(r10_23 + 2) <= 1) {
            r9_24 = reinterpret_cast<struct s149*>(0x180017240);
        } else {
            rdx25 = r10_23;
            *reinterpret_cast<uint32_t*>(&rdx26) = *reinterpret_cast<uint32_t*>(&rdx25) & 31;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rdx26) + 4) = 0;
            r9_24 = reinterpret_cast<struct s149*>(rdx26 * 88 + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(0x180000000 + (r10_23 >> 5) * 8 + 0x1d350)));
        }
        if (r9_24->f56 & 0x7f) 
            goto addr_18000487c_2;
        if (static_cast<uint32_t>(r10_23 + 2) > 1) {
            rcx27 = r10_23;
            *reinterpret_cast<uint32_t*>(&rcx28) = *reinterpret_cast<uint32_t*>(&rcx27) & 31;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx28) + 4) = 0;
            r8_22 = reinterpret_cast<struct s149*>(rcx28 * 88 + reinterpret_cast<int64_t>(*reinterpret_cast<void**>(reinterpret_cast<unsigned char>(0x180000000) + (r10_23 >> 5) * 8 + 0x1d350)));
        }
        if (r8_22->f56 & 0x80) 
            goto addr_18000487c_2;
    }
    if (!rdi11) 
        goto addr_18000487c_2;
    r15_29 = rdi11->f0;
    esi30 = reinterpret_cast<void**>(0);
    v31 = reinterpret_cast<void**>(0);
    v32 = reinterpret_cast<void**>(0);
    rdx33 = reinterpret_cast<void**>(0);
    v34 = reinterpret_cast<void**>(0);
    if (!r15_29) 
        goto addr_180004894_14;
    while (rdi11 = reinterpret_cast<struct s105*>(&rdi11->f1), v35 = rdi11, reinterpret_cast<signed char>(esi30) >= reinterpret_cast<signed char>(0)) {
        eax36 = static_cast<int32_t>(reinterpret_cast<uint64_t>(r15_29 + 0xffffffffffffffe0));
        if (*reinterpret_cast<unsigned char*>(&eax36) > 88) {
            ecx37 = reinterpret_cast<void**>(0);
        } else {
            ecx37 = reinterpret_cast<void**>(static_cast<uint32_t>(*reinterpret_cast<unsigned char*>(static_cast<int64_t>(reinterpret_cast<signed char>(r15_29)) + reinterpret_cast<unsigned char>(0x180000000) + 0x102e0)) & 15);
        }
        rax38 = reinterpret_cast<void*>(static_cast<int64_t>(reinterpret_cast<int32_t>(ecx37)));
        rax39 = reinterpret_cast<void*>(static_cast<int64_t>(reinterpret_cast<int32_t>(rdx33)));
        rdx33 = reinterpret_cast<void**>(static_cast<uint32_t>(*reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(reinterpret_cast<int64_t>(rax38) + reinterpret_cast<int64_t>(rax38) * 8 + reinterpret_cast<int64_t>(rax39) + reinterpret_cast<unsigned char>(0x180000000)) + 0x10300)) >> 4);
        *reinterpret_cast<int32_t*>(&rdx33 + 4) = 0;
        v40 = rdx33;
        if (rdx33 == 8) 
            goto addr_18000487c_2;
        if (!rdx33) {
            addr_180004735_22:
            v19 = reinterpret_cast<void**>(0);
            eax41 = fun_180008448(static_cast<uint32_t>(reinterpret_cast<unsigned char>(r15_29)), reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffffa8);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
            if (!eax41) 
                goto addr_18000476c_23;
            fun_1800048d4(r15_29, v10, reinterpret_cast<uint64_t>(rsp20) + 64, 0x180000000);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
            r15_29 = rdi11->f0;
            rdi11 = reinterpret_cast<struct s105*>(&rdi11->f1);
            if (!r15_29) 
                goto addr_18000487c_2;
        } else {
            ecx42 = rdx33 - 1;
            if (!ecx42) {
                v17 = reinterpret_cast<void**>(0);
                v14 = reinterpret_cast<void**>(0);
                v16 = reinterpret_cast<void**>(0);
                r14d13 = reinterpret_cast<void**>(0);
                *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0xffffffff);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                v19 = reinterpret_cast<void**>(0);
                goto addr_180004696_27;
            }
            ecx43 = ecx42 - 1;
            if (!ecx43) {
                if (r15_29 == 32) {
                    r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 2);
                    goto addr_180004696_27;
                } else {
                    if (r15_29 == 35) {
                        __asm__("bts r14d, 0x7");
                        goto addr_180004696_27;
                    } else {
                        if (r15_29 == 43) {
                            r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 1);
                            goto addr_180004696_27;
                        } else {
                            if (r15_29 == 45) {
                                r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 4);
                                goto addr_180004696_27;
                            } else {
                                if (reinterpret_cast<int1_t>(r15_29 == 48)) {
                                    r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 8);
                                    goto addr_180004696_27;
                                }
                            }
                        }
                    }
                }
            }
            ecx44 = ecx43 - 1;
            if (!ecx44) 
                goto addr_1800047c3_40; else 
                goto addr_18000406b_41;
        }
        addr_18000476c_23:
        fun_1800048d4(r15_29, v10, reinterpret_cast<uint64_t>(rsp20) + 64, 0x180000000);
        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        addr_180004681_42:
        esi30 = v31;
        rdx33 = v40;
        goto addr_180004696_27;
        addr_1800047c3_40:
        if (!reinterpret_cast<int1_t>(r15_29 == 42)) {
            *reinterpret_cast<void***>(&rax45) = v14;
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax45) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rcx46) = static_cast<int32_t>(rax45 + rax45 * 4);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx46) + 4) = 0;
            *reinterpret_cast<int32_t*>(&rax47) = reinterpret_cast<signed char>(r15_29);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax47) + 4) = 0;
            eax48 = reinterpret_cast<void**>(static_cast<int32_t>(rax47 + rcx46 * 2) + 0xffffffd0);
        } else {
            eax49 = *r13_12;
            r13_12 = r13_12 + 8;
            v14 = eax49;
            if (reinterpret_cast<signed char>(eax49) >= reinterpret_cast<signed char>(0)) {
                addr_180004696_27:
                r15_29 = rdi11->f0;
                if (!r15_29) 
                    break; else 
                    goto addr_1800046a2_45;
            } else {
                r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 4);
                eax48 = reinterpret_cast<void**>(-reinterpret_cast<unsigned char>(eax49));
            }
        }
        v14 = eax48;
        goto addr_180004696_27;
        addr_1800046a2_45:
        continue;
        addr_18000406b_41:
        ecx50 = ecx44 - 1;
        if (!ecx50) {
            *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0);
            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
            goto addr_180004696_27;
        }
        ecx51 = ecx50 - 1;
        if (!ecx51) {
            if (!reinterpret_cast<int1_t>(r15_29 == 42)) {
                *reinterpret_cast<int32_t*>(&r12_52) = static_cast<int32_t>(r12_15 + r12_15 * 4);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_52) + 4) = 0;
                *reinterpret_cast<int32_t*>(&rax53) = reinterpret_cast<signed char>(r15_29);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rax53) + 4) = 0;
                *reinterpret_cast<int32_t*>(&r12_54) = static_cast<int32_t>(r12_52 - 24);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_54) + 4) = 0;
                *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(static_cast<uint32_t>(rax53 + r12_54 * 2));
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                goto addr_180004696_27;
            } else {
                *reinterpret_cast<void***>(&r12_15) = *r13_12;
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                r13_12 = r13_12 + 8;
                if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r12_15)) < reinterpret_cast<signed char>(0)) {
                    *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0xffffffff);
                    *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                    goto addr_180004696_27;
                }
            }
        }
        ecx55 = ecx51 - 1;
        if (ecx55) 
            goto addr_180004083_55;
        if (r15_29 == 73) {
            __asm__("bts r14d, 0xf");
            if (!reinterpret_cast<int1_t>(rdi11->f0 == 54) || rdi11->f1 != 52) {
                if (!reinterpret_cast<int1_t>(rdi11->f0 == 51) || rdi11->f1 != 50) {
                    *reinterpret_cast<unsigned char*>(&rax39) = reinterpret_cast<unsigned char>(rdi11->f0 - 88);
                    if (*reinterpret_cast<unsigned char*>(&rax39) > 32) 
                        goto addr_180004730_60;
                    if (static_cast<int1_t>(0x120821001 >> reinterpret_cast<int64_t>(rax39))) 
                        goto addr_180004696_27;
                    addr_180004730_60:
                    v40 = reinterpret_cast<void**>(0);
                    goto addr_180004735_22;
                } else {
                    ++rdi11;
                    __asm__("btr r14d, 0xf");
                    goto addr_180004696_27;
                }
            } else {
                ++rdi11;
                __asm__("bts r14d, 0xf");
                goto addr_180004696_27;
            }
        } else {
            if (r15_29 == 0x68) {
                r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 32);
                goto addr_180004696_27;
            } else {
                if (r15_29 == 0x6c) {
                    if (!reinterpret_cast<int1_t>(rdi11->f0 == 0x6c)) {
                        r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 16);
                        goto addr_180004696_27;
                    } else {
                        rdi11 = reinterpret_cast<struct s105*>(&rdi11->f1);
                        __asm__("bts r14d, 0xc");
                        goto addr_180004696_27;
                    }
                } else {
                    if (reinterpret_cast<int1_t>(r15_29 == 0x77)) {
                        __asm__("bts r14d, 0xb");
                        goto addr_180004696_27;
                    }
                }
            }
        }
        addr_180004083_55:
        if (ecx55 - 1) 
            goto addr_180004696_27;
        *reinterpret_cast<uint32_t*>(&rcx56) = reinterpret_cast<uint32_t>(static_cast<int32_t>(reinterpret_cast<signed char>(r15_29)));
        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&rcx56) + 4) = 0;
        if (*reinterpret_cast<int32_t*>(&rcx56) <= reinterpret_cast<int32_t>(100)) 
            goto addr_180004098_73;
        if (*reinterpret_cast<int32_t*>(&rcx56) <= reinterpret_cast<int32_t>(0x67)) {
            addr_1800041e2_75:
            r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 64);
            rbx18 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffffd0);
            if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r12_15)) >= reinterpret_cast<signed char>(0)) {
                if (*reinterpret_cast<void***>(&r12_15)) {
                    if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r12_15)) > reinterpret_cast<signed char>(0x200)) {
                        *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0x200);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                    }
                    if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r12_15)) > reinterpret_cast<signed char>(0xa3)) {
                        rax57 = fun_180006770(static_cast<int64_t>(static_cast<int32_t>(r12_15 + 0x15d)), rdx33);
                        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                        v34 = rax57;
                        if (!rax57) {
                            *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0xa3);
                            *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                        } else {
                            rbx18 = rax57;
                        }
                    }
                } else {
                    if (reinterpret_cast<int1_t>(r15_29 == 0x67)) {
                        *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(1);
                        *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
                    }
                }
            } else {
                *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(6);
                *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0;
            }
        } else {
            if (*reinterpret_cast<uint32_t*>(&rcx56) == 0x69) {
                addr_1800042f9_87:
                r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | 64);
                goto addr_1800042fd_88;
            } else {
                if (*reinterpret_cast<uint32_t*>(&rcx56) == 0x6e) {
                    rdi58 = *r13_12;
                    r13_12 = r13_12 + 8;
                    eax59 = fun_180008598();
                    rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                    if (!eax59) 
                        goto addr_18000487c_2;
                    if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 32)) 
                        goto addr_1800042ea_92; else 
                        goto addr_1800042e5_93;
                } else {
                    if (*reinterpret_cast<uint32_t*>(&rcx56) == 0x6f) {
                        *reinterpret_cast<int32_t*>(&r9_60) = 8;
                        if (*reinterpret_cast<signed char*>(&r14d13) < reinterpret_cast<signed char>(0)) {
                            r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) | reinterpret_cast<unsigned char>(0x200));
                            goto addr_180004303_97;
                        }
                    }
                    if (*reinterpret_cast<uint32_t*>(&rcx56) == 0x70) 
                        goto addr_180004287_99; else 
                        goto addr_180004226_100;
                }
            }
        }
        rcx61 = g180018010;
        r13_12 = r13_12 + 8;
        rax62 = reinterpret_cast<int64_t>(DecodePointer(rcx61));
        rdx63 = rbx18;
        rax62(reinterpret_cast<int64_t>(rbp6) - 96, rdx63);
        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8 - 8 + 8);
        if (!1 && !*reinterpret_cast<void***>(&r12_15)) {
            rcx64 = g180018028;
            rax65 = reinterpret_cast<int64_t>(DecodePointer(rcx64, rdx63));
            rdx63 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffffa8);
            rax65(rbx18, rdx63);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8 - 8 + 8);
        }
        if (reinterpret_cast<int1_t>(r15_29 == 0x67) && !0) {
            rcx66 = g180018020;
            rax67 = reinterpret_cast<int64_t>(DecodePointer(rcx66, rdx63));
            rax67(rbx18, reinterpret_cast<int64_t>(rbp6) - 88);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8 - 8 + 8);
        }
        if (reinterpret_cast<int1_t>(*reinterpret_cast<void***>(rbx18) == 45)) {
            __asm__("bts r14d, 0x8");
            ++rbx18;
        }
        addr_1800044f5_107:
        rax68 = fun_1800084f0(rbx18, rbx18);
        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        addr_180004500_108:
        v32 = *reinterpret_cast<void***>(&rax68);
        goto addr_180004504_109;
        addr_1800042ea_92:
        *reinterpret_cast<void***>(rdi58) = esi30;
        addr_1800042ec_110:
        v17 = reinterpret_cast<void**>(1);
        goto addr_180004665_111;
        addr_1800042e5_93:
        *reinterpret_cast<void***>(rdi58) = esi30;
        goto addr_1800042ec_110;
        addr_180004287_99:
        *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(16);
        __asm__("bts r14d, 0xf");
        addr_180004292_112:
        addr_180004297_113:
        *reinterpret_cast<int32_t*>(&r9_60) = 16;
        if (*reinterpret_cast<signed char*>(&r14d13) >= reinterpret_cast<signed char>(0)) {
            addr_180004303_97:
            edx69 = v16;
        } else {
            edx69 = reinterpret_cast<void**>(2);
        }
        if (static_cast<int1_t>(!1)) {
            r8_70 = *r13_12;
            r13_71 = r13_12 + 8;
        } else {
            r13_71 = r13_12 + 8;
            if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 32)) {
                if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 64)) {
                    r8_70 = *(r13_71 - 8);
                    *reinterpret_cast<int32_t*>(&r8_70 + 4) = 0;
                } else {
                    r8_70 = reinterpret_cast<void**>(static_cast<int64_t>(reinterpret_cast<int32_t>(*(r13_71 - 8))));
                }
            } else {
                v72 = r13_71;
                if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 64)) {
                    r8_70 = reinterpret_cast<void**>(static_cast<uint32_t>(reinterpret_cast<uint16_t>(*(r13_71 - 8))));
                    *reinterpret_cast<int32_t*>(&r8_70 + 4) = 0;
                    goto addr_18000435a_123;
                } else {
                    r8_70 = reinterpret_cast<void**>(static_cast<int64_t>(reinterpret_cast<int16_t>(*(r13_71 - 8))));
                    goto addr_18000435a_123;
                }
            }
        }
        v72 = r13_71;
        addr_18000435a_123:
        if (*reinterpret_cast<unsigned char*>(&r14d13) & 64 && reinterpret_cast<signed char>(r8_70) < reinterpret_cast<signed char>(0)) {
            r8_70 = reinterpret_cast<void**>(-reinterpret_cast<unsigned char>(r8_70));
            __asm__("bts r14d, 0x8");
        }
        if (!0 && !0) {
            r8_70 = r8_70;
            *reinterpret_cast<int32_t*>(&r8_70 + 4) = 0;
        }
        if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r12_15)) >= reinterpret_cast<signed char>(0)) {
            r14d13 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r14d13) & 0xfffffff7);
            if (reinterpret_cast<signed char>(*reinterpret_cast<void***>(&r12_15)) > reinterpret_cast<signed char>(0x200)) {
                *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(0x200);
            }
        } else {
            *reinterpret_cast<void***>(&r12_15) = reinterpret_cast<void**>(1);
        }
        rbx73 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp6) + 0x1cf);
        v16 = reinterpret_cast<void**>(*reinterpret_cast<uint32_t*>(&rcx56) - (*reinterpret_cast<uint32_t*>(&rcx56) + reinterpret_cast<uint1_t>(*reinterpret_cast<uint32_t*>(&rcx56) < *reinterpret_cast<uint32_t*>(&rcx56) + reinterpret_cast<uint1_t>(!!r8_70))) & reinterpret_cast<unsigned char>(edx69));
        while ((ecx74 = *reinterpret_cast<void***>(&r12_15), *reinterpret_cast<void***>(&r12_15) = *reinterpret_cast<void***>(&r12_15) - 1, *reinterpret_cast<int32_t*>(reinterpret_cast<int64_t>(&r12_15) + 4) = 0, !reinterpret_cast<uint1_t>(reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(ecx74) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(ecx74 == 0))) || r8_70) {
            rcx75 = reinterpret_cast<uint64_t>(static_cast<int64_t>(*reinterpret_cast<int32_t*>(&r9_60)));
            rdx76 = reinterpret_cast<unsigned char>(r8_70) % rcx75;
            r8_70 = reinterpret_cast<void**>(reinterpret_cast<unsigned char>(r8_70) / rcx75);
            if (static_cast<int32_t>(rdx76 + 48) > 57) {
            }
            rbx73 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbx73) - 1);
        }
        r13_12 = v72;
        rax77 = reinterpret_cast<void*>(reinterpret_cast<int64_t>(rbp6) + 0x1cf);
        eax78 = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rax77)) - reinterpret_cast<uint32_t>(*reinterpret_cast<void**>(&rbx73)));
        rbx18 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbx73) + 1);
        v32 = eax78;
        if (reinterpret_cast<unsigned char>(0x200) & reinterpret_cast<unsigned char>(r14d13) && (!eax78 || v79 != 48)) {
            --rbx18;
            ++v32;
            goto addr_180004504_109;
        }
        addr_180004226_100:
        if (*reinterpret_cast<uint32_t*>(&rcx56) == 0x73) {
            addr_18000413e_140:
            rbx18 = *r13_12;
            eax80 = *reinterpret_cast<void***>(&r12_15);
            if (*reinterpret_cast<void***>(&r12_15) == 0xffffffff) {
                eax80 = reinterpret_cast<void**>(0x7fffffff);
            }
        } else {
            if (*reinterpret_cast<uint32_t*>(&rcx56) == 0x75) {
                addr_1800042fd_88:
                *reinterpret_cast<int32_t*>(&r9_60) = 10;
                goto addr_180004303_97;
            } else {
                if (*reinterpret_cast<uint32_t*>(&rcx56) != 0x78) {
                    addr_180004504_109:
                    if (v17) {
                        addr_180004665_111:
                        if (v34) {
                            fun_180005f00(v34, v34);
                            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                            v34 = reinterpret_cast<void**>(0);
                            goto addr_18000467d_145;
                        }
                    } else {
                        if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 64)) 
                            goto addr_180004546_147;
                        if (1) 
                            goto addr_180004523_149; else 
                            goto addr_18000451c_150;
                    }
                } else {
                    goto addr_180004297_113;
                }
            }
        }
        r13_12 = r13_12 + 8;
        if (!(reinterpret_cast<unsigned char>(r14d13) & 0x810)) {
            if (!rbx18) {
                rbx18 = g180017220;
            }
            rcx81 = rbx18;
            while (eax80 && (--eax80, !!*reinterpret_cast<void***>(rcx81))) {
                ++rcx81;
            }
            *reinterpret_cast<void***>(&rcx82) = reinterpret_cast<void**>(reinterpret_cast<int32_t>(*reinterpret_cast<void**>(&rcx81)) - reinterpret_cast<unsigned char>(rbx18));
        } else {
            v19 = reinterpret_cast<void**>(1);
            if (!rbx18) {
                rbx18 = g180017228;
            }
            rcx83 = rbx18;
            while (eax80 && (--eax80, !!*reinterpret_cast<void***>(rcx83))) {
                rcx83 = rcx83 + 2;
            }
            rcx82 = reinterpret_cast<int64_t>(reinterpret_cast<unsigned char>(rcx83) - reinterpret_cast<unsigned char>(rbx18)) >> 1;
        }
        v32 = *reinterpret_cast<void***>(&rcx82);
        goto addr_180004504_109;
        addr_18000467d_145:
        rdi11 = v35;
        goto addr_180004681_42;
        addr_180004523_149:
        if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 1)) {
            if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 2)) {
                addr_180004546_147:
                edi84 = v16;
            } else {
                goto addr_18000452e_168;
            }
        } else {
            goto addr_18000452e_168;
        }
        addr_18000454a_170:
        r15_29 = v10;
        esi85 = reinterpret_cast<void*>(reinterpret_cast<unsigned char>(v14) - reinterpret_cast<unsigned char>(v32) - reinterpret_cast<unsigned char>(edi84));
        if (!(*reinterpret_cast<unsigned char*>(&r14d13) & 12)) {
            fun_18000491c(32, esi85, r15_29, reinterpret_cast<uint64_t>(rsp20) + 64);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        }
        fun_180004970(reinterpret_cast<uint64_t>(rsp20) + 76, edi84, r15_29, reinterpret_cast<uint64_t>(rsp20) + 64);
        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        if (*reinterpret_cast<unsigned char*>(&r14d13) & 8 && !(*reinterpret_cast<unsigned char*>(&r14d13) & 4)) {
            fun_18000491c(48, esi85, r15_29, reinterpret_cast<uint64_t>(rsp20) + 64);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        }
        edi86 = v32;
        if (!v19 || reinterpret_cast<uint1_t>(reinterpret_cast<signed char>(edi86) < reinterpret_cast<signed char>(0)) | reinterpret_cast<uint1_t>(edi86 == 0)) {
            fun_180004970(rbx18, edi86, r15_29, reinterpret_cast<uint64_t>(rsp20) + 64);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
        } else {
            r15_87 = rbx18;
            do {
                r9d88 = reinterpret_cast<uint16_t>(*reinterpret_cast<void***>(r15_87));
                --edi86;
                r15_87 = r15_87 + 2;
                eax89 = fun_18000873c(reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffff90, reinterpret_cast<int64_t>(rbp6) + 0x1d0, 6, *reinterpret_cast<uint16_t*>(&r9d88));
                rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
                if (eax89) 
                    goto addr_180004617_178;
                if (!v90) 
                    goto addr_180004617_178;
                fun_180004970(reinterpret_cast<int64_t>(rbp6) + 0x1d0, v90, v10, reinterpret_cast<uint64_t>(rsp20) + 64);
                rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
            } while (edi86);
            goto addr_180004610_181;
        }
        addr_180004643_182:
        eax91 = v31;
        addr_180004647_183:
        if (reinterpret_cast<signed char>(eax91) >= reinterpret_cast<signed char>(0) && *reinterpret_cast<unsigned char*>(&r14d13) & 4) {
            fun_18000491c(32, esi85, r15_29, reinterpret_cast<uint64_t>(rsp20) + 64);
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
            goto addr_180004665_111;
        }
        addr_180004617_178:
        r15_29 = v10;
        eax91 = reinterpret_cast<void**>(0xffffffff);
        v31 = reinterpret_cast<void**>(0xffffffff);
        goto addr_180004647_183;
        addr_180004610_181:
        r15_29 = v10;
        goto addr_180004643_182;
        addr_18000452e_168:
        edi84 = reinterpret_cast<void**>(1);
        v16 = reinterpret_cast<void**>(1);
        goto addr_18000454a_170;
        addr_18000451c_150:
        goto addr_18000452e_168;
        addr_180004098_73:
        if (*reinterpret_cast<uint32_t*>(&rcx56) == 100) 
            goto addr_1800042f9_87;
        if (*reinterpret_cast<uint32_t*>(&rcx56) == 65) 
            goto addr_1800041d6_186;
        if (*reinterpret_cast<uint32_t*>(&rcx56) == 67) {
            if (!(reinterpret_cast<unsigned char>(r14d13) & 0x830)) {
                __asm__("bts r14d, 0xb");
            }
        } else {
            if (!(static_cast<uint32_t>(rcx56 - 69) & 0xfffffffd)) {
                addr_1800041d6_186:
                r15_29 = r15_29 + 32;
                goto addr_1800041e2_75;
            } else {
                if (*reinterpret_cast<uint32_t*>(&rcx56) == 83) {
                    if (!(reinterpret_cast<unsigned char>(r14d13) & 0x830)) {
                        __asm__("bts r14d, 0xb");
                        goto addr_18000413e_140;
                    }
                }
                if (*reinterpret_cast<uint32_t*>(&rcx56) == 88) 
                    goto addr_180004292_112; else 
                    goto addr_1800040cc_195;
            }
        }
        r13_12 = r13_12 + 8;
        if (!(reinterpret_cast<unsigned char>(r14d13) & 0x810)) {
            v32 = reinterpret_cast<void**>(1);
        } else {
            r9d92 = reinterpret_cast<uint16_t>(*(r13_12 - 8));
            eax93 = fun_18000873c(reinterpret_cast<uint64_t>(rsp20) + 68, reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffffd0, 0x200, *reinterpret_cast<uint16_t*>(&r9d92));
            rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8);
            if (eax93) {
                v17 = reinterpret_cast<void**>(1);
            }
        }
        rbx18 = reinterpret_cast<void**>(reinterpret_cast<int64_t>(rbp6) + 0xffffffffffffffd0);
        goto addr_180004504_109;
        addr_1800040cc_195:
        if (*reinterpret_cast<uint32_t*>(&rcx56) == 90) {
            r13_12 = r13_12 + 8;
            if (!*r13_12 || (rbx18 = *reinterpret_cast<void***>(*r13_12 + 8), rbx18 == 0)) {
                rbx18 = g180017220;
                goto addr_1800044f5_107;
            } else {
                *reinterpret_cast<void***>(&rax68) = reinterpret_cast<void**>(static_cast<int32_t>(reinterpret_cast<int16_t>(*reinterpret_cast<void***>(*r13_12))));
                if (1) {
                    v19 = reinterpret_cast<void**>(0);
                    goto addr_180004500_108;
                } else {
                    __asm__("cdq ");
                    v19 = reinterpret_cast<void**>(1);
                    *reinterpret_cast<void***>(&rax68) = reinterpret_cast<void**>(reinterpret_cast<int32_t>(reinterpret_cast<unsigned char>(*reinterpret_cast<void***>(&rax68)) - reinterpret_cast<unsigned char>(rdx33)) >> 1);
                    goto addr_180004500_108;
                }
            }
        } else {
            if (*reinterpret_cast<uint32_t*>(&rcx56) == 97) 
                goto addr_1800041e2_75;
            if (*reinterpret_cast<uint32_t*>(&rcx56) != 99) {
                goto addr_180004504_109;
            }
        }
    }
    if (!rdx33 || rdx33 == 7) {
        addr_180004894_14:
    } else {
        addr_18000487c_2:
        rax94 = fun_1800039c8();
        *reinterpret_cast<void***>(rax94) = reinterpret_cast<void**>(22);
        fun_1800038fc();
        rsp20 = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(rsp20) - 8 + 8 - 8 + 8);
    }
    if (v95) {
        v96->f200 = v96->f200 & 0xfffffffd;
    }
    rcx97 = v9 ^ reinterpret_cast<uint64_t>(rsp20);
    rax98 = fun_180002f40(rcx97, rcx97);
    return rax98;
}

struct s151 {
    signed char[96] pad96;
    int32_t f96;
};

void fun_18000e8c4() {
    struct s151* rdx1;

    if (rdx1->f96) {
        fun_180008ad8(0);
    }
    return;
}

struct s152 {
    signed char[1] pad1;
    int32_t f1;
};

struct s153 {
    signed char[1] pad1;
    int32_t f1;
};

int64_t fun_1800030cd() {
    uint64_t rax1;
    unsigned char* rdx2;
    int32_t ecx3;
    struct s152* rdx4;
    signed char* r10_5;
    struct s153* r10_6;
    int64_t r11_7;

    rax1 = *rdx2;
    ecx3 = rdx4->f1;
    *r10_5 = *reinterpret_cast<signed char*>(&rax1);
    r10_6->f1 = ecx3;
    return r11_7;
}

struct s154 {
    signed char[2] pad2;
    int32_t f2;
};

struct s155 {
    signed char[2] pad2;
    int32_t f2;
};

int64_t fun_1800030df() {
    uint64_t rax1;
    uint16_t* rdx2;
    int32_t ecx3;
    struct s154* rdx4;
    int16_t* r10_5;
    struct s155* r10_6;
    int64_t r11_7;

    rax1 = *rdx2;
    ecx3 = rdx4->f2;
    *r10_5 = *reinterpret_cast<int16_t*>(&rax1);
    r10_6->f2 = ecx3;
    return r11_7;
}

struct s156 {
    signed char[1] pad1;
    uint16_t f1;
};

struct s157 {
    signed char[3] pad3;
    int32_t f3;
};

struct s158 {
    signed char[1] pad1;
    int16_t f1;
};

struct s159 {
    signed char[3] pad3;
    int32_t f3;
};

int64_t fun_1800030f2() {
    uint64_t rax1;
    unsigned char* rdx2;
    uint64_t rcx3;
    struct s156* rdx4;
    int32_t edx5;
    struct s157* rdx6;
    signed char* r10_7;
    struct s158* r10_8;
    struct s159* r10_9;
    int64_t r11_10;

    rax1 = *rdx2;
    rcx3 = rdx4->f1;
    edx5 = rdx6->f3;
    *r10_7 = *reinterpret_cast<signed char*>(&rax1);
    r10_8->f1 = *reinterpret_cast<int16_t*>(&rcx3);
    r10_9->f3 = edx5;
    return r11_10;
}

int64_t fun_18000310e() {
    int64_t* r10_1;
    int64_t* rdx2;
    int64_t r11_3;

    *r10_1 = *rdx2;
    return r11_3;
}

struct s160 {
    signed char[1] pad1;
    int64_t f1;
};

struct s161 {
    signed char[1] pad1;
    int64_t f1;
};

int64_t fun_180003118() {
    uint64_t rax1;
    unsigned char* rdx2;
    int64_t rcx3;
    struct s160* rdx4;
    signed char* r10_5;
    struct s161* r10_6;
    int64_t r11_7;

    rax1 = *rdx2;
    rcx3 = rdx4->f1;
    *r10_5 = *reinterpret_cast<signed char*>(&rax1);
    r10_6->f1 = rcx3;
    return r11_7;
}

struct s162 {
    signed char[2] pad2;
    int64_t f2;
};

struct s163 {
    signed char[2] pad2;
    int64_t f2;
};

int64_t fun_18000312b() {
    uint64_t rax1;
    uint16_t* rdx2;
    int64_t rcx3;
    struct s162* rdx4;
    int16_t* r10_5;
    struct s163* r10_6;
    int64_t r11_7;

    rax1 = *rdx2;
    rcx3 = rdx4->f2;
    *r10_5 = *reinterpret_cast<int16_t*>(&rax1);
    r10_6->f2 = rcx3;
    return r11_7;
}

struct s164 {
    signed char[1] pad1;
    uint16_t f1;
};

struct s165 {
    signed char[3] pad3;
    int64_t f3;
};

struct s166 {
    signed char[1] pad1;
    int16_t f1;
};

struct s167 {
    signed char[3] pad3;
    int64_t f3;
};

int64_t fun_18000313f() {
    uint64_t rax1;
    unsigned char* rdx2;
    uint64_t rcx3;
    struct s164* rdx4;
    int64_t rdx5;
    struct s165* rdx6;
    signed char* r10_7;
    struct s166* r10_8;
    struct s167* r10_9;
    int64_t r11_10;

    rax1 = *rdx2;
    rcx3 = rdx4->f1;
    rdx5 = rdx6->f3;
    *r10_7 = *reinterpret_cast<signed char*>(&rax1);
    r10_8->f1 = *reinterpret_cast<int16_t*>(&rcx3);
    r10_9->f3 = rdx5;
    return r11_10;
}

struct s168 {
    signed char[4] pad4;
    int64_t f4;
};

struct s169 {
    signed char[4] pad4;
    int64_t f4;
};

int64_t fun_18000315c() {
    int64_t rcx1;
    struct s168* rdx2;
    int32_t* r10_3;
    int32_t* rdx4;
    struct s169* r10_5;
    int64_t r11_6;

    rcx1 = rdx2->f4;
    *r10_3 = *rdx4;
    r10_5->f4 = rcx1;
    return r11_6;
}

struct s170 {
    signed char[1] pad1;
    int32_t f1;
};

struct s171 {
    signed char[5] pad5;
    int64_t f5;
};

struct s172 {
    signed char[1] pad1;
    int32_t f1;
};

struct s173 {
    signed char[5] pad5;
    int64_t f5;
};

int64_t fun_18000316d() {
    uint64_t rax1;
    unsigned char* rdx2;
    int32_t ecx3;
    struct s170* rdx4;
    int64_t rdx5;
    struct s171* rdx6;
    signed char* r10_7;
    struct s172* r10_8;
    struct s173* r10_9;
    int64_t r11_10;

    rax1 = *rdx2;
    ecx3 = rdx4->f1;
    rdx5 = rdx6->f5;
    *r10_7 = *reinterpret_cast<signed char*>(&rax1);
    r10_8->f1 = ecx3;
    r10_9->f5 = rdx5;
    return r11_10;
}

struct s174 {
    signed char[2] pad2;
    int32_t f2;
};

struct s175 {
    signed char[6] pad6;
    int64_t f6;
};

struct s176 {
    signed char[2] pad2;
    int32_t f2;
};

struct s177 {
    signed char[6] pad6;
    int64_t f6;
};

int64_t fun_180003187() {
    uint64_t rax1;
    uint16_t* rdx2;
    int32_t ecx3;
    struct s174* rdx4;
    int64_t rdx5;
    struct s175* rdx6;
    int16_t* r10_7;
    struct s176* r10_8;
    struct s177* r10_9;
    int64_t r11_10;

    rax1 = *rdx2;
    ecx3 = rdx4->f2;
    rdx5 = rdx6->f6;
    *r10_7 = *reinterpret_cast<int16_t*>(&rax1);
    r10_8->f2 = ecx3;
    r10_9->f6 = rdx5;
    return r11_10;
}

struct s178 {
    signed char[1] pad1;
    uint16_t f1;
};

struct s179 {
    signed char[3] pad3;
    int32_t f3;
};

struct s180 {
    signed char[7] pad7;
    int64_t f7;
};

struct s181 {
    signed char[1] pad1;
    int16_t f1;
};

struct s182 {
    signed char[3] pad3;
    int32_t f3;
};

struct s183 {
    signed char[7] pad7;
    int64_t f7;
};

int64_t fun_1800031a2() {
    uint64_t r8_1;
    unsigned char* rdx2;
    uint64_t rax3;
    struct s178* rdx4;
    int32_t ecx5;
    struct s179* rdx6;
    int64_t rdx7;
    struct s180* rdx8;
    signed char* r10_9;
    struct s181* r10_10;
    struct s182* r10_11;
    struct s183* r10_12;
    int64_t r11_13;

    r8_1 = *rdx2;
    rax3 = rdx4->f1;
    ecx5 = rdx6->f3;
    rdx7 = rdx8->f7;
    *r10_9 = *reinterpret_cast<signed char*>(&r8_1);
    r10_10->f1 = *reinterpret_cast<int16_t*>(&rax3);
    r10_11->f3 = ecx5;
    r10_12->f7 = rdx7;
    return r11_13;
}

int64_t fun_1800031c6() {
    int64_t r11_1;

    __asm__("movdqu xmm0, [rdx]");
    __asm__("movdqu [r10], xmm0");
    return r11_1;
}
