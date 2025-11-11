/*
 * MIT License
 * Copyright (c) 2025 qn 
 */

#ifndef INVOKESHIELD_HPP
#define INVOKESHIELD_HPP

#include <type_traits>
#include <utility>
#include <cstdint>

namespace ivs {
    
    template<std::size_t N>
    struct ct_rnd {
        static constexpr std::size_t mix(std::size_t x) {
            x ^= x >> 33;
            x *= 0xff51afd7ed558ccdULL;
            x ^= x >> 33;
            x *= 0xc4ceb9fe1a85ec53ULL;
            x ^= x >> 33;
            return x;
        }
        static constexpr std::size_t value = mix(N * 0x9e3779b97f4a7c15ULL);
    };
    
    template<typename T, std::size_t Key>
    struct enc_val {
        T data;
        constexpr enc_val(T v) : data(v ^ Key) {}
        constexpr T dec() const { return data ^ Key; }
    };
    
    template<typename P, std::size_t Key>
    class ptr_guard {
        std::uintptr_t ptr;
    public:
        constexpr ptr_guard(P p)
            : ptr(reinterpret_cast<std::uintptr_t>(p) ^ Key) {}
        P get() const { 
            volatile std::uintptr_t x = ptr ^ Key;
            return reinterpret_cast<P>(x);
        }
    };
    
    template<typename R, typename F>
    struct call_ctx {
        F func;
        std::size_t check;
        
        static_assert(!std::is_void<R>::value, "call_ctx does not support void return type");
        
        constexpr call_ctx(F f, std::size_t c) : func(f), check(c) {}
        
        template<typename... Args>
        R invoke(Args&&... args) const {
            volatile std::size_t v = check;
            if (v == 0) return R{};
            return func(std::forward<Args>(args)...);
        }
    };
    
    template<typename R, typename F>
    constexpr auto make_ctx(F&& f, std::size_t check) {
        return call_ctx<R, F>(std::forward<F>(f), check);
    }
    
    template<typename P, std::size_t Key1, std::size_t Key2>
    struct dual_guard {
        std::uintptr_t p1, p2;
        
        constexpr dual_guard(P ptr) 
            : p1(reinterpret_cast<std::uintptr_t>(ptr) ^ Key1)
            , p2(reinterpret_cast<std::uintptr_t>(ptr) ^ Key2) {}
        
        P get() const {
            volatile std::uintptr_t a = p1 ^ Key1;
            volatile std::uintptr_t b = p2 ^ Key2;
            return (a == b) ? reinterpret_cast<P>(a) : nullptr;
        }
    };
    
    template<typename T, std::size_t... Keys>
    struct multi_enc;
    
    template<typename T, std::size_t K1, std::size_t K2>
    struct multi_enc<T, K1, K2> {
        T d1, d2;
        constexpr multi_enc(T v) : d1(v ^ K1), d2(v ^ K2) {}
        T dec() const {
            volatile T a = d1 ^ K1;
            volatile T b = d2 ^ K2;
            return (a == b) ? a : T{};
        }
    };
    
    template<typename T, std::size_t K1, std::size_t K2, std::size_t K3>
    struct multi_enc<T, K1, K2, K3> {
        T d1, d2, d3;
        constexpr multi_enc(T v) : d1(v ^ K1), d2(v ^ K2), d3(v ^ K3) {}
        T dec() const {
            volatile T a = d1 ^ K1;
            volatile T b = d2 ^ K2;
            volatile T c = d3 ^ K3;
            if (a != b || b != c) return T{};
            return a;
        }
    };
    
    template<std::size_t Key>
    struct scramble {
        static constexpr std::size_t apply(std::size_t x) {
            return (x ^ Key) * 0x517cc1b727220a95ULL;
        }
    };
}

#define IVS_CALL(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t key = ivs::ct_rnd<__COUNTER__>::value; \
        auto ctx = ivs::make_ctx<ret>([&]() { return func(__VA_ARGS__); }, key); \
        return ctx.invoke(); \
    }()

#define IVS_PROTECTED(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        using fn_t = ret(*)(__VA_ARGS__); \
        fn_t fptr = &func; \
        ivs::ptr_guard<fn_t, k1> pg(fptr); \
        auto real_fn = pg.get(); \
        ivs::enc_val<std::size_t, k2> chk(k2); \
        if (chk.dec() == k2) return real_fn(__VA_ARGS__); \
        return ret{}; \
    }()

#define IVS_VCALL(ret, obj, idx, ...) \
    [&]() -> ret { \
        constexpr std::size_t key = ivs::ct_rnd<__COUNTER__>::value; \
        using fn_t = ret(*)(__int64, ##__VA_ARGS__); \
        auto vt_ptr = *reinterpret_cast<std::uintptr_t*>(reinterpret_cast<std::uintptr_t>(obj)); \
        auto fn_ptr = *(reinterpret_cast<std::uintptr_t*>(vt_ptr) + idx); \
        auto typed = reinterpret_cast<fn_t>(fn_ptr); \
        ivs::ptr_guard<fn_t, key> pg(typed); \
        auto fn = pg.get(); \
        return fn(reinterpret_cast<__int64>(obj), ##__VA_ARGS__); \
    }()

#define IVS_INDIRECT(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k = ivs::ct_rnd<__COUNTER__ + __LINE__>::value; \
        using fn_t = ret(*)(__VA_ARGS__); \
        volatile std::uintptr_t p = reinterpret_cast<std::uintptr_t>(&func); \
        p ^= k; \
        p ^= k; \
        auto real = reinterpret_cast<fn_t>(p); \
        volatile int dummy = 0; \
        if (dummy == 1) return ret{}; \
        return real(__VA_ARGS__); \
    }()

#define IVS_SECURE(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k3 = ivs::ct_rnd<__COUNTER__>::value; \
        ivs::enc_val<std::size_t, k1> e1(k1); \
        ivs::enc_val<std::size_t, k2> e2(k2); \
        if (e1.dec() != k1 || e2.dec() != k2) return ret{}; \
        using fn_t = ret(*)(__VA_ARGS__); \
        fn_t fptr = &func; \
        ivs::ptr_guard<fn_t, k3> pg(fptr); \
        auto fn = pg.get(); \
        volatile std::size_t check = k3; \
        if (check == 0) return ret{}; \
        return fn(__VA_ARGS__); \
    }()

#define IVS_FORTIFIED(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        using fn_t = ret(*)(__VA_ARGS__); \
        fn_t fptr = &func; \
        ivs::dual_guard<fn_t, k1, k2> dg(fptr); \
        auto ptr = dg.get(); \
        if (!ptr) return ret{}; \
        return ptr(__VA_ARGS__); \
    }()

#define IVS_ARMORED(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k3 = ivs::ct_rnd<__COUNTER__>::value; \
        ivs::multi_enc<std::size_t, k1, k2, k3> guard(k1); \
        if (guard.dec() != k1) return ret{}; \
        using fn_t = ret(*)(__VA_ARGS__); \
        fn_t fptr = &func; \
        ivs::ptr_guard<fn_t, k2> pg(fptr); \
        auto fn = pg.get(); \
        volatile std::size_t check = k3; \
        if (check == 0) return ret{}; \
        return fn(__VA_ARGS__); \
    }()

#define IVS_STEALTH(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        using fn_t = ret(*)(__VA_ARGS__); \
        ivs::multi_enc<std::uintptr_t, k1, k2> enc(reinterpret_cast<std::uintptr_t>(&func)); \
        auto addr = enc.dec(); \
        volatile int check = 0; \
        for (int i = 0; i < 3; ++i) { \
            check ^= (i + 1); \
        } \
        if (check != 0) return ret{}; \
        auto fn = reinterpret_cast<fn_t>(addr); \
        return fn(__VA_ARGS__); \
    }()

#define IVS_LAYERED(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k3 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k4 = ivs::ct_rnd<__COUNTER__>::value; \
        ivs::enc_val<std::size_t, k1> e1(k1); \
        ivs::enc_val<std::size_t, k2> e2(k2); \
        ivs::multi_enc<std::size_t, k3, k4> e3(k3); \
        if (e1.dec() != k1 || e2.dec() != k2 || e3.dec() != k3) return ret{}; \
        using fn_t = ret(*)(__VA_ARGS__); \
        fn_t fptr = &func; \
        ivs::dual_guard<fn_t, k1, k2> dg(fptr); \
        auto ptr = dg.get(); \
        if (!ptr) return ret{}; \
        volatile std::size_t final_check = k4; \
        if (final_check == 0) return ret{}; \
        return ptr(__VA_ARGS__); \
    }()

#define IVS_ULTIMATE(ret, func, ...) \
    [&]() -> ret { \
        constexpr std::size_t k1 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k2 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k3 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k4 = ivs::ct_rnd<__COUNTER__>::value; \
        constexpr std::size_t k5 = ivs::ct_rnd<__COUNTER__>::value; \
        ivs::multi_enc<std::uintptr_t, k1, k2, k3> ptr_enc(reinterpret_cast<std::uintptr_t>(&func)); \
        ivs::multi_enc<std::size_t, k4, k5> val_enc(k4); \
        if (val_enc.dec() != k4) return ret{}; \
        auto addr = ptr_enc.dec(); \
        if (addr == 0) return ret{}; \
        using fn_t = ret(*)(__VA_ARGS__); \
        volatile int anti_opt = 0; \
        for (volatile int i = 0; i < 5; ++i) anti_opt += i; \
        if (anti_opt != 10) return ret{}; \
        addr ^= ivs::ct_rnd<0>::value; \
        addr ^= ivs::ct_rnd<0>::value; \
        auto fn = reinterpret_cast<fn_t>(addr); \
        return fn(__VA_ARGS__); \
    }()

#endif
