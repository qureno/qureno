// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "prevector.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include "crypto/sph_blake.h"
#include "crypto/sph_bmw.h"
#include "crypto/sph_groestl.h"
#include "crypto/sph_jh.h"
#include "crypto/sph_keccak.h"
#include "crypto/sph_skein.h"
#include "crypto/sph_luffa.h"
#include "crypto/sph_cubehash.h"
#include "crypto/sph_shavite.h"
#include "crypto/sph_simd.h"
#include "crypto/sph_echo.h"

#include "crypto/sph_hamsi.h"
#include "crypto/sph_fugue.h"
#include "crypto/sph_shabal.h"
#include "crypto/sph_whirlpool.h"
#include "crypto/sph_sha2.h"
#include "crypto/sph_haval.h"

#include <vector>

typedef uint256 ChainCode;

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_blake512_context     z_blake;
GLOBAL sph_bmw512_context       z_bmw;
GLOBAL sph_groestl512_context   z_groestl;
GLOBAL sph_jh512_context        z_jh;
GLOBAL sph_keccak512_context    z_keccak;
GLOBAL sph_skein512_context     z_skein;
GLOBAL sph_luffa512_context     z_luffa;
GLOBAL sph_cubehash512_context  z_cubehash;
GLOBAL sph_shavite512_context   z_shavite;
GLOBAL sph_simd512_context      z_simd;
GLOBAL sph_echo512_context      z_echo;
GLOBAL sph_hamsi512_context     z_hamsi;
GLOBAL sph_fugue512_context     z_fugue;
GLOBAL sph_shabal512_context    z_shabal;
GLOBAL sph_whirlpool_context    z_whirlpool;
GLOBAL sph_sha512_context       z_sha2;
GLOBAL sph_haval256_5_context   z_haval;

#define fillz() do { \
    sph_blake512_init(&z_blake); \
    sph_bmw512_init(&z_bmw); \
    sph_groestl512_init(&z_groestl); \
    sph_jh512_init(&z_jh); \
    sph_keccak512_init(&z_keccak); \
    sph_skein512_init(&z_skein); \
    sph_luffa512_init(&z_luffa); \
    sph_cubehash512_init(&z_cubehash); \
    sph_shavite512_init(&z_shavite); \
    sph_simd512_init(&z_simd); \
    sph_echo512_init(&z_echo); \
    sph_hamsi512_init(&z_hamsi); \
    sph_fugue512_init(&z_fugue); \
    sph_shabal512_init(&z_shabal); \
    sph_whirlpool_init(&z_whirlpool); \
    sph_sha512_init(&z_sha2); \
    sph_haval256_5_init(&z_haval); \
} while (0)

#define ZBLAKE (memcpy(&ctx_blake, &z_blake, sizeof(z_blake)))
#define ZBMW (memcpy(&ctx_bmw, &z_bmw, sizeof(z_bmw)))
#define ZGROESTL (memcpy(&ctx_groestl, &z_groestl, sizeof(z_groestl)))
#define ZJH (memcpy(&ctx_jh, &z_jh, sizeof(z_jh)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZSKEIN (memcpy(&ctx_skein, &z_skein, sizeof(z_skein)))
#define ZHAMSI (memcpy(&ctx_hamsi, &z_hamsi, sizeof(z_hamsi)))
#define ZFUGUE (memcpy(&ctx_fugue, &z_fugue, sizeof(z_fugue)))
#define ZSHABAL (memcpy(&ctx_shabal, &z_shabal, sizeof(z_shabal)))
#define ZWHIRLPOOL (memcpy(&ctx_whirlpool, &z_whirlpool, sizeof(z_whirlpool)))
#define ZSHA2 (memcpy(&ctx_sha2, &z_sha2, sizeof(z_sha2)))
#define ZHAVAL (memcpy(&ctx_haval, &z_haval, sizeof(z_haval)))

/* ----------- Bitcoin Hash ------------------------------------------------- */
/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[sha.OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, sha.OUTPUT_SIZE).Finalize(hash);
    }

    CHash256& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[sha.OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, sha.OUTPUT_SIZE).Finalize(hash);
    }

    CHash160& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash160& Reset() {
        sha.Reset();
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
              .Write(p3begin == p3end ? pblank : (const unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template<typename T1, typename T2, typename T3, typename T4>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end,
                    const T4 p4begin, const T4 p4end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
              .Write(p3begin == p3end ? pblank : (const unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
              .Write(p4begin == p4end ? pblank : (const unsigned char*)&p4begin[0], (p4end - p4begin) * sizeof(p4begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template<typename T1, typename T2, typename T3, typename T4, typename T5>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end,
                    const T4 p4begin, const T4 p4end,
                    const T5 p5begin, const T5 p5end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
              .Write(p3begin == p3end ? pblank : (const unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
              .Write(p4begin == p4end ? pblank : (const unsigned char*)&p4begin[0], (p4end - p4begin) * sizeof(p4begin[0]))
              .Write(p5begin == p5end ? pblank : (const unsigned char*)&p5begin[0], (p5end - p5begin) * sizeof(p5begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end,
                    const T4 p4begin, const T4 p4end,
                    const T5 p5begin, const T5 p5end,
                    const T6 p6begin, const T6 p6end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
              .Write(p3begin == p3end ? pblank : (const unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
              .Write(p4begin == p4end ? pblank : (const unsigned char*)&p4begin[0], (p4end - p4begin) * sizeof(p4begin[0]))
              .Write(p5begin == p5end ? pblank : (const unsigned char*)&p5begin[0], (p5end - p5begin) * sizeof(p5begin[0]))
              .Write(p6begin == p6end ? pblank : (const unsigned char*)&p6begin[0], (p6end - p6begin) * sizeof(p6begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 160-bit hash an object. */
template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    uint160 result;
    CHash160().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 160-bit hash of a vector. */
inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

/** Compute the 160-bit hash of a vector. */
template<unsigned int N>
inline uint160 Hash160(const prevector<N, unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

/** A writer stream (for serialization) that computes a 256-bit hash. */
class CHashWriter
{
private:
    CHash256 ctx;

public:
    int nType;
    int nVersion;

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}

    CHashWriter& write(const char *pch, size_t size) {
        ctx.Write((const unsigned char*)pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

/** Reads data from an underlying stream, while hashing the read data. */
template<typename Source>
class CHashVerifier : public CHashWriter
{
private:
    Source* source;

public:
    CHashVerifier(Source* source_) : CHashWriter(source_->GetType(), source_->GetVersion()), source(source_) {}

    void read(char* pch, size_t nSize)
    {
        source->read(pch, nSize);
        this->write(pch, nSize);
    }

    void ignore(size_t nSize)
    {
        char data[1024];
        while (nSize > 0) {
            size_t now = std::min<size_t>(nSize, 1024);
            read(data, now);
            nSize -= now;
        }
    }

    template<typename T>
    CHashVerifier<Source>& operator>>(T& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

/** Compute the 256-bit hash of an object's serialization. */
template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

/** SipHash-2-4, using a uint64_t-based (rather than byte-based) interface */
class CSipHasher
{
private:
    uint64_t v[4];
    int count;

public:
    CSipHasher(uint64_t k0, uint64_t k1);
    CSipHasher& Write(uint64_t data);
    uint64_t Finalize() const;
};

uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val);
uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256& val, uint32_t extra);

/* ----------- Qureno Hash ------------------------------------------------ */
template<typename T1>
inline uint256 QRNHash(const T1 pbegin, const T1 pend, std::string hashPrevBlock, uint32_t nTime)
{
    char hashChar = hashPrevBlock.back();

    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    sph_sha512_context        ctx_sha2;
    sph_haval256_5_context    ctx_haval;
    static unsigned char pblank[1];
	
    if(nTime >= 1604188800) {
	uint512 hash[33];
	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	sph_luffa512_init(&ctx_luffa);
	sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	sph_simd512_init(&ctx_simd);
	sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	sph_echo512_init(&ctx_echo);
	sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	sph_shabal512_init(&ctx_shabal);
	sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	sph_sha512_init(&ctx_sha2);
	sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	sph_luffa512_init(&ctx_luffa);
	sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	sph_simd512_init(&ctx_simd);
	sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	sph_echo512_init(&ctx_echo);
	sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	sph_shabal512_init(&ctx_shabal);
	sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	sph_sha512_init(&ctx_sha2);
	sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	return hash[32].trim256();
    }
	
    if(nTime >= 1601510400 && nTime < 1604188800) {
        if(hashChar == 48) {
            uint512 hash[34];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[32]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[33]));
            return hash[33].trim256();
        } else if(hashChar == 49) {
            uint512 hash[35];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[32]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[33]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[33]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[34]));
    	    return hash[34].trim256();
        } else if(hashChar == 50) {
            uint512 hash[36];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[32]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[33]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[33]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[34]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[34]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[35]));
            return hash[35].trim256();
        } else if(hashChar == 51) {
            uint512 hash[37];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[32]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[33]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[33]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[34]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[34]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[35]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[35]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[36]));
            return hash[36].trim256();
	} else if(hashChar == 52) {
            uint512 hash[38];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[32]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[33]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[33]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[34]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[34]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[35]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[35]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[36]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[36]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[37]));
	    return hash[37].trim256();
	} else if(hashChar == 53) {
            uint512 hash[39];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[32]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[33]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[33]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[34]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[34]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[35]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[35]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[36]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[36]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[37]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[37]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[38]));
	    return hash[38].trim256();
	} else if(hashChar == 54) {
            uint512 hash[40];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[32]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[33]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[33]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[34]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[34]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[35]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[35]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[36]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[36]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[37]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[37]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[38]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[38]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[39]));
	    return hash[39].trim256();
	} else if(hashChar == 55) {
            uint512 hash[41];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[32]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[33]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[33]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[34]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[34]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[35]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[35]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[36]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[36]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[37]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[37]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[38]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[38]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[39]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[39]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[40]));
	    return hash[40].trim256();
	} else if(hashChar == 56) {
            uint512 hash[42];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[32]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[33]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[33]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[34]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[34]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[35]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[35]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[36]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[36]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[37]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[37]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[38]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[38]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[39]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[39]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[40]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[40]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[41]));
	    return hash[41].trim256();
	} else if(hashChar == 57) {
            uint512 hash[43];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[32]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[33]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[33]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[34]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[34]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[35]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[35]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[36]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[36]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[37]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[37]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[38]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[38]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[39]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[39]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[40]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[40]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[41]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[41]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[42]));
	    return hash[42].trim256();
	} else if(hashChar == 97) {
            uint512 hash[44];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[32]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[33]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[33]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[34]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[34]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[35]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[35]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[36]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[36]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[37]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[37]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[38]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[38]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[39]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[39]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[40]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[40]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[41]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[41]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[42]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[42]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[43]));
	    return hash[43].trim256();
	} else if(hashChar == 98) {
            uint512 hash[45];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[32]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[33]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[33]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[34]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[34]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[35]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[35]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[36]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[36]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[37]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[37]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[38]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[38]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[39]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[39]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[40]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[40]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[41]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[41]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[42]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[42]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[43]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[43]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[44]));
	    return hash[44].trim256();
	} else if(hashChar == 99) {
            uint512 hash[46];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[32]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[33]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[33]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[34]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[34]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[35]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[35]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[36]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[36]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[37]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[37]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[38]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[38]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[39]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[39]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[40]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[40]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[41]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[41]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[42]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[42]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[43]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[43]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[44]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[44]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[45]));
	    return hash[45].trim256();
	} else if(hashChar == 100) {
            uint512 hash[47];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[32]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[33]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[33]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[34]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[34]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[35]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[35]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[36]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[36]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[37]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[37]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[38]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[38]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[39]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[39]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[40]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[40]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[41]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[41]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[42]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[42]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[43]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[43]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[44]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[44]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[45]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[45]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[46]));
	    return hash[46].trim256();
	} else if(hashChar == 101) {
            uint512 hash[48];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[32]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[33]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[33]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[34]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[34]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[35]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[35]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[36]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[36]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[37]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[37]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[38]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[38]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[39]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[39]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[40]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[40]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[41]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[41]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[42]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[42]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[43]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[43]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[44]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[44]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[45]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[45]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[46]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[46]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[47]));
	    return hash[47].trim256();
	} else if(hashChar == 102) {
            uint512 hash[49];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[32]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[33]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[33]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[34]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[34]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[35]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[35]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[36]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[36]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[37]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[37]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[38]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[38]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[39]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[39]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[40]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[40]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[41]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[41]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[42]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[42]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[43]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[43]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[44]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[44]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[45]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[45]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[46]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[46]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[47]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[47]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[48]));
	    return hash[48].trim256();
        } else {
            uint512 hash[33];
	    sph_blake512_init(&ctx_blake);
	    sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	    sph_bmw512_init(&ctx_bmw);
	    sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	    sph_groestl512_init(&ctx_groestl);
	    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	    sph_skein512_init(&ctx_skein);
	    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	    sph_jh512_init(&ctx_jh);
	    sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	    sph_keccak512_init(&ctx_keccak);
	    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	    sph_luffa512_init(&ctx_luffa);
	    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	    sph_cubehash512_init(&ctx_cubehash);
	    sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	    sph_shavite512_init(&ctx_shavite);
	    sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	    sph_simd512_init(&ctx_simd);
	    sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	    sph_echo512_init(&ctx_echo);
	    sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	    sph_hamsi512_init(&ctx_hamsi);
	    sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	    sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	    sph_fugue512_init(&ctx_fugue);
	    sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	    sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	    sph_shabal512_init(&ctx_shabal);
	    sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	    sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	    sph_whirlpool_init(&ctx_whirlpool);
	    sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	    sph_sha512_init(&ctx_sha2);
	    sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	    sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	    sph_haval256_5_init(&ctx_haval);
	    sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	    return hash[32].trim256();
        }
    } else {
	uint512 hash[33];
	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
	sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));
	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[0]), 64);
	sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[1]));
	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[1]), 64);
	sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[2]));
	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[2]), 64);
	sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[3]));
	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[3]), 64);
	sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[4]));
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[4]), 64);
	sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[5]));
	sph_luffa512_init(&ctx_luffa);
	sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[5]), 64);
	sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[6]));
	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[6]), 64);
	sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[7]));
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[7]), 64);
	sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[8]));
	sph_simd512_init(&ctx_simd);
	sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[8]), 64);
	sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[9]));
	sph_echo512_init(&ctx_echo);
	sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[9]), 64);
	sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[10]));
	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[10]), 64);
	sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[11]));
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[11]), 64);
	sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[12]));
	sph_shabal512_init(&ctx_shabal);
	sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[12]), 64);
	sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[13]));
	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[13]), 64);
	sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[14]));
	sph_sha512_init(&ctx_sha2);
	sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[14]), 64);
	sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[15]));
	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[15]), 64);
	sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[16]));
	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, static_cast<const void*>(&hash[16]), 64);
	sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash[17]));
	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, static_cast<const void*>(&hash[17]), 64);
	sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash[18]));
	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[18]), 64);
	sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[19]));
	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, static_cast<const void*>(&hash[19]), 64);
	sph_jh512_close(&ctx_jh, static_cast<void*>(&hash[20]));
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[20]), 64);
	sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[21]));
	sph_luffa512_init(&ctx_luffa);
	sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[21]), 64);
	sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash[22]));
	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512 (&ctx_cubehash, static_cast<const void*>(&hash[22]), 64);
	sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash[23]));
	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, static_cast<const void*>(&hash[23]), 64);
	sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash[24]));
	sph_simd512_init(&ctx_simd);
	sph_simd512 (&ctx_simd, static_cast<const void*>(&hash[24]), 64);
	sph_simd512_close(&ctx_simd, static_cast<void*>(&hash[25]));
	sph_echo512_init(&ctx_echo);
	sph_echo512 (&ctx_echo, static_cast<const void*>(&hash[25]), 64);
	sph_echo512_close(&ctx_echo, static_cast<void*>(&hash[26]));
	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512 (&ctx_hamsi, static_cast<const void*>(&hash[26]), 64);
	sph_hamsi512_close(&ctx_hamsi, static_cast<void*>(&hash[27]));
	sph_fugue512_init(&ctx_fugue);
	sph_fugue512 (&ctx_fugue, static_cast<const void*>(&hash[27]), 64);
	sph_fugue512_close(&ctx_fugue, static_cast<void*>(&hash[28]));
	sph_shabal512_init(&ctx_shabal);
	sph_shabal512 (&ctx_shabal, static_cast<const void*>(&hash[28]), 64);
	sph_shabal512_close(&ctx_shabal, static_cast<void*>(&hash[29]));
	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool (&ctx_whirlpool, static_cast<const void*>(&hash[29]), 64);
	sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[30]));
	sph_sha512_init(&ctx_sha2);
	sph_sha512 (&ctx_sha2, static_cast<const void*>(&hash[30]), 64);
	sph_sha512_close(&ctx_sha2, static_cast<void*>(&hash[31]));
	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5 (&ctx_haval, static_cast<const void*>(&hash[31]), 64);
	sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[32]));
	return hash[32].trim256();
    }
}

#endif // BITCOIN_HASH_H
