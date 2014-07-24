#ifndef __HASHES_HMAC__
#define __HASHES_HMAC__

#include "Hashes.h"

template <class T>
class HMAC : public Hash{
    protected:
        virtual unsigned int blocksize(void) const{
            return 512;
        }

        T inner, outer;

    public:
        HMAC(std::string key, const std::string & message=std::string()) :
            Hash(),
            inner(),
            outer()
        {
            unsigned int bytelen = std::max(blocksize(), inner.blocksize()) >> 3;
            if (key.size() > bytelen){
                key = T(key).digest();
            }
            key += std::string(bytelen-key.size(), 0);
            inner.update(xor_strings(key, std::string(key.size(), 0x36)));
            outer.update(xor_strings(key, std::string(key.size(), 0x5c)));
            update(message);
        }

        void update(const std::string &message){
            inner.update(message);
        }

        std::string hexdigest() const{
            T h = outer;
            h.update(inner.digest());
            return h.hexdigest();
        }

        std::string digest() const{
            return unhexlify(hexdigest());
        }

};

typedef HMAC<MD5> HMAC_MD5;
typedef HMAC<RIPEMD160> HMAC_RIPEMD160;
typedef HMAC<SHA1> HMAC_SHA1;
typedef HMAC<SHA224> HMAC_SHA224;
typedef HMAC<SHA256> HMAC_SHA256;
typedef HMAC<SHA384> HMAC_SHA384;
typedef HMAC<SHA512> HMAC_SHA512;

#endif
