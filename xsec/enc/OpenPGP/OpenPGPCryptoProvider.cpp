/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * XSEC
 *
 * OpenPGPCryptoProvider := Base class to define an OpenPGP module
 *
 * Author(s): Berin Lautenbach
 *
 * $Id: OpenPGPCryptoProvider.cpp 1125514 2011-05-20 19:08:33Z scantor $
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)

#include <xsec/framework/XSECError.hpp>

#include <xsec/enc/OpenPGP/OpenPGPCryptoProvider.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoHash.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoHashHMAC.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoBase64.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoKeyDSA.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoKeyHMAC.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoKeyRSA.hpp>

#include <xsec/enc/XSCrypt/XSCryptCryptoBase64.hpp>

#include <xsec/enc/XSECCryptoException.hpp>

#include <xercesc/util/Janitor.hpp>

XSEC_USING_XERCES(ArrayJanitor);
XSEC_USING_XERCES(Janitor);

#include <OpenPGP/RNG/RNG.h>

OpenPGPCryptoProvider::OpenPGPCryptoProvider() {

}


OpenPGPCryptoProvider::~OpenPGPCryptoProvider() {

}

const XMLCh * OpenPGPCryptoProvider::getProviderName() const {

	return DSIGConstants::s_unicodeStrPROVOpenPGP;

}
	// Hashing classes

XSECCryptoHash	* OpenPGPCryptoProvider::hashSHA1() const {

	OpenPGPCryptoHash * ret;

	XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_SHA1));

	return ret;

}

XSECCryptoHash * OpenPGPCryptoProvider::hashHMACSHA1() const {

	OpenPGPCryptoHashHMAC * ret;

	XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_SHA1));

	return ret;

}

XSECCryptoHash	* OpenPGPCryptoProvider::hashSHA(int length) const {


	OpenPGPCryptoHash * ret;

	switch (length) {

	case 160: XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_SHA1));
		break;
	case 224: XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_SHA224));
		break;
	case 256: XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_SHA256));
		break;
	case 384: XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_SHA384));
		break;
	case 512: XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_SHA512));
		break;
	default:
		ret = NULL;
	}

	return ret;

}

XSECCryptoHash * OpenPGPCryptoProvider::hashHMACSHA(int length) const {

	OpenPGPCryptoHashHMAC * ret;

	switch (length) {

	case 160: XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_SHA1));
		break;
	case 224: XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_SHA224));
		break;
	case 256: XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_SHA256));
		break;
	case 384: XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_SHA384));
		break;
	case 512: XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_SHA512));
		break;
	default:
		ret = NULL;
	}

	return ret;

}

XSECCryptoHash	* OpenPGPCryptoProvider::hashMD5() const {

	OpenPGPCryptoHash * ret;

	XSECnew(ret, OpenPGPCryptoHash(XSECCryptoHash::HASH_MD5));

	return ret;

}

XSECCryptoHash * OpenPGPCryptoProvider::hashHMACMD5() const {

	OpenPGPCryptoHashHMAC * ret;

	XSECnew(ret, OpenPGPCryptoHashHMAC(XSECCryptoHash::HASH_MD5));

	return ret;

}

XSECCryptoKeyHMAC * OpenPGPCryptoProvider::keyHMAC(void) const {

	OpenPGPCryptoKeyHMAC * ret;
	XSECnew(ret, OpenPGPCryptoKeyHMAC);

	return ret;

}

XSECCryptoKeyDSA * OpenPGPCryptoProvider::keyDSA() const {
	
	OpenPGPCryptoKeyDSA * ret;

	XSECnew(ret, OpenPGPCryptoKeyDSA());

	return ret;

}

XSECCryptoKeyEC * OpenPGPCryptoProvider::keyEC() const {
    throw XSECCryptoException(XSECCryptoException::UnsupportedError,
        "OpenPGPCryptoProvider::keyEC - EC support not available");
}

XSECCryptoKeyRSA * OpenPGPCryptoProvider::keyRSA() const {
	
	OpenPGPCryptoKeyRSA * ret;

	XSECnew(ret, OpenPGPCryptoKeyRSA());

	return ret;

}

XSECCryptoKey* OpenPGPCryptoProvider::keyDER(const char* buf, unsigned long len, bool base64) const {
    throw XSECCryptoException(XSECCryptoException::UnsupportedError,
		"OpenPGPCryptoProvider::keyDER - DER support not available");
}


XSECCryptoX509 * OpenPGPCryptoProvider::X509() const {
    throw XSECCryptoException(XSECCryptoException::UnsupportedError,
		"OpenPGPCryptoProvider::X509 - X509 support not available");
}

XSECCryptoBase64 * OpenPGPCryptoProvider::base64() const {

#if 0
	OpenPGPCryptoBase64 * ret;

	XSECnew(ret, OpenPGPCryptoBase64());
#else
	XSCryptCryptoBase64 *ret;
	XSECnew(ret, XSCryptCryptoBase64);

#endif
	return ret;

}

bool OpenPGPCryptoProvider::algorithmSupported(XSECCryptoSymmetricKey::SymmetricKeyType alg) const {

	switch (alg) {

	case (XSECCryptoSymmetricKey::KEY_AES_128) :
	case (XSECCryptoSymmetricKey::KEY_AES_192) :
	case (XSECCryptoSymmetricKey::KEY_AES_256) :
	case (XSECCryptoSymmetricKey::KEY_3DES_192) :
	default:

		return false;

	}

	return false;

}

bool OpenPGPCryptoProvider::algorithmSupported(XSECCryptoHash::HashType alg) const {

	switch (alg) {

	case (XSECCryptoHash::HASH_SHA1) :
	case (XSECCryptoHash::HASH_MD5) :
	case (XSECCryptoHash::HASH_SHA224) :
	case (XSECCryptoHash::HASH_SHA256) :
	case (XSECCryptoHash::HASH_SHA384) :
	case (XSECCryptoHash::HASH_SHA512) :
		return true;

	default:
		return false;
	}

	return false;

}


XSECCryptoSymmetricKey	* OpenPGPCryptoProvider::keySymmetric(XSECCryptoSymmetricKey::SymmetricKeyType alg) const {
    throw XSECCryptoException(XSECCryptoException::UnsupportedError,
		"OpenPGPCryptoProvider::keySymmetric - Symmetric cipher support not available");
}

unsigned int OpenPGPCryptoProvider::getRandom(unsigned char * buffer, unsigned int numOctets) const {

	BBS(static_cast <PGPMPI> (static_cast <int> (now()))); // seed just in case not seeded

	std::string t = BBS::rand(numOctets << 3);
	memcpy(buffer, t.data(), numOctets);

	return numOctets;

}


#endif /* XSEC_HAVE_OPENPGP */
