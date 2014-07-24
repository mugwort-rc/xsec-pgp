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
 * OpenPGPCryptoKeyRSA := RSA Keys
 *
 * Author(s): Berin Lautenbach
 *
 * $Id: OpenPGPCryptoKeyRSA.cpp 1350045 2012-06-13 22:33:10Z scantor $
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)

#include <xsec/enc/OpenPGP/OpenPGPCryptoKeyRSA.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoBase64.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoUtils.hpp>
#include <xsec/framework/XSECError.hpp>

#include <OpenPGP/PKA/RSA.h>

#include <xercesc/util/Janitor.hpp>

XSEC_USING_XERCES(ArrayJanitor);

#include <memory.h>

OpenPGPCryptoKeyRSA::OpenPGPCryptoKeyRSA() :
m_rsaKey(),
m_rsaPub() {
}

OpenPGPCryptoKeyRSA::~OpenPGPCryptoKeyRSA() {

}

// Generic key functions

XSECCryptoKey::KeyType OpenPGPCryptoKeyRSA::getKeyType() const {

	// Find out what we have
	if (m_rsaKey.empty() && m_rsaPub.empty())
		return KEY_NONE;

	if (!m_rsaKey.empty() && !m_rsaPub.empty())
		return KEY_RSA_PAIR;

	if (!m_rsaKey.empty())
		return KEY_RSA_PRIVATE;

	if (!m_rsaPub.empty())
		return KEY_RSA_PUBLIC;

	return KEY_NONE;

}

void OpenPGPCryptoKeyRSA::loadPublicModulusBase64BigNums(const char * b64, unsigned int len) {

	if (m_rsaPub.empty())
		m_rsaPub = std::vector<PGPMPI>(2, PGPMPI());

	m_rsaPub[0] = OpenPGPCryptoBase64::b642BN((char *) b64, len);

}

void OpenPGPCryptoKeyRSA::loadPublicExponentBase64BigNums(const char * b64, unsigned int len) {

	if (m_rsaPub.empty())
		m_rsaPub = std::vector<PGPMPI>(2, PGPMPI());

	m_rsaPub[1] = OpenPGPCryptoBase64::b642BN((char *) b64, len);

}

// "Hidden" OpenPGP functions

OpenPGPCryptoKeyRSA::OpenPGPCryptoKeyRSA(const std::vector<PGPMPI> &pub, const std::vector<PGPMPI> &pri) :
m_rsaKey(pri),
m_rsaPub(pub) {

}

// --------------------------------------------------------------------------------
//           Verify a signature encoded as a Base64 string
// --------------------------------------------------------------------------------

bool OpenPGPCryptoKeyRSA::verifySHA1PKCS1Base64Signature(const unsigned char * hashBuf,
								 unsigned int hashLen,
								 const char * base64Signature,
								 unsigned int sigLen,
								 hashMethod hm = HASH_SHA1) {

	// Use the currently loaded key to validate the Base64 encoded signature

	if (m_rsaPub.empty()) {

		throw XSECCryptoException(XSECCryptoException::RSAError,
			"OpenPGP:RSA - Attempt to validate signature with empty key");
	}

	std::string sigVal = radix642ascii(std::string(base64Signature, sigLen));
	std::vector<PGPMPI> signature;
	signature.push_back(rawtompi(signature));

	// Now decrypt
	uint8_t h = 0;

	switch (hm){
	case HASH_MD5:
		h = 1;
		break;
	case HASH_SHA1:
		h = 2;
		break;
	case HASH_SHA224:
		h = 11;
		break;
	case HASH_SHA256:
		h = 8;
		break;
	case HASH_SHA384:
		h = 9;
		break;
	case HASH_SHA512:
		h = 10;
		break;

	default:
		throw XSECCryptoException(XSECCryptoException::RSAError,
			"OpenPGP:RSA - Unsupported HASH algorithm for RSA");

	}

	std::string msg = EMSA_PKCS1_v1_5(h, std::string(hashBuf, hashLen), bitsize(m_rsaPub[0]) >> 3);

	return RSA_verify(msg, signature, m_rsaPub);

}

// --------------------------------------------------------------------------------
//           Sign and encode result as a Base64 string
// --------------------------------------------------------------------------------


unsigned int OpenPGPCryptoKeyRSA::signSHA1PKCS1Base64Signature(unsigned char * hashBuf,
		unsigned int hashLen,
		char * base64SignatureBuf,
		unsigned int base64SignatureBufLen,
		hashMethod hm) {

	// Sign a pre-calculated hash using this key

	if (m_rsaKey.empty()) {

		throw XSECCryptoException(XSECCryptoException::RSAError,
			"OpenPGP:RSA - Attempt to sign data with empty key");
	}

	// Build the buffer to be encrypted by prepending the OID to the hash
	uint8_t h = 0;

	switch (hm){
	case HASH_MD5:
		h = 1;
		break;
	case HASH_SHA1:
		h = 2;
		break;
	case HASH_SHA224:
		h = 11;
		break;
	case HASH_SHA256:
		h = 8;
		break;
	case HASH_SHA384:
		h = 9;
		break;
	case HASH_SHA512:
		h = 10;
		break;

	default:
		throw XSECCryptoException(XSECCryptoException::RSAError,
			"OpenPGP:RSA - Unsupported HASH algorithm for RSA");

	}

	std::string msg = EMSA_PKCS1_v1_5(h, std::string(hashBuf, hashLen), bitsize(m_rsaPub[0]) >> 3);

	// Now encrypt

	PGPMPI signature = RSA_sign(msg, m_rsaKey, m_rsaPub);
	std::string sigVal = mpitoraw(signature);

	// Now convert to Base 64

	std::string b64 = ascii2radix64(sigVal);

	unsigned int retLen = (base64SignatureBufLen < b64.size() ? base64SignatureBufLen : b64.size());
	memcpy(base64SignatureBuf, &b64[0], retLen);

	return retLen;
}

// --------------------------------------------------------------------------------
//           Size in bytes
// --------------------------------------------------------------------------------

unsigned int OpenPGPCryptoKeyRSA::getLength(void) const {

	if (!m_rsaPub.empty())
		return bitsize(m_rsaPub[0]) >> 3;

	return 0;

}

// --------------------------------------------------------------------------------
//           Clone this key
// --------------------------------------------------------------------------------

XSECCryptoKey * OpenPGPCryptoKeyRSA::clone() const {

	OpenPGPCryptoKeyRSA * ret;

	XSECnew(ret, OpenPGPCryptoKeyRSA);

	ret->m_rsaKey = m_rsaKey;
	ret->m_rsaPub = m_rsaPub;

	return ret;

}

#endif /* XSEC_HAVE_OPENPGP */
