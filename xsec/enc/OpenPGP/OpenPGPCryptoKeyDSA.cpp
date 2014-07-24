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
 * OpenPGPCryptoKeyDSA := DSA Keys
 *
 * Author(s): Berin Lautenbach
 *
 * $Id: OpenPGPCryptoKeyDSA.cpp 1125752 2011-05-21 17:50:17Z scantor $
 *
 */
#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)

#include <xsec/enc/OpenPGP/OpenPGPCryptoKeyDSA.hpp>
#include <xsec/enc/OpenPGP/OpenPGPCryptoBase64.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoUtils.hpp>
#include <xsec/framework/XSECError.hpp>

#include <xercesc/util/Janitor.hpp>

XSEC_USING_XERCES(ArrayJanitor);

#include <OpenPGP/PKA/DSA.h>

OpenPGPCryptoKeyDSA::OpenPGPCryptoKeyDSA() : m_dsaKey(), m_dsaPub() {
}

OpenPGPCryptoKeyDSA::~OpenPGPCryptoKeyDSA() {

}

// Generic key functions

XSECCryptoKey::KeyType OpenPGPCryptoKeyDSA::getKeyType() const {

	// Find out what we have
	if (m_dsaKey.empty() && m_dsaPub.empty())
		return KEY_NONE;

	if (!m_dsaKey.empty() && !m_dsaPub.empty())
		return KEY_DSA_PAIR;

	if (!m_dsaKey.empty())
		return KEY_DSA_PRIVATE;

	if (!m_dsaPub.empty())
		return KEY_DSA_PUBLIC;

	return KEY_NONE;

}

void OpenPGPCryptoKeyDSA::loadPBase64BigNums(const char * b64, unsigned int len) {

	if (m_dsaPub.empty())
		m_dsaPub = std::vector<PGPMPI>(4, PGPMPI());

	m_dsaPub[0] = OpenPGPCryptoBase64::b642BN((char *) b64, len);

}

void OpenPGPCryptoKeyDSA::loadQBase64BigNums(const char * b64, unsigned int len) {

	if (m_dsaPub.empty())
		m_dsaPub = std::vector<PGPMPI>(4, PGPMPI());

	m_dsaPub[1] = OpenPGPCryptoBase64::b642BN((char *) b64, len);

}

void OpenPGPCryptoKeyDSA::loadGBase64BigNums(const char * b64, unsigned int len) {

	if (m_dsaPub.empty())
		m_dsaPub = std::vector<PGPMPI>(4, PGPMPI());

	m_dsaPub[2] = OpenPGPCryptoBase64::b642BN((char *) b64, len);

}

void OpenPGPCryptoKeyDSA::loadYBase64BigNums(const char * b64, unsigned int len) {

	if (m_dsaPub.empty())
		m_dsaPub = std::vector<PGPMPI>(4, PGPMPI());

	mp_dsaPub[3] = OpenPGPCryptoBase64::b642BN((char *) b64, len);

}

void OpenPGPCryptoKeyDSA::loadJBase64BigNums(const char * b64, unsigned int len) {

	if (m_dsaPub.empty())
		m_dsaPub = std::vector<PGPMPI>(4, PGPMPI());

	// Do nothing
}


// "Hidden" OpenPGP functions

OpenPGPCryptoKeyDSA::OpenPGPCryptoKeyDSA(const std::vector<PGPMPI> &pub, const std::vector<PGPMPI> &pri) : m_dsaKey(pri), m_dsaPub(pub) {

}

// --------------------------------------------------------------------------------
//           Verify a signature encoded as a Base64 string
// --------------------------------------------------------------------------------

bool OpenPGPCryptoKeyDSA::verifyBase64Signature(unsigned char * hashBuf,
								 unsigned int hashLen,
								 char * base64Signature,
								 unsigned int sigLen) {

	// Use the currently loaded key to validate the Base64 encoded signature

	if (m_dsaPub.empty()) {

		throw XSECCryptoException(XSECCryptoException::DSAError,
			"OpenPGP:DSA - Attempt to validate signature with empty key");
	}

	std::string sigVal = radix642ascii(std::string(base64Signature, sigLen));

	// Translate to BNs and thence to DSA_SIG
	PGPMPI R;
	PGPMPI S;

	if (sigValLen == 40) {

		R = rawtompi(sigVal.substr(0, 20));
		S = rawtompi(sigVal.substr(20, 20));
	}
	else {

		unsigned char rb[20];
		unsigned char sb[20];

		if (sigValLen == 46 && ASN2DSASig(sigVal, rb, sb) == true) {

			R = rawtompi(std::string(rb, 20));
			S = rawtompi(std::string(sb, 20));

		}

		else {

			throw XSECCryptoException(XSECCryptoException::DSAError,
				"OpenPGP:DSA - Signature Length incorrect");
		}
	}

	// Now we have a signature and a key - lets check
	std::vector<PGPMPI> dsa_sig;
	dsa_sig.push_back(R);
	dsa_sig.push_back(S);

	return DSA_verify(std::string(hashBuf, hashLen), dsa_sig, m_dsaKey);

}

// --------------------------------------------------------------------------------
//           Sign and encode result as a Base64 string
// --------------------------------------------------------------------------------


unsigned int OpenPGPCryptoKeyDSA::signBase64Signature(unsigned char * hashBuf,
		unsigned int hashLen,
		char * base64SignatureBuf,
		unsigned int base64SignatureBufLen) {

	// Sign a pre-calculated hash using this key

	if (m_dsaKey.empty()) {

		throw XSECCryptoException(XSECCryptoException::DSAError,
			"OpenPGP:DSA - Attempt to sign data with empty key");
	}

	std::vector<PGPMPI> dsa_sig;

	dsa_sig = DSA_sign(std::string(hashBuf, hashLen), m_dsaKey, m_dsaPub);

	if (dsa_sig.empty()) {

		throw XSECCryptoException(XSECCryptoException::DSAError,
			"OpenPGP:DSA - Error signing data");

	}

	// Now turn the signature into a base64 string

	std::string rawSigR = mpitoraw(dsa_sig[0]);
	std::string rawSigS = mpitoraw(dsa_sig[1]);

	if (rawSigR.size() < 20) {
		rawSigR = std::string(20-rawSigR.size(), 0) + rawSigR;
	}
	if (rawSigS.size() < 20) {
		rawSigS = std::string(20-rawSigS.size(), 0) + rawSigS;
	}

	// Now convert to Base 64

	std::string b64 = ascii2radix64(rawSigR+rawSigS);
	unsigned int retLen = (b64.size() > base64SignatureBufLen ? base64SignatureBufLen : b64.size());

	memcpy(base64SignatureBuf, &b64[0], retLen);

	if (retLen <= 0) {

		throw XSECCryptoException(XSECCryptoException::DSAError,
			"OpenPGP:DSA - Error base64 encoding signature");
	}

	return retLen;

}



XSECCryptoKey * OpenPGPCryptoKeyDSA::clone() const {

	OpenPGPCryptoKeyDSA * ret;

	XSECnew(ret, OpenPGPCryptoKeyDSA);

	ret->m_keyType = m_keyType;
	ret->m_dsaKey = m_dsaKey;
	ret->m_dsaPub = m_dsaPub;

	return ret;

}

#endif /* XSEC_HAVE_OPENPGP */
