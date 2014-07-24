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
 * OpenPGPCryptoHashHMAC := OpenPGP Implementation of HMAC
 *
 * Author(s): Berin Lautenbach
 *
 * $Id: OpenPGPCryptoHashHMAC.cpp 1125514 2011-05-20 19:08:33Z scantor $
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)


#include <xsec/enc/OpenPGP/OpenPGPCryptoHashHMAC.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>

#include <memory.h>

// Constructors/Destructors

OpenPGPCryptoHashHMAC::OpenPGPCryptoHashHMAC(HashType alg) {

	m_initialised = false;
	m_hashType = alg;

}

void OpenPGPCryptoHashHMAC::setKey(XSECCryptoKey *key) {

	// Use this to initialise the HMAC Context

	if (key->getKeyType() != XSECCryptoKey::KEY_HMAC) {

		throw XSECCryptoException(XSECCryptoException::MDError,
			"OpenPGP:HashHMAC - Non HMAC Key passed to OpenPGPHashHMAC");

	}

	
	m_keyLen = ((XSECCryptoKeyHMAC *) key)->getKey(m_keyBuf);
	reset();

}

OpenPGPCryptoHashHMAC::~OpenPGPCryptoHashHMAC() {

}



// Hashing Activities

void OpenPGPCryptoHashHMAC::reset(void) {

	std::string key(m_keyBuf.rawBuffer(), m_keyLen);

	switch (m_hashType) {

	case (XSECCryptoHash::HASH_SHA1) :
	
		mp_md.reset(HMAC_SHA1(key));
		break;

	case (XSECCryptoHash::HASH_MD5) :
	
		mp_md.reset(HMAC_MD5(key));
		break;

	case (XSECCryptoHash::HASH_SHA224) :
	
		mp_md.reset(HMAC_SHA224(key));
		break;

	case (XSECCryptoHash::HASH_SHA256) :
	
		mp_md.reset(HMAC_SHA256(key));
		break;

	case (XSECCryptoHash::HASH_SHA384) :
	
		mp_md.reset(HMAC_SHA384(key));
		break;

	case (XSECCryptoHash::HASH_SHA512) :
	
		mp_md.reset(HMAC_SHA512(key));
		break;

	default :

		mp_md.reset();

	}

	if(!mp_md) {

		throw XSECCryptoException(XSECCryptoException::MDError,
			"OpenPGP:HashHMAC - Error loading Message Digest"); 
	}

}

void OpenPGPCryptoHashHMAC::hash(unsigned char * data, 
								 unsigned int length) {

	if (!m_initialised)
		throw XSECCryptoException(XSECCryptoException::MDError,
			"OpenPGP:HashHMAC - hash called prior to setKey");

	mp_md->update(std::string(reinterpret_cast<char *>(data), length));

}

unsigned int OpenPGPCryptoHashHMAC::finish(unsigned char * hash,
									   unsigned int maxLength) {

	unsigned int retLen;

	// Finish up and copy out hash, returning the length
	std::string out = mp_md->digest();

	// Copy to output buffer
	
	retLen = (maxLength > m_mdLen ? m_mdLen : maxLength);
	memcpy(hash, &out[0], retLen);

	return retLen;

}

// Get information

XSECCryptoHash::HashType OpenPGPCryptoHashHMAC::getHashType(void) const {

	return m_hashType;			// This could be any kind of hash

}

#endif /* XSEC_HAVE_OPENPGP */
