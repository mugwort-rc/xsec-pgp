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
 * OpenPGPCryptoHashSHA1 := OpenPGP Implementation of SHA1
 *
 * Author(s): Berin Lautenbach
 *
 * $Id: OpenPGPCryptoHash.cpp 1125514 2011-05-20 19:08:33Z scantor $
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)

#include <xsec/enc/OpenPGP/OpenPGPCryptoHash.hpp>
#include <xsec/enc/XSECCryptoException.hpp>

#include <OpenPGP/Hashes/Hashes.h>

#include <memory.h>

// Constructors/Destructors

OpenPGPCryptoHash::OpenPGPCryptoHash(HashType alg) {

	m_hashType = alg;
	reset();

}


OpenPGPCryptoHash::~OpenPGPCryptoHash() {

	mp_md.reset();

}



// Hashing Activities
void OpenPGPCryptoHash::reset(void) {

	switch (m_hashType) {

	case (XSECCryptoHash::HASH_SHA1) :
	
		mp_md.reset(new SHA1);
		break;

	case (XSECCryptoHash::HASH_MD5) :
	
		mp_md.reset(new MD5);
		break;

	case (XSECCryptoHash::HASH_SHA224) :
	
		mp_md.reset(new SHA224);
		break;

	case (XSECCryptoHash::HASH_SHA256) :
	
		mp_md.reset(new SHA256);
		break;

	case (XSECCryptoHash::HASH_SHA384) :
	
		mp_md.reset(new SHA384);
		break;

	case (XSECCryptoHash::HASH_SHA512) :
	
		mp_md.reset(new SHA512);
		break;

	default :

		mp_md.reset();

	}

	if(!mp_md) {

		throw XSECCryptoException(XSECCryptoException::MDError,
			"OpenPGP:Hash - Error loading Message Digest"); 
	}

}

void OpenPGPCryptoHash::hash(unsigned char * data, 
								 unsigned int length) {

	mp_md->update(std::string(reinterpret_cast<char *>(data), length));

}
unsigned int OpenPGPCryptoHash::finish(unsigned char * hash,
									   unsigned int maxLength) {

	std::string out = mp_md->digest();
	memcpy(hash, &out[0], out.size());

	return out.size();

}

// Get information

XSECCryptoHash::HashType OpenPGPCryptoHash::getHashType(void) const {

	return m_hashType;			// This could be any kind of hash

}

#endif /* XSEC_HAVE_OPENPGP */
