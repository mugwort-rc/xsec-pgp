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
 * XSECCryptoKeyHMAC := Raw HMAC buffers
 *
 * Author(s): Berin Lautenbach
 *
 * $Id: OpenPGPCryptoKeyHMAC.cpp 1125514 2011-05-20 19:08:33Z scantor $
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)

#include <xsec/enc/OpenPGP/OpenPGPCryptoKeyHMAC.hpp>
#include <xsec/framework/XSECError.hpp>

OpenPGPCryptoKeyHMAC::OpenPGPCryptoKeyHMAC() :m_keyBuf("") {

	m_keyBuf.isSensitive();
	m_keyLen = 0;

};

void OpenPGPCryptoKeyHMAC::setKey(unsigned char * inBuf, unsigned int inLength) {

	m_keyBuf.sbMemcpyIn(inBuf, inLength);
	m_keyBuf.isSensitive();
	m_keyLen = inLength;

}

unsigned int OpenPGPCryptoKeyHMAC::getKey(safeBuffer &outBuf) const {

	outBuf = m_keyBuf;
	return m_keyLen;

}

XSECCryptoKey * OpenPGPCryptoKeyHMAC::clone() const {

	OpenPGPCryptoKeyHMAC * ret;

	XSECnew(ret, OpenPGPCryptoKeyHMAC());

	ret->m_keyBuf = m_keyBuf;
	ret->m_keyLen = m_keyLen;

	return ret;

}

#endif /* XSEC_HAVE_OPENPGP */
