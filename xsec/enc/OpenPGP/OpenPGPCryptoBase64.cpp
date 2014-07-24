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
 * OpenPGPCryptoBase64 := Base virtual class to define a base64 encoder/decoder
 *
 * Author(s): Berin Lautenbach
 *
 * $ID$
 *
 * $LOG$
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENPGP)

#include <xsec/enc/OpenPGP/OpenPGPCryptoBase64.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSCrypt/XSCryptCryptoBase64.hpp>
#include <xsec/framework/XSECError.hpp>

#include <xercesc/util/Janitor.hpp>

#include <OpenPGP/radix64.h>
#include <OpenPGP/mpi.h>

XERCES_CPP_NAMESPACE_USE


// --------------------------------------------------------------------------------
//           Decoding
// --------------------------------------------------------------------------------

unsigned int OpenPGPCryptoBase64::decode(const unsigned char * inData, 
						 	    unsigned int inLength,
								unsigned char * outData,
								unsigned int outLength) {

	if (outLength < inLength) {

		throw XSECCryptoException(XSECCryptoException::MemoryError,
			"OpenPGP:Base64 - Output buffer not big enough for Base64 decode");

	}

	std::string out = radix642ascii(std::string(reinterpret_cast<const char *>(inData), inLength));
	memcpy(outData, &out[0], out.size());

	if (out.size() > (int) outLength) {

		throw XSECCryptoException(XSECCryptoException::MemoryError,
			"OpenPGP:Base64 - Output buffer not big enough for Base64 decode and overflowed");

	}
		
	return out.size();

}

unsigned int OpenPGPCryptoBase64::decodeFinish(unsigned char * , unsigned int ) {

	return 0;

}

// --------------------------------------------------------------------------------
//           Encoding
// --------------------------------------------------------------------------------

unsigned int OpenPGPCryptoBase64::encode(const unsigned char * inData, 
						 	    unsigned int inLength,
								unsigned char * outData,
								unsigned int outLength) {

	if (outLength < inLength * 1.37) {

		throw XSECCryptoException(XSECCryptoException::MemoryError,
			"OpenPGP:Base64 - Output buffer not big enough for Base64 encode");

	}

	std::string out = ascii2radix64(std::string(reinterpret_cast<const char *>(inData), inLength));
	memcpy(outData, &out[0], out.size());

	if (out.size() > (int) outLength) {

		throw XSECCryptoException(XSECCryptoException::MemoryError,
			"OpenPGP:Base64 - Output buffer not big enough for Base64 encode and overflowed");

	}
		
	return out.size();

}

unsigned int OpenPGPCryptoBase64::encodeFinish(unsigned char * , unsigned int ) {

	return 0;

}

// --------------------------------------------------------------------------------
//           Utility functions
// --------------------------------------------------------------------------------

PGPMPI OpenPGPCryptoBase64::b642PGPMPI(char * b64in, unsigned int len) {

	XSCryptCryptoBase64 *b64;
	XSECnew(b64, XSCryptCryptoBase64);
	Janitor<XSCryptCryptoBase64> j_b64(b64);

	std::unique_ptr<char> buf(new char[len]);

	b64->decodeInit();
	bufLen = b64->decode((unsigned char *) b64in, len, buf.get(), len);
	bufLen += b64->decodeFinish(&buf.get()[bufLen], len-bufLen);

	// Now translate to a PGPMPI
	return rawtompi(std::string(buf.get(), bufLen));

}

#endif /* XSEC_HAVE_OPENPGP */
