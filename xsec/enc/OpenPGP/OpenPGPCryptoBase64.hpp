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
 * $Id: OpenPGPCryptoBase64.hpp 1125514 2011-05-20 19:08:33Z scantor $
 *
 */

#ifndef OPENPGPCRYPTOBASE64_INCLUDE
#define OPENPGPCRYPTOBASE64_INCLUDE

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECCryptoBase64.hpp>

// OpenPGP
#if defined (XSEC_HAVE_OPENPGP)

/**
 * @ingroup openpgpcrypto
 */
 /*\@{*/

/**
 * \brief Base64 encode/decode handler interface class.
 *
 * The XSEC library will use implementations of this interface 
 * for translating bytes to/from base64 encoding.
 *
 * Uses the EVP decode/encode routines in OpenPGP to perform the 
 * work.
 *
 */


class DSIG_EXPORT OpenPGPCryptoBase64 : public XSECCryptoBase64 {


public :

	
	OpenPGPCryptoBase64() {};
	virtual ~OpenPGPCryptoBase64() {};

	/** @name Decoding Functions */
	//@{

	/**
	 * \brief Initialise the base64 object.
	 *
	 */

	virtual void decodeInit(void) {}

	/**
	 * \brief Decode some passed in data.
	 *
	 * Pass the encoded data through the OpenPGP base64 decode function
	 * and place the data in the outData buffer.
	 *
	 * @param inData Pointer to the buffer holding encoded data.
	 * @param inLength Length of the encoded data in the buffer
	 * @param outData Buffer to place decoded data into
	 * @param outLength Maximum amount of data that can be placed in
	 *        the buffer.
	 * @returns The number of bytes placed in the outData buffer.
	 */

	virtual unsigned int decode(const unsigned char * inData, 
						 	    unsigned int inLength,
								unsigned char * outData,
								unsigned int outLength);


	/**
	 * \brief Finish off a decode.
	 *
	 * Clean out any extra data in the OpenPGP decode context 
	 * variable into the outData buffer.
	 *
	 * @param outData Buffer to place any remaining decoded data
	 * @param outLength Max amount of data to be placed in the buffer.
	 * @returns Amount of data placed in the outData buffer
	 */

	virtual unsigned int decodeFinish(unsigned char * outData,
							 	      unsigned int outLength);

	//@}

	/** @name Encoding Functions */
	//@{

	/**
	 * \brief Initialise the base64 object for encoding
	 *
	 */

	virtual void		 encodeInit(void) {}

	/**
	 * \brief Encode some passed in data.
	 *
	 * Pass the data through the OpenPGP Base64 encoder and place
	 * the output in the outData buffer.  Will keep any "overhang"
	 * data in the context buffer ready for the next pass of input 
	 * data.
	 *
	 * @param inData Pointer to the buffer holding data to be encoded.
	 * @param inLength Length of the data in the buffer
	 * @param outData Buffer to place encoded data into
	 * @param outLength Maximum amount of data that can be placed in
	 *        the buffer.
	 * @returns The number of bytes placed in the outData buffer.
	 */

	virtual unsigned int encode(const unsigned char * inData, 
						 	    unsigned int inLength,
								unsigned char * outData,
								unsigned int outLength);

	/**
	 * \brief Finish off an encode.
	 *
	 * Take any data left in the context variable, and create the
	 * tail of the base64 encoding.
	 *
	 * @param outData Buffer to place any remaining encoded data
	 * @param outLength Max amount of data to be placed in the buffer.
	 * @returns Amount of data placed in the outData buffer
	 */

	virtual unsigned int encodeFinish(unsigned char * outData,
							 	      unsigned int outLength);	// Finish


	//@}

	/** @name Library Specific Functions */
	//@{

	/**
	 * \brief Translate a base64 encoded BN to a bignum
	 *
	 * Take a ds:CryptoBinary number and translate to an OpenPGP
	 * representation of a PGPMPI.
	 *
	 */
	
	static PGPMPI b642MPI(char * b64in, unsigned int len);

	//@}

};

/*\@}*/

#endif /* XSEC_HAVE_OPENPGP */
#endif /* OPENPGPCRYPTOBASE64_INCLUDE */
