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
 * $Id: OpenPGPCryptoProvider.hpp 1125514 2011-05-20 19:08:33Z scantor $
 *
 */

#ifndef OPENPGPCRYPTOPROVIDER_INCLUDE
#define OPENPGPCRYPTOPROVIDER_INCLUDE

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>

#include <map>
#include <string>

#if defined (XSEC_HAVE_OPENPGP)

/**
 * @defgroup openpgpcrypto OpenPGP Interface
 * @ingroup crypto
 * The OpenPGP/OpenPGP* classes provide an implementation of the 
 * XSECCrypto interface layer for OpenPGP.  The layer is very thin -
 * it only provides the functionality necessary to provide cryptographic
 * services to the library.
 *
 * Calling applications need to do the work to initialise OpenPGP, load
 * keys from disk etc.
 *
 */
 /*\@{*/

class DSIG_EXPORT OpenPGPCryptoProvider : public XSECCryptoProvider {

public :

	/** @name Constructors and Destructors */
	//@{
	
	OpenPGPCryptoProvider();
	virtual ~OpenPGPCryptoProvider();

	//@}

	/** @name Hashing (Digest) Functions */
	//@{

	/**
	 * \brief Return a SHA1 implementation.
	 *
	 * Call used by the library to obtain a SHA1 object from the 
	 * provider.
	 *
	 * @returns A pointer to an OpenPGP Hash object that implements SHA1
	 * @see XSECCryptoHash
	 */

	virtual XSECCryptoHash			* hashSHA1() const;

	/**
	 * \brief Return a SHA implementation.
	 *
	 * Call used by the library to obtain a SHA object from the 
	 * provider.  Size of hash determined by length argument (160 = SHA1)
	 *
	 * @returns A pointer to a Hash object that implements SHA1
	 * @param length - length of hash.  E.g. 160 for SHA1 or 256 for SHA256
	 * @see OpenPGPCryptoHash
	 */
	 
	virtual XSECCryptoHash			* hashSHA(int length = 160) const;

	/**
	 * \brief Return a HMAC SHA1 implementation.
	 *
	 * Call used by the library to obtain a HMAC SHA1 object from the 
	 * provider.  The caller will need to set the key in the hash
	 * object with an XSECCryptoKeyHMAC using OpenPGPCryptoHash::setKey()
	 *
	 * @returns A pointer to a Hash object that implements HMAC-SHA1
	 * @see OpenPGPCryptoHash
	 */

	virtual XSECCryptoHash			* hashHMACSHA1() const;

	/**
	 * \brief Return a HMAC SHA(1-512) implementation.
	 *
	 * Call used by the library to obtain a HMAC SHA object from the 
	 * provider.  The caller will need to set the key in the hash
	 * object with an XSECCryptoKeyHMAC using XSECCryptoHash::setKey()
	 *
	 * @returns A pointer to a Hash object that implements HMAC-SHA1
	 * @param length Length of hash output (160 = SHA1, 256, 512 etc)
	 * @see OpenPGPCryptoHash
	 */

	virtual XSECCryptoHash			* hashHMACSHA(int length = 160) const;
	
	/**
	 * \brief Return a MD5 implementation.
	 *
	 * Call used by the library to obtain a MD5 object from the 
	 * OpenPGP provider.
	 *
	 * @returns A pointer to a Hash object that implements MD5
	 * @see OpenPGPCryptoHash
	 */
	 
	virtual XSECCryptoHash			* hashMD5() const;

	/**
	 * \brief Return a HMAC MD5 implementation.
	 *
	 * Call used by the library to obtain a HMAC MD5 object from the 
	 * provider.  The caller will need to set the key in the hash
	 * object with an XSECCryptoKeyHMAC using XSECCryptoHash::setKey()
	 *
	 * @note The use of MD5 is explicitly marked as <b>not recommended</b> 
	 * in the XML Digital Signature standard due to recent advances in
	 * cryptography indicating there <em>may</em> be weaknesses in the 
	 * algorithm.
	 *
	 * @returns A pointer to a Hash object that implements HMAC-MD5
	 * @see OpenPGPCryptoHash
	 */

	virtual XSECCryptoHash			* hashHMACMD5() const;

	/**
	 * \brief Return a HMAC key
	 *
	 * Sometimes the library needs to create an HMAC key (notably within
	 * the XKMS utilities.
	 *
	 * This function allows the library to obtain a key that can then have
	 * a value set within it.
	 */

	virtual XSECCryptoKeyHMAC		* keyHMAC(void) const;

	//@}

	/** @name Encoding functions */
	//@{

	/**
	 * \brief Return a Base64 encoder/decoder implementation.
	 *
	 * Call used by the library to obtain an OpenPGP Base64 
	 * encoder/decoder.
	 *
	 * @returns Pointer to the new Base64 encoder.
	 * @see OpenPGPCryptoBase64
	 */

	virtual XSECCryptoBase64		* base64() const;

	//@}

	/** @name Keys and Certificates */
	//@{

	/**
	 * \brief Return a DSA key implementation object.
	 * 
	 * Call used by the library to obtain a DSA key object.
	 *
	 * @returns Pointer to the new DSA key
	 * @see OpenPGPCryptoKeyDSA
	 */

	virtual XSECCryptoKeyDSA		* keyDSA() const;

	/**
	 * \brief Return an RSA key implementation object.
	 * 
	 * Call used by the library to obtain an OpenPGP RSA key object.
	 *
	 * @returns Pointer to the new RSA key
	 * @see OpenPGPCryptoKeyRSA
	 */

	virtual XSECCryptoKeyRSA		* keyRSA() const;

	/**
	 * \brief Return an EC key implementation object.
	 * 
	 * Call used by the library to obtain an OpenPGP EC key object.
	 *
	 * @returns Pointer to the new EC key
	 * @see OpenPGPCryptoKeyEC
	 */

	virtual XSECCryptoKeyEC		    * keyEC() const;

	/**
	 * \brief Return a key implementation object based on DER-encoded input.
	 * 
	 * Call used by the library to obtain a key object from a DER-encoded key.
	 *
	 * @param buf       DER-encoded data
	 * @param buflen    length of data
	 * @param base64    true iff data is base64-encoded
	 * @returns Pointer to the new key
	 * @see XSECCryptoKey
	 */

	virtual XSECCryptoKey           * keyDER(const char* buf, unsigned long buflen, bool base64) const;

	/**
	 * \brief Return an X509 implementation object.
	 * 
	 * Call used by the library to obtain an object that can work
	 * with X509 certificates.
	 *
	 * @returns Pointer to the new X509 object
	 */

	virtual XSECCryptoX509			* X509() const;

	/**
	 * \brief Determine whether a given algorithm is supported
	 *
	 * A call that can be used to determine whether a given 
	 * symmetric algorithm is supported
	 */

	virtual bool algorithmSupported(XSECCryptoSymmetricKey::SymmetricKeyType alg) const;

	/**
	 * \brief Determine whether a given algorithm is supported
	 *
	 * A call that can be used to determine whether a given 
	 * digest algorithm is supported
	 */

	virtual bool algorithmSupported(XSECCryptoHash::HashType alg) const;
	
	/**
	 * \brief Return a Symmetric Key implementation object.
	 *
	 * Call used by the library to obtain a bulk encryption
	 * object.
	 *
	 * @returns Pointer to the new SymmetricKey object
	 * @see XSECCryptoSymmetricKey
	 */

	virtual XSECCryptoSymmetricKey	* keySymmetric(XSECCryptoSymmetricKey::SymmetricKeyType alg) const;

	/**
	 * \brief Obtain some random octets
	 *
	 * For generation of IVs and the like, the library needs to be able
	 * to obtain "random" octets.  The library uses this call to the 
	 * crypto provider to obtain what it needs.
	 *
	 * @param buffer The buffer to place the random data in
	 * @param numOctets Number of bytes required
	 * @returns Number of bytes obtained.
	 */

	virtual unsigned int getRandom(unsigned char * buffer, unsigned int numOctets) const;

	//@}

	/** @name Information Functions */
	//@{

	/**
	 * \brief Returns a string that identifies the Crypto Provider
	 */

	virtual const XMLCh * getProviderName() const;

	//@}

	/*\@}*/

};

#endif /* XSEC_HAVE_OPENPGP */
#endif /* OPENPGPCRYPTOPROVIDER_INCLUDE */
