/*
 * Copyright (C) 2018 Tobias Brunner
 * Copyright (C) 2018 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup qske_mechanism qske_mechanism
 * @{ @ingroup crypto
 */

#ifndef QSKE_MECHANISM_H_
#define QSKE_MECHANISM_H_

typedef enum qske_mechanism_t qske_mechanism_t;
typedef struct qske_t qske_t;
typedef struct qske_params_t qske_params_t;

#include <library.h>

/**
 * Quantum-Safe Key Encapsulation Mechanism
 *
 * KEM Candidates from the NIST Post-Quantum Cryptograpy Round 1 Submissions
 */
enum qske_mechanism_t {
	QSKE_NONE           =  0,
	QSKE_NEWHOPE        =  1,
	QSKE_CRYSTALS_KYBER =  2,
	QSKE_FRODO          =  3,
};

/**
 * enum name for qske_mechanism_t.
 */
extern enum_name_t *qske_mechanism_names;

/**
 * Implementation of a Quantum-Safe Key Encapsulation Mechanism
 */
struct qske_t {

	/**
	 * Get the QSKE mechanism used.
	 *
	 * @return			QSKE mechanism
	 */
	qske_mechanism_t (*get_qske_mechanism) (qske_t *this);

	/**
	 * Get the transport-encpded QSKE public key.
	 *
	 * @param value			Transport-encoded QSKE public key (allocated)
	 * @return				TRUE if encoding successful
	 */
	bool (*get_public_key) (qske_t *this, chunk_t *value)
		__attribute__((warn_unused_result));

	/**
	 * Set the transport-encoded QSKE public key
	 *
	 * @param value			Transport-encoded QSKE public key
	 * @return				TRUE if decoding successful
	 */
	bool (*set_public_key) (qske_t *this, chunk_t value)
		__attribute__((warn_unused_result));

	/**
	 * Get the transport-encoded encrypted shared secret
	 *
	 * @param value			Transport-encode encrypted shared secret (allocated)
	 * @return				TRUE if shared secret successfully encrypted
	 */
	bool (*get_ciphertext) (qske_t *this, chunk_t *value)
		__attribute__((warn_unused_result));

	/**
	 * Set the transport-encoded encrypted shared secret and decrypt it
	 *
	 * @param value			Transport-encoded encrypted shared secret
	 * @return				TRUE if shared secret successfully decrypted
	 */
	bool (*set_ciphertext) (qske_t *this, chunk_t value)
		__attribute__((warn_unused_result));

	/**
	 * Get the shared secret
	 *
	 * @param secret		Shared secret (allocated)
	 * @return				TRUE if shared secret successfully retrieved
	 */
	bool (*get_shared_secret) (qske_t *this, chunk_t *secret)
		__attribute__((warn_unused_result));

	/**
	 * Set the shared secret for test purposes
	 *
	 * @param secret		Shared secret
	 */
	void (*set_shared_secret) (qske_t *this, chunk_t secret);

	/**
	 * Destroys a qske_t object.
	 */
	void (*destroy) (qske_t *this);
};

#endif /** QSKE_MECHANISM_H_ @}*/
