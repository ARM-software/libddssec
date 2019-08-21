/*
 * DDS Security library
 * Copyright (c) 2019-2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DSEC_TA_KEY_MATERIAL_H
#define DSEC_TA_KEY_MATERIAL_H

#include <tee_api.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * \brief Maximum number of Key Material Handles that can be loaded
 *     concurrently.
 */
#define DSEC_TA_MAX_KEY_MATERIAL_HANDLE (256U)

/*
 * Extra care is taken here to make sure the maximum size of the array storing
 * the handles cannot exceed INT32_MAX. This is because OPTEE-OS parameters are
 * uint32_t and the index of a handle is an int32_t. When the cast occurres, if
 * the index overflows, it will make the handle ID invalid.
 */
#if (DSEC_TA_MAX_KEY_MATERIAL_HANDLE > INT32_MAX)
#error "DSEC_TA_MAX_KEY_MATERIAL_HANDLE cannot be more than INT32_MAX"
#endif

/*! No encryption/authentication */
#define TRANSFORMATION_KIND_NONE         {0, 0, 0, 0}
/*! Authentication only (AES128-GMAC) */
#define TRANSFORMATION_KIND_AES128_GMAC  {0, 0, 0, 1}
/*! Authenticated encryption (AES128-GCM) */
#define TRANSFORMATION_KIND_AES128_GCM   {0, 0, 0, 2}
/*! Authentication only (AES256-GMAC) */
#define TRANSFORMATION_KIND_AES256_GMAC  {0, 0, 0, 3}
/*! Authenticated encryption (AES256-GCM) */
#define TRANSFORMATION_KIND_AES256_GCM   {0, 0, 0, 4}

/* See the OMG specification for the meaning of those data */
#define TRANSFORMATION_KIND_SIZE          (4U)
#define MASTER_SALT_SIZE                  (32U)
#define SENDER_KEY_ID_SIZE                (4U)
#define MASTER_SENDER_KEY_SIZE            (32U)
#define RECEIVER_SPECIFIC_KEY_ID_SIZE     (4U)
#define MASTER_RECEIVER_SPECIFIC_KEY_SIZE (32U)

/*!
 * \brief Structure Key Material as defined in the OMG specification. Please
 *     look at the documentation for more details. The same names have been
 *     used.
 */
struct key_material_t {
    /*!
     * One of the value defined by the macros TRANSFORMATION_KIND_* .
     * Indicates the kind of operation that should be done when using the key
     * material.
     */
    uint8_t transformation_kind[TRANSFORMATION_KIND_SIZE];
    /*! Computed from the Challenges and the Shared Secret. */
    uint8_t master_salt[MASTER_SALT_SIZE];
    /*! Unique value to identify the key material of the sender. */
    uint8_t sender_key_id[SENDER_KEY_ID_SIZE];
    /*! Computed from the Challenges and the Shared Secret. */
    uint8_t master_sender_key[MASTER_SENDER_KEY_SIZE];
    /*! Unique value to identify the key material of the receiver. */
    uint8_t receiver_specific_key_id[RECEIVER_SPECIFIC_KEY_ID_SIZE];
    uint8_t master_receiver_specific_key[MASTER_RECEIVER_SPECIFIC_KEY_SIZE];
};

/*!
 * \brief Wrapper structure to indicates if the Key Material has been
 *     initialized
 */
struct key_material_handle_t {
    bool initialized;
    struct key_material_t key_material;
};

/*!
 * \brief Creates a Key Material Handle
 *
 * \details Create a Key Material by setting its transformation type, filling
 *     random values for master_salt and master_sender_key, creating a unique ID
 *     for sender_key_id, setting receiver_specific_key_id to 0 and
 *     master_receiver_specific_key to 0.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VALUE_OUTPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].value.a ID of the generated Key Material Handle.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a Specify to use GCM or GMAC.
 * \param parameters[1].value.b Specify to use 256 bits or 128 bits.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been created.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY No more memory is available for the
 *     allocation of the handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_create(uint32_t parameters_type,
                                       TEE_Param parameters[2]);

/*!
 * \brief Copy a Key Material Handle
 *
 * \details Allocate a new Key Material Handle, retrieve the handle from the
 *     given input and copy all the fields.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VALUE_OUTPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].value.a ID of the generated Key Material Handle.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a ID of the handle to be copied.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been created.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY No more memory is available for the
 *     allocation of the handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_copy(uint32_t parameters_type,
                                     TEE_Param parameters[2]);

/*!
 * \brief Register a key material
 *
 * \details Allocate Key Material Handle, retrieve the handle given by the
 *     input ID and copy the transformation_kind, master_salt, master_sender_key
 *     and sender_key_id of the input Key Material. If authentication is used,
 *     receiver_specific_key_id, master_receiver_specific_key are generated or
 *     copied.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VALUE_OUTPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].value.a ID of the generated Key Material Handle.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a ID of the handle to use for the copy.
 * \param parameters[2].value.a Use authentication.
 * \param parameters[2].value.b Generate the receiver specific key.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been created.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY No more memory is available for the
 *     allocation of the handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_register(uint32_t parameters_type,
                                         TEE_Param parameters[3]);

/*!
 * \brief Generate a key material
 *
 * \details Keys are created following the OMG specification using the Shared
 *     Secret Handle containing challenge 1, challenge 2 and shared secret.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VALUE_OUTPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].value.a ID of the generated Key Material Handle.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a ID of the handle to use for the copy.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been created.
 * \retval ::TEE_ERROR_OUT_OF_MEMORY No more memory is available for the
 *     allocation of the handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_generate(uint32_t parameters_type,
                                         TEE_Param parameters[2]);

/*!
 * \brief Return fields of a Key Material
 *
 * \details Retrieve the Handle asociated to the given ID and extract the fields
 *     requested. As a Key Material has too many fields to be returned in one
 *     go, there is a parameter used for selecting which part of the structure
 *     the function will return.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *
 * \param[out] parameters[0].memref.buffer Buffer that will contain the data
 *      selected.
 * \param[out] parameters[0].memref.size Input size of the buffer containing the
 *      output. Updated with the number of bytes written.
 * \param[out] parameters[1].memref.buffer Buffer that will contain the data
 *      selected.
 * \param[out] parameters[1].memref.size Input size of the buffer containing the
 *      output. Updated with the number of bytes written.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a ID of the handle to use for the copy.
 * \param parameters[2].value.a Part of the Key Material to return:
 *     - transformation_kind and master_salt if 0.
 *     - sender_key_id and master_sender_key if 1.
 *     - receiver_specific_key_id and master_receiver_specific_key if 2.
 *
 * \retval ::TEE_SUCCESS Requested fields are returned.
 * \retval ::TEE_ERROR_SHORT_BUFFER Given buffers are too small.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_return(uint32_t parameters_type,
                                       TEE_Param parameters[4]);

/*!
 * \brief Delete a key material handle
 *
 * \details Free the handle associated with the given ID.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[0].value.a ID of the handle to use for the copy.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been deleted.
 * \retval ::TEE_ERROR_NO_DATA The handle ID leads to an invalid Handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_delete(uint32_t parameters_type,
                                       TEE_Param parameters[1]);

/*!
 * \brief Serialize a key material handle to a buffer
 *
 * \details From a valid key material handle, extract the fields and generate
 *     a buffer.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *        - TEE_PARAM_TYPE_VALUE_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].memref.buffer Output buffer.
 * \param[out] parameters[0].memref.size Input size of the output buffer.
 *     Updated with the number of bytes written.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].value.a ID of the handle to use for the copy.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been serialized.
 * \retval ::TEE_ERROR_NO_DATA The handle ID leads to an invalid Handle.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_serialize(uint32_t parameters_type,
                                         TEE_Param parameters[2]);

/*!
 * \brief Deserialize a buffer to create a key material handle
 *
 * \details From a valid valid buffer, extract the fields and generate a key
 *     material handle.
 *     The TEE_Param expected are:
 *        - TEE_PARAM_TYPE_VALUE_OUTPUT
 *        - TEE_PARAM_TYPE_MEMREF_INPUT
 *        - TEE_PARAM_NONE
 *        - TEE_PARAM_NONE
 *
 * \param[out] parameters[0].value.a Handle ID allocated.
 *
 * \param parameters_type The types of each of the parameters in parameters as
 *     described above.
 * \param parameters[1].memref.buffer Input buffer.
 * \param parameters[1].memref.size Input size of the buffer.
 *
 * \retval ::TEE_SUCCESS Key Material Handle has been deserialized.
 * \retval ::TEE_ERROR_BAD_PARAMETERS Parameter types are not properly set.
 */
TEE_Result dsec_ta_key_material_deserialize(uint32_t parameters_type,
                                            TEE_Param parameters[2]);

#endif /* DSEC_TA_KEY_MATERIAL_H */
