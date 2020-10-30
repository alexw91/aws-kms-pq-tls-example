/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.example;

import com.example.crypto.RSAUtils;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.crt.io.TlsCipherPreference;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.ExpirationModelType;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.GetParametersForImportResponse;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionResponse;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;
import software.amazon.awssdk.utils.Logger;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Random;

/*
 * This Java code shows how to configure the AWS Java SDK 2.0 with the AWS Common Runtime (CRT) HTTP client and PQ
 * cipher suites. Then, it uses the KMS client to import key material into a customer master key (CMK), generate a data
 * key under that CMK, and decrypt the encrypted data key.
 */
public class AwsKmsPqTlsExample {
    private static final Logger LOG = Logger.loggerFor(AwsKmsPqTlsExample.class);
    private static final Random SECURE_RANDOM = new SecureRandom();
    private static final int AES_KEY_SIZE_BYTES = 256 / 8;

    public static void main(String[] args) throws Exception {
        /*
         * Check preconditions before continuing. The AWS CRT supports hybrid post-quantum TLS on Linux systems only.
         */
        LOG.info(() -> "\nConfirm Access to Post-Quantum TLS Ciphers:");
        TlsCipherPreference cipherPreference = TlsCipherPreference.TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2020_07;
        if (cipherPreference.isSupported()) {
            LOG.info(() -> "1. " + cipherPreference.name() + " is available on current platform.");
            LOG.info(() -> "2. Hybrid post-quantum cipher are supported and will be used.");
        } else {
            throw new UnsupportedOperationException("Hybrid post-quantum cipher suites are supported only on Linux systems");
        }

        /*
         * Set up a PQ TLS HTTP client that will be used in the rest of the example.
         */
        SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .tlsCipherPreference(cipherPreference)
                .build();
        /*
         * Set up a Java SDK 2.0 KMS Client which will use hybrid post-quantum TLS for all connections to KMS.
         */
        KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                .httpClient(awsCrtHttpClient)
                .build();

        /*
         * Import key material workflow with hybrid post-quantum TLS
         *
         * Step 1: Create an external CMK with no key material
         */
        LOG.info(() -> "\nPost-Quantum KMS Key Import Example:");
        CreateKeyRequest createRequest = CreateKeyRequest.builder()
                .origin(OriginType.EXTERNAL)
                .description("Test key for aws-kms-pq-tls-example. Feel free to delete this.")
                .build();
        CreateKeyResponse createResponse = asyncKMSClient.createKey(createRequest).get();
        String keyId = createResponse.keyMetadata().keyId();
        LOG.info(() -> "1. Created CMK ID: " + keyId);

        /*
         * Step 2: Get the wrapping key and token required to import the local key material. The AlgorithmSpec determines
         * how we must wrap the local key material using the public key from KMS.
         */
        GetParametersForImportRequest getParametersRequest = GetParametersForImportRequest.builder()
                .keyId(keyId)
                .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_1)
                .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                .build();
        GetParametersForImportResponse getParametersResponse =
                asyncKMSClient.getParametersForImport(getParametersRequest).get();
        LOG.info(() -> "2. Received Public RSA Wrapping Key from KMS for CMK import");

        /*
         * Step 3: Prepare the parameters for the ImportKeyMaterial call.
         */
        SdkBytes importToken = getParametersResponse.importToken();
        byte[] publicKeyBytes = getParametersResponse.publicKey().asByteArray();

        /*
         * Create an ephemeral AES key. You should never do this in production. With KMS ImportKeyMaterial, you are
         * responsible for keeping a durable copy of the key.
         * https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
         *
         * The plaintextAesKey exists only for the lifetime of this function. This example key material will expire from
         * KMS in 10 minutes. This is the 'validTo(Instant.now().plusSeconds(600))' in the ImportKeyMaterial call below.
         */
        byte[] plaintextAesKey = new byte[AES_KEY_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(plaintextAesKey);
        LOG.info(() -> "3. Generated local secure AES Key");

        /*
         * Use the wrapping key to encrypt the local key material. Then use the token to import the wrapped key
         * material into KMS.
         *
         * This RSA wrapped key material is protected in transit with PQ TLS. If you use classic TLS, a large-scale
         * quantum computer would be able to decrypt the TLS session data and recover the RSA-wrapped key material. Then
         * it could decrypt the RSA-wrapped key to recover your plaintext AES key.
         */
        RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicKeyBytes);
        byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);
        LOG.info(() -> "4. Wrapped local AES Key with public KMS Wrapping Key");

        /*
         * Step 4: Import the key material using the CMK ID, wrapped key material, and import token. This is the
         * important call to protect. Your AES key is leaving your computer and traveling over the network wrapped by an
         * RSA public key and encrypted with PQ TLS.
         *
         * This AES key will be used for all KMS cryptographic operations when you use this CMK. If this key is
         * compromised, all ciphertexts that use this CMK are also compromised.
         */
        ImportKeyMaterialRequest importRequest = ImportKeyMaterialRequest.builder()
                .keyId(keyId)
                .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedAesKey))
                .importToken(importToken)
                .expirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                .validTo(Instant.now().plusSeconds(600))
                .build();
        asyncKMSClient.importKeyMaterial(importRequest).get();
        LOG.info(() -> String.format("5. Imported AES key into KMS with CMK ID:%s. Used PQ TLS to protect RSA-wrapped AES key " +
                "in transit.", keyId));

        /*
         * Clean up resources from this demo.
         *
         * Schedule deletion of the CMK that contains imported key material. Because this CMK was created only for this
         * test, we will delete it as part of cleanup. After the CMK is deleted, any ciphertexts encrypted under
         * this CMK are permanently unrecoverable.
         */
        LOG.info(() -> "\nClean Up after Demo:");
        ScheduleKeyDeletionRequest deletionRequest = ScheduleKeyDeletionRequest.builder()
                .keyId(keyId)
                .pendingWindowInDays(7)
                .build();
        ScheduleKeyDeletionResponse deletionResult = asyncKMSClient.scheduleKeyDeletion(deletionRequest).get();
        LOG.info(() -> String.format("1. CMK %s is scheduled to be deleted at %s.\n", keyId, deletionResult.deletionDate()));

        /*
         * Shut down the SDK and HTTP client. This will free any Java and native resources created for the demo.
         */
        asyncKMSClient.close();
        awsCrtHttpClient.close();
    }
}