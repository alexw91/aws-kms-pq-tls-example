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
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.ListKeysResponse;
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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    private static final int AES_TAG_SIZE_BITS = 128;
    private static final int AES_GCM_IV_BYTES = 12;
    private static final byte[] privateData = "MySecretData".getBytes();

    private static List<Long> gatherHandshakeData(int iterations, boolean pqEnabled) throws Exception {
        List<Long> handshakeTimeMicro = new ArrayList<Long>(iterations);
        for (int i = 0; i < iterations; i++) {

            SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                    .postQuantumTlsEnabled(pqEnabled)
                    .build();

            KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                    .httpClient(awsCrtHttpClient)
                    .build();

            long start = System.nanoTime();

            // Perform TCP Handshake + TLS Handshake + 1 HTTP Request
            ListKeysResponse keys = asyncKMSClient.listKeys().get();
            long end = System.nanoTime();
            handshakeTimeMicro.add((end-start)/1000);

            asyncKMSClient.close();
            awsCrtHttpClient.close();
        }

        return handshakeTimeMicro;
    }

    public static void main(String[] args) throws Exception {
        final int iterations = 500;

        // Perform warm up handshakes
        gatherHandshakeData(100, false);
        gatherHandshakeData(100, true);

        // Gather actual data
        List<Long> classicHandshakes = gatherHandshakeData(iterations, false);
        List<Long> pqHandshakes = gatherHandshakeData(iterations, true);

        double avgClassicHandshake = classicHandshakes.stream().mapToDouble(a->a).average().getAsDouble();
        double medianClassicHandshake = classicHandshakes.stream().mapToDouble(a->a).sorted().toArray()[iterations/2];
        double avgPqHandshake = pqHandshakes.stream().mapToDouble(a->a).average().getAsDouble();
        double medianPQHandshake = pqHandshakes.stream().mapToDouble(a->a).sorted().toArray()[iterations/2];

        System.out.println("Classic Handshake Times: " + Arrays.toString(classicHandshakes.toArray()));
        System.out.println("\nPQ Handshake Times: " + Arrays.toString(pqHandshakes.toArray()));

        System.out.println("\nAvg Classical Request Time: " + avgClassicHandshake);
        System.out.println("Avg PQ Request Time: " + avgPqHandshake);

        System.out.println("\nMedian Classical Request Time: " + medianClassicHandshake);
        System.out.println("Median PQ Request Time: " + medianPQHandshake);
    }
}
