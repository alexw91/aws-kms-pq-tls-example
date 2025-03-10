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

import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.util.function.Consumer;

/*
 * This Java code shows how to configure the AWS Java SDK 2.0 with the AWS Common Runtime (CRT) HTTP client and PQ
 * cipher suites. Then, it uses the KMS client to import key material into a customer master key (CMK), generate a data
 * key under that CMK, and decrypt the encrypted data key.
 */
public class AwsKmsPqTlsExample {
    private static final int AES_KEY_SIZE_BYTES = 256 / 8;

    public static Consumer<AwsRequestOverrideConfiguration.Builder> requestCloseConnection() {
        /* See https://tools.ietf.org/html/rfc2616#section-14.10 which specifies the "close" header to signal the
         * connection will be closed after the server responds. This is more efficient that deleting the entire SDK and
         * HTTP client for every transaction.
         */
        return b -> b.putHeader("Connection", "close");
    }

    private static String getKeyIDArn() {
        return "arn:aws:kms:us-west-2:431231179649:key/46568b3b-6485-4765-89d2-30d7718e145d";
    }

    private static long benchmarkHandshakes(long timeoutMillis, boolean pqEnabled) throws Exception {
        long numRequests = 0;
        try (SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .postQuantumTlsEnabled(pqEnabled)
                .build()) {

            try (KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                    .httpClient(awsCrtHttpClient)
                    .build();) {

                final String keyId = getKeyIDArn();

                long startTime = System.currentTimeMillis();

                do {
                    software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest dataKeyRequest =
                            software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest.builder()
                                    .keyId(keyId)
                                    .numberOfBytes(AES_KEY_SIZE_BYTES)
                                    .overrideConfiguration(requestCloseConnection())
                                    .build();

                    GenerateDataKeyResponse resp = asyncKMSClient.generateDataKey(dataKeyRequest).get();
                    numRequests++;

                    if(!resp.sdkHttpResponse().isSuccessful()) {
                        throw new RuntimeException("Error: " + resp.sdkHttpResponse().toString());
                    }
                } while((System.currentTimeMillis() - startTime) < timeoutMillis);
            }
        }
        return numRequests;
    }

    public static void main(String[] args) throws Exception {
        final long durationMillis = 5 * 1000;
        final int iterations = 100;

        long pqTotal = 0;
        long classicTotal = 0;
        try {
            for(int i = 0; i < iterations; i++) {
                final long pqCount = benchmarkHandshakes(durationMillis, true);
                final long classicCount = benchmarkHandshakes(durationMillis, false);
                pqTotal += pqCount;
                classicTotal += classicCount;
                final long durationSec = ((i+1) * durationMillis) / 1000;

                System.out.println("\nIteration: " + (i+1) + ": New Handshake Measurement: [PQ: " + pqCount + ", Classic: " + classicCount + "]");
                System.out.println("\nPQ Total: " + pqTotal);
                System.out.println("Classic Total: " + classicTotal);

                System.out.println("\nPQ TLS Request/sec: " + (((double)pqTotal)/durationSec));
                System.out.println("Classic TLS Handshake/sec: " + (((double)classicTotal)/durationSec));
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

