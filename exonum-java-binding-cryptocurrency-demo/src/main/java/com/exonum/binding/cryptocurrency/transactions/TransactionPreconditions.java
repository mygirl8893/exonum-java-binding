/*
 * Copyright 2018 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.exonum.binding.cryptocurrency.transactions;

import static com.google.common.base.Preconditions.checkArgument;

import com.exonum.binding.common.message.Message;
import com.exonum.binding.cryptocurrency.CryptocurrencyService;
import com.google.errorprone.annotations.CanIgnoreReturnValue;

final class TransactionPreconditions {

  private static final short SERVICE_ID = CryptocurrencyService.ID;

  private TransactionPreconditions() {
    throw new AssertionError("Non-instantiable");
  }

  @CanIgnoreReturnValue
  static <MessageT extends Message> MessageT checkTransaction(
      MessageT message, short expectedTxId) {
    checkServiceId(message);
    checkTransactionId(message, expectedTxId);
    return message;
  }

  static <MessageT extends Message> void checkServiceId(MessageT message) {
    short serviceId = message.getServiceId();
    checkArgument(
        serviceId == SERVICE_ID,
        "This message (%s) does not belong to this service: wrong service ID (%s), must be %s",
        message,
        serviceId,
        SERVICE_ID);
  }

  static <MessageT extends Message> void checkTransactionId(MessageT message,
                                                            short expectedTxId) {
    short txId = message.getMessageType();
    checkArgument(
        txId == expectedTxId,
        "This message (%s) has wrong transaction ID (%s), must be %s",
        message,
        txId,
        expectedTxId);
  }
}
