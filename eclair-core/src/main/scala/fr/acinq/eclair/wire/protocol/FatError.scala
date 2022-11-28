/*
 * Copyright 2022 ACINQ SAS
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

package fr.acinq.eclair.wire.protocol

import fr.acinq.bitcoin.scalacompat.ByteVector32
import fr.acinq.eclair.wire.protocol.CommonCodecs._
import scodec.Codec
import scodec.bits.ByteVector
import scodec.codecs._

import scala.concurrent.duration.{DurationLong, FiniteDuration}


case class FatError(failurePayload: ByteVector, hopPayloads: Seq[ByteVector], hmacs: Seq[Seq[ByteVector32]])

object FatError {
  // @formatter:off
  sealed trait PayloadType
  object IntermediateHop extends PayloadType
  object ErrorSource extends PayloadType
  // @formatter:on

  def payloadTypeCodec: Codec[PayloadType] = mappedEnum(uint8, (IntermediateHop -> 0), (ErrorSource -> 1))

  case class HopPayload(payloadType: PayloadType, holdTime: FiniteDuration)

  def hopPayloadCodec: Codec[HopPayload] = (
    ("payload_type" | payloadTypeCodec) ::
      ("hold_time_ms" | uint64overflow.xmap[FiniteDuration](_.millis, _.toMillis))).as[HopPayload]

  private def hmacsCodec(n: Int): Codec[Seq[Seq[ByteVector32]]] =
    if (n == 0) {
      provide(Nil)
    }
    else {
      (listOfN(provide(n), bytes32).xmap[Seq[ByteVector32]](_.toSeq, _.toList) ::
        hmacsCodec(n - 1)).as[(Seq[ByteVector32], Seq[Seq[ByteVector32]])]
        .xmap(pair => pair._1 +: pair._2, seq => (seq.head, seq.tail))
    }

  def fatErrorCodec(payloadAndPadLength: Int = 256, hopPayloadLength: Int = 9, maxHop: Int = 27): Codec[FatError] = (
    ("failure_payload" | bytes(payloadAndPadLength + 4)) ::
      ("hop_payloads" | listOfN(provide(maxHop), bytes(hopPayloadLength)).xmap[Seq[ByteVector]](_.toSeq, _.toList)) ::
      ("hmacs" | hmacsCodec(maxHop))).as[FatError].complete
}
