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

import fr.acinq.bitcoin.scalacompat.{ByteVector64, Satoshi, TxOut}
import fr.acinq.eclair.wire.protocol.CommonCodecs.{bytes64, satoshi, varint, varsizebinarydata}
import fr.acinq.eclair.wire.protocol.TlvCodecs.{tlvField, tlvStream, tmillisatoshi, tsatoshi}
import fr.acinq.eclair.{MilliSatoshi, UInt64}
import scodec.Codec
import scodec.codecs.discriminated

/**
 * Created by t-bast on 08/04/2022.
 */

sealed trait TxAddInputTlv extends Tlv

object TxAddInputTlv {
  val txAddInputTlvCodec: Codec[TlvStream[TxAddInputTlv]] = tlvStream(discriminated[TxAddInputTlv].by(varint))
}

sealed trait TxAddOutputTlv extends Tlv

object TxAddOutputTlv {
  val txAddOutputTlvCodec: Codec[TlvStream[TxAddOutputTlv]] = tlvStream(discriminated[TxAddOutputTlv].by(varint))
}

sealed trait TxRemoveInputTlv extends Tlv

object TxRemoveInputTlv {
  val txRemoveInputTlvCodec: Codec[TlvStream[TxRemoveInputTlv]] = tlvStream(discriminated[TxRemoveInputTlv].by(varint))
}

sealed trait TxRemoveOutputTlv extends Tlv

object TxRemoveOutputTlv {
  val txRemoveOutputTlvCodec: Codec[TlvStream[TxRemoveOutputTlv]] = tlvStream(discriminated[TxRemoveOutputTlv].by(varint))
}

sealed trait TxCompleteTlv extends Tlv

object TxCompleteTlv {
  val txCompleteTlvCodec: Codec[TlvStream[TxCompleteTlv]] = tlvStream(discriminated[TxCompleteTlv].by(varint))
}

sealed trait TxSignaturesTlv extends Tlv

object TxSignaturesTlv {
  case class PreviousFundingTxSig(sig: ByteVector64) extends TxSignaturesTlv

  val txSignaturesTlvCodec: Codec[TlvStream[TxSignaturesTlv]] = tlvStream(discriminated[TxSignaturesTlv].by(varint)
    .typecase(UInt64(601), tlvField(bytes64.as[PreviousFundingTxSig]))
  )
}

sealed trait TxInitRbfTlv extends Tlv

sealed trait TxAckRbfTlv extends Tlv

sealed trait SpliceInitTlv extends Tlv

sealed trait SpliceAckTlv extends Tlv

object InteractiveTxTlv {
  /** Amount that the peer will contribute to the transaction's shared output. */
  case class SharedOutputContributionTlv(amount: Satoshi) extends TxInitRbfTlv with TxAckRbfTlv with SpliceInitTlv with SpliceAckTlv

  /** Amount that the peer will push to the other side when building the commitment tx (used in splices). */
  case class PushAmountTlv(amount: MilliSatoshi) extends SpliceInitTlv with SpliceAckTlv

  case class SpliceOutOutputTlv(output: TxOut) extends SpliceInitTlv with SpliceAckTlv

  object SpliceOutOutputTlv {
    val codec: Codec[SpliceOutOutputTlv] = (satoshi :: varsizebinarydata).as[TxOut].as[SpliceOutOutputTlv]
  }
}

object TxInitRbfTlv {

  import InteractiveTxTlv._

  val txInitRbfTlvCodec: Codec[TlvStream[TxInitRbfTlv]] = tlvStream(discriminated[TxInitRbfTlv].by(varint)
    .typecase(UInt64(0), tlvField(tsatoshi.as[SharedOutputContributionTlv]))
  )
}

object TxAckRbfTlv {

  import InteractiveTxTlv._

  val txAckRbfTlvCodec: Codec[TlvStream[TxAckRbfTlv]] = tlvStream(discriminated[TxAckRbfTlv].by(varint)
    .typecase(UInt64(0), tlvField(tsatoshi.as[SharedOutputContributionTlv]))
  )
}

object SpliceInitTlv {

  import InteractiveTxTlv._

  val spliceInitTlvCodec: Codec[TlvStream[SpliceInitTlv]] = tlvStream(discriminated[SpliceInitTlv].by(varint)
    .typecase(UInt64(0), tlvField(tsatoshi.as[SharedOutputContributionTlv]))
    .typecase(UInt64(3001), tlvField(tmillisatoshi.as[PushAmountTlv]))
    .typecase(UInt64(3003), tlvField(SpliceOutOutputTlv.codec))
  )
}

object SpliceAckTlv {

  import InteractiveTxTlv._

  val spliceAckTlvCodec: Codec[TlvStream[SpliceAckTlv]] = tlvStream(discriminated[SpliceAckTlv].by(varint)
    .typecase(UInt64(0), tlvField(tsatoshi.as[SharedOutputContributionTlv]))
    .typecase(UInt64(3001), tlvField(tmillisatoshi.as[PushAmountTlv]))
    .typecase(UInt64(3003), tlvField(SpliceOutOutputTlv.codec))
  )
}

sealed trait TxAbortTlv extends Tlv

object TxAbortTlv {
  val txAbortTlvCodec: Codec[TlvStream[TxAbortTlv]] = tlvStream(discriminated[TxAbortTlv].by(varint))
}