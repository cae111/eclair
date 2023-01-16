package fr.acinq.eclair.wire.internal.channel.version3

import fr.acinq.bitcoin.scalacompat.{ByteVector32, DeterministicWallet, Satoshi}
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import fr.acinq.eclair.channel._
import fr.acinq.eclair.crypto.ShaChain
import fr.acinq.eclair.transactions.Transactions._
import fr.acinq.eclair.{CltvExpiryDelta, Features, InitFeature, MilliSatoshi, channel}
import scodec.bits.ByteVector

private[version3] object ChannelTypes3 {

  case class LocalParams(nodeId: PublicKey,
                         fundingKeyPath: DeterministicWallet.KeyPath,
                         dustLimit: Satoshi,
                         maxHtlcValueInFlightMsat: MilliSatoshi,
                         requestedChannelReserve_opt: Option[Satoshi],
                         htlcMinimum: MilliSatoshi,
                         toSelfDelay: CltvExpiryDelta,
                         maxAcceptedHtlcs: Int,
                         isInitiator: Boolean,
                         defaultFinalScriptPubKey: ByteVector,
                         walletStaticPaymentBasepoint: Option[PublicKey],
                         initFeatures: Features[InitFeature]) {
    def migrate(): channel.LocalParams = channel.LocalParams(
      nodeId, fundingKeyPath, dustLimit, maxHtlcValueInFlightMsat, requestedChannelReserve_opt, htlcMinimum, toSelfDelay, maxAcceptedHtlcs, isInitiator,
      if (defaultFinalScriptPubKey.size == 0) None else Some(defaultFinalScriptPubKey),
      walletStaticPaymentBasepoint, initFeatures
    )
  }

  object LocalParams {
    def apply(input: channel.LocalParams) = new LocalParams(input.nodeId, input.fundingKeyPath, input.dustLimit, input.maxHtlcValueInFlightMsat,
      input.requestedChannelReserve_opt, input.htlcMinimum, input.toSelfDelay, input.maxAcceptedHtlcs, input.isInitiator,
      input.upfrontShutdownScript_opt.getOrElse(ByteVector.empty), input.walletStaticPaymentBasepoint, input.initFeatures)
  }

  case class Commitments(channelId: ByteVector32,
                         channelConfig: ChannelConfig,
                         channelFeatures: ChannelFeatures,
                         localParams: LocalParams, remoteParams: RemoteParams,
                         channelFlags: ChannelFlags,
                         localCommit: LocalCommit, remoteCommit: RemoteCommit,
                         localChanges: LocalChanges, remoteChanges: RemoteChanges,
                         localNextHtlcId: Long, remoteNextHtlcId: Long,
                         originChannels: Map[Long, Origin],
                         remoteNextCommitInfo: Either[WaitingForRevocation, PublicKey],
                         commitInput: InputInfo,
                         remotePerCommitmentSecrets: ShaChain) {
    def migrate(): channel.Commitments = channel.Commitments(
      channelId,
      channelConfig,
      channelFeatures,
      if (channelFeatures.hasFeature(Features.UpfrontShutdownScript)) localParams.migrate() else localParams.migrate().copy(upfrontShutdownScript_opt = None),
      remoteParams: RemoteParams,
      channelFlags,
      localCommit, remoteCommit,
      localChanges, remoteChanges,
      localNextHtlcId, remoteNextHtlcId,
      originChannels,
      remoteNextCommitInfo,
      commitInput,
      remotePerCommitmentSecrets)
  }
}
