/*
 * Copyright 2019 ACINQ SAS
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

package fr.acinq.eclair.channel.states.e

import akka.testkit.TestProbe
import com.softwaremill.quicklens.ModifyPimp
import fr.acinq.bitcoin.scalacompat.{ByteVector32, SatoshiLong}
import fr.acinq.eclair._
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher.{WatchFundingConfirmed, WatchFundingConfirmedTriggered}
import fr.acinq.eclair.blockchain.fee._
import fr.acinq.eclair.channel._
import fr.acinq.eclair.channel.states.ChannelStateTestsTags.NoMaxHtlcValueInFlight
import fr.acinq.eclair.channel.states.{ChannelStateTestsBase, ChannelStateTestsTags}
import fr.acinq.eclair.transactions.Transactions
import fr.acinq.eclair.wire.protocol._
import org.scalatest.funsuite.FixtureAnyFunSuiteLike
import org.scalatest.{Outcome, Tag}

/**
 * Created by PM on 05/07/2016.
 */

class NormalSplicesStateSpec extends TestKitBaseClass with FixtureAnyFunSuiteLike with ChannelStateTestsBase {

  type FixtureParam = SetupFixture

  implicit val log: akka.event.LoggingAdapter = akka.event.NoLogging

  override def withFixture(test: OneArgTest): Outcome = {
    val tags = test.tags + ChannelStateTestsTags.DualFunding
    val nodeParamsB = TestConstants.Bob.nodeParams
      // we can't simply .modify(_.onChainFeeConf.defaultFeerateTolerance) because FeerateTolerance has private members
      .modify(_.onChainFeeConf).usingIf(test.tags.contains("small_channel"))(oc => OnChainFeeConf(
      feeTargets = oc.feeTargets, feeEstimator = oc.feeEstimator, spendAnchorWithoutHtlcs = oc.spendAnchorWithoutHtlcs, closeOnOfflineMismatch = oc.closeOnOfflineMismatch, updateFeeMinDiffRatio = oc.updateFeeMinDiffRatio, defaultFeerateTolerance = FeerateTolerance(0.01, 100.0, TestConstants.anchorOutputsFeeratePerKw, DustTolerance(25_000 sat, closeOnUpdateFeeOverflow = true)), perNodeFeerateTolerance = Map.empty
    ))
    val setup = init(nodeParamsB = nodeParamsB, tags = tags)
    import setup._
    reachNormal(setup, tags)
    awaitCond(alice.stateName == NORMAL)
    awaitCond(bob.stateName == NORMAL)
    withFixture(test.toNoArgTest(setup))
  }

  def initiateSplice(f: FixtureParam, spliceIn_opt: Option[SpliceIn] = None, spliceOut_opt: Option[SpliceOut] = None) = {
    import f._

    val sender = TestProbe()
    val cmd = CMD_SPLICE(sender.ref, spliceIn_opt, spliceOut_opt)
    alice ! cmd
    alice2bob.expectMsgType[SpliceInit]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[SpliceAck]
    bob2alice.forward(alice)
    sender.expectMsgType[RES_SUCCESS[CMD_SPLICE]]

    if (spliceIn_opt.isDefined) {
      alice2bob.expectMsgType[TxAddInput]
      alice2bob.forward(bob)
      bob2alice.expectMsgType[TxComplete]
      bob2alice.forward(alice)
      alice2bob.expectMsgType[TxAddOutput]
      alice2bob.forward(bob)
      bob2alice.expectMsgType[TxComplete]
      bob2alice.forward(alice)
    }
    if (spliceOut_opt.isDefined) {
      alice2bob.expectMsgType[TxAddOutput]
      alice2bob.forward(bob)
      bob2alice.expectMsgType[TxComplete]
      bob2alice.forward(alice)
    }
    alice2bob.expectMsgType[TxAddOutput]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[TxComplete]
    bob2alice.forward(alice)
    alice2bob.expectMsgType[TxComplete]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[CommitSig]
    bob2alice.forward(alice)
    alice2bob.expectMsgType[CommitSig]
    alice2bob.forward(bob)

    if (spliceIn_opt.isDefined) {
      bob2alice.expectMsgType[TxSignatures]
      bob2alice.forward(alice)
      alice2bob.expectMsgType[TxSignatures]
      alice2bob.forward(bob)
    } else {
      alice2bob.expectMsgType[TxSignatures]
      alice2bob.forward(bob)
      bob2alice.expectMsgType[TxSignatures]
      bob2alice.forward(alice)
    }

    awaitCond(alice.stateData.asInstanceOf[DATA_NORMAL].spliceStatus == SpliceStatus.NoSplice)
  }

  test("recv CMD_SPLICE (splice-in)") { f =>
    import f._

    val initialState = alice.stateData.asInstanceOf[DATA_NORMAL]
    assert(initialState.metaCommitments.latest.capacity == 1_500_000.sat)
    assert(initialState.metaCommitments.latest.localCommit.spec.toLocal == 800_000_000.msat)
    assert(initialState.metaCommitments.latest.remoteCommit.spec.toLocal == 700_000_000.msat)

    initiateSplice(f, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)))

    assert(alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.capacity == 2_000_000.sat)
    assert(alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.localCommit.spec.toLocal == 1_300_000_000.msat)
    assert(alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.remoteCommit.spec.toLocal == 700_000_000.msat)
  }

  test("recv CMD_SPLICE (splice-out)") { f =>
    import f._

    val initialState = alice.stateData.asInstanceOf[DATA_NORMAL]
    assert(initialState.metaCommitments.latest.capacity == 1_500_000.sat)
    assert(initialState.metaCommitments.latest.localCommit.spec.toLocal == 800_000_000.msat)
    assert(initialState.metaCommitments.latest.remoteCommit.spec.toLocal == 700_000_000.msat)

    initiateSplice(f, spliceOut_opt = Some(SpliceOut(100_000 sat, ByteVector32.Zeroes)))

    val feerate = TestConstants.Alice.nodeParams.onChainFeeConf.feeEstimator.getFeeratePerKw(TestConstants.Alice.nodeParams.onChainFeeConf.feeTargets.fundingBlockTarget)
    val miningFee = Transactions.weight2fee(feerate, 600)
    assert(alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.capacity == 1_400_000.sat - miningFee)
    assert(alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.localCommit.spec.toLocal == 700_000_000.msat - miningFee)
    assert(alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.remoteCommit.spec.toLocal == 700_000_000.msat)
  }

  test("recv WatchFundingConfirmedTriggered on splice tx", Tag(NoMaxHtlcValueInFlight)) { f =>
    import f._

    val sender = TestProbe()
    // command for a large payment (larger than local balance pre-slice)
    val cmd = CMD_ADD_HTLC(sender.ref, 1_000_000_000 msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(currentBlockHeight), TestConstants.emptyOnionPacket, None, localOrigin(sender.ref))
    // first attempt at payment fails (not enough balance)
    alice ! cmd
    sender.expectMsgType[RES_ADD_FAILED[_]]
    alice2bob.expectNoMessage()

    initiateSplice(f, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)))
    bob2alice.expectMsgType[Warning] // TODO: this is because non-initiator stops the InteractiveTx FSM right after having sent its signature
    alice2blockchain.expectMsgType[WatchFundingConfirmed]
    alice2blockchain.expectNoMessage()
    alice ! WatchFundingConfirmedTriggered(BlockHeight(400000), 42, alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.localFundingStatus.signedTx_opt.get)
    bob ! WatchFundingConfirmedTriggered(BlockHeight(400000), 42, alice.stateData.asInstanceOf[DATA_NORMAL].metaCommitments.latest.localFundingStatus.signedTx_opt.get)
    alice2bob.expectMsgType[SpliceConfirmed]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[SpliceConfirmed]
    bob2alice.forward(alice)

    // 2nd attempt works!
    alice ! cmd
    sender.expectMsgType[RES_SUCCESS[CMD_ADD_HTLC]]
    alice2bob.expectMsgType[UpdateAddHtlc]
    alice2bob.forward(bob)

    alice ! CMD_SIGN()
    alice2bob.expectMsgType[CommitSig]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[RevokeAndAck]
    bob2alice.forward(alice)
  }

  test("recv CMD_ADD_HTLC with multiple commitments") { f =>
    import f._
    initiateSplice(f, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)))
    val sender = TestProbe()
    alice ! CMD_ADD_HTLC(sender.ref, 500000 msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(currentBlockHeight), TestConstants.emptyOnionPacket, None, localOrigin(sender.ref))
    sender.expectMsgType[RES_SUCCESS[CMD_ADD_HTLC]]
    alice2bob.expectMsgType[UpdateAddHtlc]
  }

  test("recv CMD_ADD_HTLC while a splice is requested") { f =>
    import f._
    val sender = TestProbe()
    val cmd = CMD_SPLICE(sender.ref, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)), spliceOut_opt = None)
    alice ! cmd
    alice2bob.expectMsgType[SpliceInit]
    alice ! CMD_ADD_HTLC(sender.ref, 500000 msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(currentBlockHeight), TestConstants.emptyOnionPacket, None, localOrigin(sender.ref))
    sender.expectMsgType[RES_ADD_FAILED[_]]
    alice2bob.expectNoMessage()
  }

  test("recv CMD_ADD_HTLC while a splice is in progress") { f =>
    import f._
    val sender = TestProbe()
    val cmd = CMD_SPLICE(sender.ref, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)), spliceOut_opt = None)
    alice ! cmd
    alice2bob.expectMsgType[SpliceInit]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[SpliceAck]
    bob2alice.forward(alice)
    sender.expectMsgType[RES_SUCCESS[CMD_SPLICE]]
    alice2bob.expectMsgType[TxAddInput]
    alice ! CMD_ADD_HTLC(sender.ref, 500000 msat, randomBytes32(), CltvExpiryDelta(144).toCltvExpiry(currentBlockHeight), TestConstants.emptyOnionPacket, None, localOrigin(sender.ref))
    sender.expectMsgType[RES_ADD_FAILED[_]]
    alice2bob.expectNoMessage()
  }

  test("recv UpdateAddHtlc while a splice is requested") { f =>
    import f._
    val sender = TestProbe()
    val cmd = CMD_SPLICE(sender.ref, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)), spliceOut_opt = None)
    alice ! cmd
    alice2bob.expectMsgType[SpliceInit]
    // we're not forwarding the splice_init to create a race

    val (_, cmdAdd: CMD_ADD_HTLC) = makeCmdAdd(5_000_000 msat, bob.underlyingActor.remoteNodeId, bob.underlyingActor.nodeParams.currentBlockHeight)
    bob ! cmdAdd
    bob2alice.expectMsgType[UpdateAddHtlc]
    bob2alice.forward(alice)
    alice2bob.forward(bob)
    bob2alice.expectMsgType[TxAbort]
    bob2alice.forward(alice)
    alice2bob.expectMsgType[TxAbort]
    alice2bob.forward(bob)
  }

  test("recv UpdateAddHtlc while a splice is in progress") { f =>
    import f._
    val sender = TestProbe()
    val cmd = CMD_SPLICE(sender.ref, spliceIn_opt = Some(SpliceIn(500_000 sat, pushAmount = 0 msat)), spliceOut_opt = None)
    alice ! cmd
    alice2bob.expectMsgType[SpliceInit]
    alice2bob.forward(bob)
    bob2alice.expectMsgType[SpliceAck]
    bob2alice.forward(alice)
    sender.expectMsgType[RES_SUCCESS[CMD_SPLICE]]
    alice2bob.expectMsgType[TxAddInput]

    // have to build a htlc manually because eclair would refuse to accept this command as it's forbidden
    val fakeHtlc = UpdateAddHtlc(channelId = randomBytes32(), id = 5656, amountMsat = 50000000 msat, cltvExpiry = CltvExpiryDelta(144).toCltvExpiry(currentBlockHeight), paymentHash = randomBytes32(), onionRoutingPacket = TestConstants.emptyOnionPacket, blinding_opt = None)
    bob2alice.forward(alice, fakeHtlc)
    alice2bob.expectMsgType[Error]
  }

}
