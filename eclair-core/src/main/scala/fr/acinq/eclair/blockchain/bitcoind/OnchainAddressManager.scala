package fr.acinq.eclair.blockchain.bitcoind


import akka.actor.typed.Behavior
import akka.actor.typed.eventstream.EventStream
import akka.actor.typed.scaladsl.{ActorContext, Behaviors, TimerScheduler}
import fr.acinq.bitcoin.scalacompat.{ByteVector32, Script}
import fr.acinq.eclair.blockchain.OnChainAddressGenerator
import scodec.bits.ByteVector

import java.util.concurrent.atomic.AtomicReference
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.{DurationInt, FiniteDuration}
import scala.util.{Failure, Success}

object OnchainAddressManager {
  sealed trait Command

  case object Renew extends Command

  private case class Set(pukeyScript: ByteVector) extends Command

  private case class Error(reason: Throwable) extends Command

  private case object Done extends Command

  def apply(chainHash: ByteVector32, generator: OnChainAddressGenerator, finalScriptPubKey: AtomicReference[ByteVector], delay: FiniteDuration): Behavior[Command] = {
    Behaviors.setup { context =>
      context.system.eventStream ! EventStream.Subscribe[Command](context.self)
      Behaviors.withTimers { timers =>
        new OnchainAddressManager(chainHash, generator, finalScriptPubKey, context, timers, delay).idle()
      }
    }
  }
}

private class OnchainAddressManager(chainHash: ByteVector32, generator: OnChainAddressGenerator, finalScriptPubKey: AtomicReference[ByteVector], context: ActorContext[OnchainAddressManager.Command], timers: TimerScheduler[OnchainAddressManager.Command], delay: FiniteDuration) {

  import OnchainAddressManager._

  def idle(): Behavior[Command] = Behaviors.receiveMessagePartial {
    case Renew =>
      context.log.debug(s"received Renew current script is ${finalScriptPubKey.get()}")
      context.pipeToSelf(generator.getReceiveAddress()) {
        case Success(address) => Set(Script.write(fr.acinq.eclair.addressToPublicKeyScript(address, chainHash)))
        case Failure(reason) => Error(reason)
      }
      Behaviors.receiveMessagePartial {
        case Set(script) =>
          timers.startSingleTimer(Done, 5.seconds)
          waiting(script)
        case Error(reason) =>
          context.log.error("cannot generate new onchain address", reason)
          Behaviors.same
      }
  }

  def waiting(script: ByteVector): Behavior[Command] = Behaviors.receiveMessagePartial {
    case Done =>
      context.log.info(s"setting final onchain script to $script")
      finalScriptPubKey.set(script)
      idle()
  }
}
