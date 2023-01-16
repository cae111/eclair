package fr.acinq.eclair.blockchain.bitcoind


import akka.actor.typed.Behavior
import akka.actor.typed.eventstream.EventStream
import akka.actor.typed.scaladsl.Behaviors
import fr.acinq.bitcoin.scalacompat.{ByteVector32, Script}
import fr.acinq.eclair.blockchain.OnChainAddressGenerator
import scodec.bits.ByteVector

import java.util.concurrent.atomic.AtomicReference
import scala.concurrent.ExecutionContext.Implicits.global

object OnchainAddressManager {
  sealed trait Command
  case class Renew(pubkeyScript: ByteVector) extends Command

  def apply(chainHash: ByteVector32, generator: OnChainAddressGenerator, finalScriptPubKey: AtomicReference[ByteVector]): Behavior[Command] = {
    Behaviors.setup { context =>
      val log = context.log
      context.system.eventStream ! EventStream.Subscribe[Command](context.self)
      Behaviors.receiveMessage {
        case Renew(currentScript) =>
          log.info(s"received Renew($currentScript")
          if (currentScript == finalScriptPubKey.get()) {
            generator.getReceiveAddress().map(address => {
              val script = Script.write(fr.acinq.eclair.addressToPublicKeyScript(address, chainHash))
              log.info(s"setting final onchain address to address = $address script = ${script.toHex}")
              finalScriptPubKey.set(script)
            })
          }
          Behaviors.same
      }
    }
  }
}

